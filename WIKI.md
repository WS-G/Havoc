# Havoc Framework — Wiki

> Comprehensive documentation for the Havoc C2 framework (WS-G fork).  
> This fork includes significant security enhancements, evasion improvements, and new features.

---

## Table of Contents

- [Overview](#overview)
- [Installation](#installation)
  - [Prerequisites](#prerequisites)
  - [Building the Teamserver](#building-the-teamserver)
  - [Building the Client](#building-the-client)
  - [Quick Start](#quick-start)
- [Teamserver](#teamserver)
  - [Configuration (Profiles)](#configuration-profiles)
  - [Starting the Teamserver](#starting-the-teamserver)
  - [Operators](#operators)
- [Listeners](#listeners)
  - [HTTP/HTTPS Listener](#httphttps-listener)
  - [HTTP/2 Support](#http2-support)
  - [DNS Listener](#dns-listener)
  - [SMB Listener (Pivot)](#smb-listener-pivot)
  - [External C2](#external-c2)
- [Demon Agent](#demon-agent)
  - [Payload Generation](#payload-generation)
  - [Sleep Obfuscation](#sleep-obfuscation)
  - [Indirect Syscalls](#indirect-syscalls)
  - [ETW/AMSI Bypass](#etwamsi-bypass)
  - [String Obfuscation](#string-obfuscation)
  - [Call Stack Spoofing](#call-stack-spoofing)
- [Post-Exploitation](#post-exploitation)
  - [Built-in Commands](#built-in-commands)
  - [Token Management](#token-management)
  - [Inline Execute (BOFs)](#inline-execute-bofs)
  - [.NET Assembly Execution](#net-assembly-execution)
  - [DLL Injection](#dll-injection)
- [Evasion Features](#evasion-features)
  - [Polymorphic Build System](#polymorphic-build-system)
  - [FNV-1a Hashing](#fnv-1a-hashing)
  - [Syscall Donor Rotation](#syscall-donor-rotation)
  - [Custom XOR Sleep Encryption](#custom-xor-sleep-encryption)
  - [Synthetic Call Stack Spoofing](#synthetic-call-stack-spoofing)
  - [Hardware Breakpoint ETW/AMSI Bypass](#hardware-breakpoint-etwamsi-bypass)
  - [Compile-Time String Obfuscation](#compile-time-string-obfuscation)
  - [HTTP/2 Protocol Support](#http2-protocol-support)
- [MCP Server](#mcp-server)
- [Extending Havoc](#extending-havoc)
  - [Custom Agents](#custom-agents)
  - [Modules](#modules)
  - [Python API](#python-api)
- [Troubleshooting](#troubleshooting)
- [Credits](#credits)

---

## Overview

Havoc is a modern, malleable post-exploitation command and control (C2) framework originally created by [@C5pider](https://twitter.com/C5pider). This fork (WS-G) includes significant enhancements focused on:

- **EDR evasion** — Polymorphic builds, hardware breakpoint bypasses, call stack spoofing
- **Detection resistance** — FNV-1a hashing, compile-time string obfuscation, custom sleep encryption
- **Protocol diversity** — HTTP/HTTPS, HTTP/2, DNS tunneling, SMB pivoting
- **Operational flexibility** — MCP server integration, improved .NET execution

### Architecture

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│   Operator   │────▶│  Teamserver  │◀────│    Demon     │
│   (Client)   │     │   (Golang)   │     │  (C Agent)   │
└──────────────┘     └──────────────┘     └──────────────┘
       Qt/C++         HTTP/DNS/SMB          Shellcode
                      Listeners             Implant
```

- **Client** — Qt-based cross-platform GUI for operator interaction
- **Teamserver** — Go-based server handling listeners, agent management, and tasking
- **Demon** — Lightweight C/ASM agent (shellcode) deployed on targets

---

## Installation

### Prerequisites

**Teamserver (Linux):**
```bash
# Debian/Ubuntu
sudo apt install -y git build-essential golang mingw-w64 nasm

# Go 1.21+ required
go version
```

**Client (Linux):**
```bash
# Qt5 development libraries
sudo apt install -y qt5-default libqt5websockets5-dev python3 python3-dev

# Or Qt6 on newer distros
sudo apt install -y qt6-base-dev qt6-websockets-dev python3 python3-dev
```

> **Note:** Building works best on Debian 11+, Ubuntu 22.04+, or Kali Linux. Use the latest OS version to avoid Qt/Python compatibility issues.

### Building the Teamserver

```bash
cd teamserver

# Install Go dependencies
go mod download

# Build
make
```

This produces the `teamserver` binary (or `havoc` depending on your build configuration).

### Building the Client

```bash
cd client

# Install Python dependencies
pip3 install -r requirements.txt

# Build
make

# The client binary will be at Build/Havoc
```

### Quick Start

1. **Create a profile** (e.g., `profiles/havoc.yaotl`) — see [Configuration](#configuration-profiles)
2. **Start the teamserver:**
   ```bash
   ./havoc server --profile profiles/havoc.yaotl
   ```
3. **Connect the client:**
   ```bash
   ./client/Build/Havoc
   ```
   Enter the teamserver host, port, and operator credentials.
4. **Create a listener** via the client GUI
5. **Generate a payload** and deploy to target
6. **Interact** with the beacon once it checks in

---

## Teamserver

### Configuration (Profiles)

Havoc uses `.yaotl` profile files (HCL-based syntax). A basic profile:

```hcl
Teamserver {
    Host = "0.0.0.0"
    Port = 40056

    Build {
        Compiler64 = "/usr/bin/x86_64-w64-mingw32-gcc"
        Compiler86 = "/usr/bin/i686-w64-mingw32-gcc"
        Nasm       = "/usr/bin/nasm"
    }
}

Operators {
    user "admin" {
        Password = "password123"
    }
}

Listeners {
    Http {
        Name         = "https-listener"
        Hosts        = ["192.168.1.100"]
        HostBind     = "0.0.0.0"
        PortBind     = 443
        PortConn     = 443
        Secure       = true
        UserAgent    = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

        Uris = [
            "/api/v1/status",
            "/content/update",
            "/assets/check"
        ]

        Headers = [
            "Content-Type: application/json",
            "X-Requested-With: XMLHttpRequest"
        ]

        Response {
            Headers = [
                "Content-Type: application/json",
                "Server: nginx/1.24.0",
                "Cache-Control: no-cache"
            ]
        }
    }
}

Demon {
    Sleep  = 5
    Jitter = 20

    Injection {
        Spawn64 = "C:\\Windows\\System32\\notepad.exe"
        Spawn32 = "C:\\Windows\\SysWOW64\\notepad.exe"
    }
}
```

### Starting the Teamserver

```bash
# Basic
./havoc server --profile profiles/havoc.yaotl

# With verbose logging
./havoc server --profile profiles/havoc.yaotl -v

# Custom port
./havoc server --profile profiles/havoc.yaotl --port 8443
```

The teamserver will:
1. Load the profile configuration
2. Start configured listeners
3. Generate TLS certificates (if HTTPS)
4. Begin accepting operator connections

### Operators

Operators are defined in the profile. Each operator connects via the client UI and can:
- View active agents
- Task agents with commands
- Generate payloads
- Manage listeners

---

## Listeners

### HTTP/HTTPS Listener

The primary listener type. Supports:
- Custom URIs, headers, and user agents
- Host rotation (round-robin, random)
- Proxy awareness
- TLS with custom certificates

**Profile configuration:**
```hcl
Listeners {
    Http {
        Name         = "https-listener"
        Hosts        = ["10.0.0.1", "10.0.0.2"]  # Multiple hosts for rotation
        HostBind     = "0.0.0.0"
        PortBind     = 443
        PortConn     = 443
        Secure       = true
        HostRotation = "round-robin"  # or "random"
        UserAgent    = "Mozilla/5.0 ..."
        
        Uris = ["/api/v1/data", "/content/sync"]
        
        Headers = ["Content-Type: application/json"]
        
        Response {
            Headers = ["Server: nginx"]
        }
    }
}
```

### HTTP/2 Support

This fork adds HTTP/2 protocol support for HTTPS listeners. HTTP/2 is automatically negotiated via ALPN when using TLS, making C2 traffic blend with modern web traffic.

**How it works:**
- Teamserver advertises `h2` and `http/1.1` via TLS ALPN extension
- Demon client requests HTTP/2 via `WINHTTP_PROTOCOL_FLAG_HTTP2`
- Connection automatically upgrades to HTTP/2 if both sides support it
- Falls back to HTTP/1.1 gracefully if HTTP/2 is unavailable

**No additional configuration needed** — HTTP/2 is enabled automatically for all HTTPS listeners.

**Verification:**
- Wireshark: With TLS decryption keys, look for `h2` in the EncryptedExtensions ALPN field
- Teamserver: Check connection logs for protocol negotiation
- Note: In TLS 1.3, ALPN is in EncryptedExtensions (encrypted), not visible in plaintext ServerHello

### DNS Listener

DNS tunneling allows C2 communication over DNS queries, bypassing firewalls that only allow DNS traffic.

**Profile configuration:**
```hcl
Listeners {
    Dns {
        Name     = "dns-c2"
        Domain   = "c2.example.com"
        PortBind = 53
    }
}
```

**GUI options (Cobalt Strike-style):**

When creating a DNS listener via the client GUI, the following options are available:

| Option | Default | Description |
|--------|---------|-------------|
| Domain | *(required)* | C2 domain (e.g., `c2.example.com`) |
| Host Bind | `0.0.0.0` | Interface to bind the DNS server |
| Port Bind | `53` | DNS server port |
| Record Type | `A/TXT` | DNS record type for control signals. Options: `A/TXT`, `AAAA/TXT`, `TXT Only` |
| Poll Interval | `60` | Seconds between agent check-ins |
| TTL | `5` | DNS response TTL in seconds |
| Kill Date | *(empty)* | Date to stop the agent (format: `DD/MM/YYYY`) |
| Working Hours | *(empty)* | Time window for agent activity (format: `HH:MM-HH:MM`) |

**Record Types:**
- **A/TXT** (default) — Control signals via A records, data via TXT records. Most compatible.
- **AAAA/TXT** — Control signals via AAAA records, data via TXT. Useful when A records are filtered/inspected.
- **TXT Only** — All communication via TXT records. Simplest but most detectable.

**Setup requirements:**
1. Own a domain (e.g., `example.com`)
2. Create an NS record pointing a subdomain to your teamserver:
   ```
   c2.example.com  NS  ns1.c2.example.com
   ns1.c2.example.com  A  <teamserver-ip>
   ```
3. Ensure port 53 (UDP) is open on the teamserver

**Protocol details:**
- Upstream (agent → teamserver): Data encoded as base32 in DNS subdomain labels
  - Format: `<base32_data>.<seq>.<total>.<agent_id>.<domain>`
- Downstream (teamserver → agent): TXT record responses with base32-encoded commands
- Control signals via A records (or AAAA if configured):
  - `1.0.0.1` — ACK (chunk received)
  - `1.0.0.2` — Has pending job
  - `1.0.0.0` — No pending job

**Limitations:**
- Low bandwidth (~50 bytes usable per query)
- Suitable for C2 commands, not large file transfers
- High DNS query volume can be suspicious — adjust poll interval and use working hours

### SMB Listener (Pivot)

SMB named pipe listener for pivoting through compromised hosts.

```hcl
Listeners {
    Smb {
        Name     = "smb-pivot"
        PipeName = "\\.\pipe\mypipe"
    }
}
```

### External C2

Havoc supports external C2 channels via a REST API, allowing custom transport implementations.

---

## Demon Agent

### Payload Generation

Generate payloads via the client GUI:
- **Format:** Windows Executable (.exe), DLL (.dll), Shellcode (.bin)
- **Architecture:** x64 (primary), x86
- **Options:** Sleep interval, jitter, injection settings

The build system uses `polymorphic_build.py` to generate unique payloads each build (see [Polymorphic Build System](#polymorphic-build-system)).

### Sleep Obfuscation

During sleep, the Demon encrypts its memory using a custom XOR cipher (replacing the original RC4/SystemFunction032 implementation). This prevents memory scanners from detecting the beacon while idle.

**Supported techniques:**
- **Ekko** — Timer-based sleep with ROP chain
- **Zilean** — CreateTimerQueueTimer-based sleep
- **FOLIAGE** — APC-based sleep obfuscation

Each technique:
1. Encrypts the Demon's memory with a random key
2. Sleeps for the configured interval
3. Decrypts memory on wake

The custom XOR cipher avoids signatures associated with `SystemFunction032` and RC4.

### Indirect Syscalls

All Nt* API calls use indirect syscalls to avoid userland hooks:
- Syscall numbers resolved dynamically at runtime
- Syscall instruction executed from `ntdll.dll` memory (indirect)
- **Donor address rotation**: 8 different legitimate ntdll functions used as syscall donors, rotated round-robin to avoid detection patterns

### ETW/AMSI Bypass

This fork implements a patchless ETW and AMSI bypass using hardware breakpoints:

- **No memory patching** — avoids detection by integrity-checking EDRs
- Sets hardware breakpoints on:
  - `NtTraceControl` — Blocks ETW event logging
  - `EtwEventWrite` — Blocks ETW event writes
  - `AmsiScanBuffer` — Bypasses AMSI scanning
- Vectored Exception Handler intercepts breakpoint exceptions and returns success
- Zero ETW events from the beacon process

### String Obfuscation

Module names and sensitive strings are obfuscated at compile time using XOR encryption with a random per-build key. Strings are decrypted at runtime only when needed.

**Obfuscated strings include:**
- `ntdll.dll`, `kernel32.dll`, `advapi32.dll`
- `ws2_32.dll`, `winhttp.dll`, `mscoree.dll`
- And other DLL/module names used by the agent

### Call Stack Spoofing

Synthetic call stack spoofing during sleep prevents detection by tools like Hunt-Sleeping-Beacons. The implementation:

- Constructs a realistic-looking call stack before sleep
- Uses legitimate return addresses from system DLLs
- Validates return addresses point to actual CALL instruction targets (not JMP gadgets)
- Includes frames from `KERNELBASE.dll`, `ntdll.dll`, and `kernel32.dll`

---

## Post-Exploitation

### Built-in Commands

| Command | Description |
|---------|-------------|
| `help` | Show available commands |
| `sleep` | Set sleep interval and jitter |
| `checkin` | Force immediate check-in |
| `shell` | Execute shell command |
| `powershell` | Execute PowerShell command |
| `upload` | Upload file to target |
| `download` | Download file from target |
| `cd` | Change directory |
| `pwd` | Print working directory |
| `ls` | List directory contents |
| `cat` | Display file contents |
| `cp` | Copy file |
| `mv` | Move file |
| `rm` | Remove file |
| `mkdir` | Create directory |
| `ps` | List processes |
| `proc` | Process management |
| `token` | Token manipulation |
| `inject` | Inject shellcode/DLL |
| `inlineExecute` | Execute BOF (Beacon Object File) |
| `dotnet` | Execute .NET assembly |
| `exit` | Exit the agent |

### Token Management

The Demon includes a token vault for managing Windows tokens:
- `token list` — List stored tokens
- `token steal <pid>` — Steal token from process
- `token make <domain> <user> <password>` — Create token
- `token use <id>` — Impersonate stored token
- `token revert` — Revert to original token

### Inline Execute (BOFs)

Execute Beacon Object Files (BOFs) in-process:
```
inlineExecute /path/to/bof.o <args>
```

Compatible with most Cobalt Strike BOFs. The execution engine handles:
- Dynamic function resolution
- Memory allocation and cleanup
- Output capture

### .NET Assembly Execution

Execute .NET assemblies in-memory using the CLR:
```
dotnet inline-execute /path/to/assembly.exe <args>
```

**Implementation note:** This fork fixes the CLR execution engine to use `GetDefaultDomain()` instead of the deprecated `CreateDomain()`, resolving issues on newer .NET runtimes. The default AppDomain is used (cannot be unloaded), ensuring compatibility with .NET 4.x and later.

### DLL Injection

Multiple injection techniques available:
- **Spawn + Inject** — Create new sacrificial process and inject
- **Direct Inject** — Inject into existing process

---

## Evasion Features

### Polymorphic Build System

Each payload build is unique thanks to `polymorphic_build.py`:
- **Randomized FNV-1a hash seed** — Different hash values every build
- **Auto-synced magic values** — DEMON_MAGIC_VALUE synced across Defines.h, commands.go, and Service.cc
- **Unique signatures** — No two builds produce identical binaries
- **YARA rule resistance** — Eliminates static signatures used by common YARA rules

**Usage:**
```bash
python3 polymorphic_build.py
```

The script:
1. Generates a random 32-bit FNV-1a basis seed
2. Recomputes all hash constants with the new seed
3. Updates Demon source files (Defines.h)
4. Syncs the magic value across teamserver (commands.go) and client (Service.cc)
5. Builds the payload with the new values

### FNV-1a Hashing

Replaced the original DJB2 hash algorithm with FNV-1a:
- More uniform hash distribution
- Polymorphic basis value changes per build
- Eliminates known DJB2 hash signatures used by security products
- All API function resolution uses the randomized FNV-1a hashes

### Syscall Donor Rotation

Instead of using a single syscall donor address, the Demon rotates through 8 different legitimate ntdll functions:
- Round-robin selection on each syscall
- Each donor is a legitimate function containing a `syscall` instruction
- Prevents behavioral detection based on repeated syscall origins
- Donors validated at runtime to ensure they contain valid syscall instructions

### Custom XOR Sleep Encryption

Replaced `SystemFunction032` (RC4) with a custom XOR cipher for sleep encryption:
- No dependency on `advapi32.dll` exports
- Eliminates the "SystemFunction032" signature
- Random key generated each sleep cycle
- Equivalent security for memory obfuscation purposes
- CFG-compatible (heap-allocated function pointer)

### Synthetic Call Stack Spoofing

SilentMoonWalk-style synthetic call stack construction:
- Builds a realistic call stack before each sleep
- Uses return addresses from legitimate DLL CALL targets
- Validates addresses point to actual CALL instructions (not JMP gadgets)
- Includes standard thread startup frames (BaseThreadInitThunk, RtlUserThreadStart)
- Defeats Hunt-Sleeping-Beacons and similar call stack analysis tools

### Hardware Breakpoint ETW/AMSI Bypass

Patchless bypass using CPU debug registers:
- DR0-DR3 hardware breakpoints on ETW/AMSI functions
- Vectored Exception Handler returns early with success status
- **Zero memory modifications** — passes integrity checks
- Targets: `NtTraceControl`, `EtwEventWrite`, `AmsiScanBuffer`
- Result: Zero ETW events emitted by the beacon process

### Compile-Time String Obfuscation

All sensitive module name strings encrypted at compile time:
- Random XOR key per build
- Strings decrypted in-memory at runtime
- 15+ module names obfuscated (ntdll, kernel32, advapi32, ws2_32, etc.)
- Eliminates static string signatures in the binary

### HTTP/2 Protocol Support

Automatic HTTP/2 negotiation for HTTPS listeners:
- Server-side: Go `http2.ConfigureServer()` + explicit TLS ALPN configuration
- Client-side: WinHTTP `WINHTTP_PROTOCOL_FLAG_HTTP2`
- HTTP/2 multiplexing makes C2 traffic blend with modern HTTPS
- Transparent fallback to HTTP/1.1 if HTTP/2 is unavailable

---

## MCP Server

This fork includes an MCP (Model Context Protocol) server for AI-assisted C2 operation:
- Basic agent tasking via MCP tools
- Connection pooling and health monitoring
- Integration with AI coding assistants

See `mcp-server/README.md` for setup and usage details.

---

## Extending Havoc

### Custom Agents

Havoc supports custom agents through the External C2 interface:
- Implement your own agent in any language
- Communicate via the External C2 REST API
- Example: [Talon](https://github.com/HavocFramework/Talon)

### Modules

Extend Demon's functionality with modules:
- Written in C, compiled as BOFs or DLLs
- Access to internal Demon APIs
- Community modules: [HavocFramework/Modules](https://github.com/HavocFramework/Modules)

### Python API

Automate teamserver operations via the Python API:
- [havoc-py](https://github.com/HavocFramework/havoc-py)
- Script listener management, agent tasking, and data extraction

---

## Troubleshooting

### Common Issues

**"No Aes Key specified" in teamserver logs**
- This log message has inverted logic — it appears when AES IS configured
- Can be safely ignored; it's a misleading log from the original codebase

**DEMON_MAGIC_VALUE mismatch**
- Symptoms: Agent connects but teamserver doesn't recognize it
- The magic value must match across 3 files: `Defines.h`, `commands.go`, `Service.cc`
- Fix: Run `polymorphic_build.py` which auto-syncs all three files

**Client build fails (Modules clone error)**
- The client build process clones upstream module repos expecting specific branch names
- Fix: Check that the referenced branches exist, or build with `--skip-modules`

**CLR inline-execute fails on newer .NET**
- Fixed in this fork — uses `GetDefaultDomain()` instead of `CreateDomain()`
- The default AppDomain cannot be unloaded (by design)

**Cross-compilation errors (AddMandatoryAce undeclared)**
- Missing mingw headers on Linux build host
- Install: `sudo apt install mingw-w64`
- Some functions may require generating shellcode on a Windows host

**Agent not checking in (HTTPS)**
- Verify TLS certificates are valid or self-signed is accepted
- Check firewall rules for the listener port
- Verify the host/port in the profile matches what the agent is configured for
- Check sleep interval — agent may just be sleeping

**DNS listener not receiving queries**
- Verify NS records point to your teamserver
- Check that port 53 (UDP) is accessible
- Test with `dig TXT test.c2.example.com @<teamserver-ip>`
- Ensure no other DNS server is binding port 53

### Known Limitations

- KaynLdr maps sections only (no DOS/PE headers in memory) — `ModuleBase` points to `.text` section
- DNS transport is low bandwidth (~50 bytes/query) — not suitable for large file transfers
- HTTP/2 requires TLS (HTTPS listener) — doesn't apply to plain HTTP listeners

---

## Credits

- **[@C5pider](https://twitter.com/C5pider)** — Original Havoc framework creator
- **WS-G** — Fork maintainer, evasion enhancements, protocol additions
- **Community** — Bug reports, testing, and module contributions

See [CREDITS.md](CREDITS.md) for full attribution.

---

*Last updated: February 2026*
