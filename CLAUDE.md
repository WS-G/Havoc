# CLAUDE.md — Havoc C2 Framework (WS-G Fork)

## What This Is

Havoc is a post-exploitation C2 framework. This is a modernised fork focused on EDR evasion improvements. Three main components:

| Component | Language | Location | Build |
|-----------|----------|----------|-------|
| **Teamserver** | Go | `teamserver/` | `go build` from `teamserver/cmd/server/` |
| **Client** | C++ / Qt5 | `client/` | CMake (`client/CMakeLists.txt`) |
| **Demon** (agent) | C / ASM | `payloads/Demon/` | CMake, cross-compiled with `x86_64-w64-mingw32-gcc` |

## Architecture Overview

```
Client (Qt GUI) <--websocket--> Teamserver (Go) <--HTTP/HTTPS/DNS/SMB--> Demon (implant on target)
```

- **Teamserver** handles listeners, agent management, payload generation, and operator multiplayer
- **Client** is the operator GUI — connects to teamserver via websocket
- **Demon** is the implant — beacon-style agent that calls back to teamserver listeners
- **KaynLdr** (`payloads/Demon/KaynLdr/`) is the reflective loader — maps Demon into memory. Only maps sections (no DOS/PE headers in memory). `ModuleBase` points to `.text`, not image base.

## Build Instructions

### Teamserver
```bash
cd teamserver
go build -o ../havoc cmd/server/main.go
```
Requires: Go 1.21+, `miekg/dns`, `gin-gonic/gin`, `golang.org/x/net/http2`

### Client
```bash
cd client
mkdir build && cd build
cmake ..
make -j$(nproc)
```
Requires: Qt5, CMake 3.19+, `nlohmann/json.hpp`

**⚠️ Client build is fragile** — the Modules clone step expects specific upstream branch names. If it fails, check `client/CMakeLists.txt` ExternalProject entries.

### Demon (payload)
Payloads are generated through the teamserver, not built standalone. The teamserver invokes CMake + mingw cross-compilation internally via `teamserver/pkg/common/builder/builder.go`.

### Polymorphic Build
Before generating payloads, run the polymorphic build script to randomise hash constants:
```bash
cd payloads/Demon
python3 scripts/polymorphic_build.py
```
This generates unique FNV-1a hash seeds per build — no two builds share static IOCs. The script also syncs `DEMON_MAGIC_VALUE` across all required files automatically.

## Critical Gotchas

### DEMON_MAGIC_VALUE
Must match across **3 locations** or agents won't register:
1. `payloads/Demon/include/common/Defines.h` — `#define DEMON_MAGIC_VALUE 0x76188E64`
2. `teamserver/pkg/agent/commands.go` — `DEMON_MAGIC_VALUE = 0x76188E64`
3. `client/src/Havoc/Service.cc` — `uint64_t DemonMagicValue = 0x76188e64`

The `polymorphic_build.py` script syncs this automatically. **Never change it manually in just one file.**

### KaynLdr Memory Layout
KaynLdr maps sections only — there are no DOS/PE headers in memory. `ModuleBase` points to the `.text` section, NOT the image base. Any code that assumes a PE header at `ModuleBase` will break.

### Go HTTP/2
Go's `net/http` does NOT auto-enable HTTP/2. Requires explicit `http2.ConfigureServer()` + `golang.org/x/net/http2` import. For TLS 1.3, ALPN is in EncryptedExtensions (not ServerHello) — use `ConnState` debug logging to verify.

### miekg/dns
`HandleFunc` expects domain with **trailing dot** (FQDN format). Without it, the handler never fires.
```go
dns.HandleFunc("c2.example.com.", handler)  // ✅ correct
dns.HandleFunc("c2.example.com", handler)   // ❌ won't match
```

### Packer "No Aes Key specified" Log
The log message in `packer.go` has inverted logic — it logs when the key IS present. Misleading but not a bug.

### Cross-Compilation
Linux builds may fail with "AddMandatoryAce undeclared" if mingw headers are incomplete. Payload generation + testing requires the teamserver running on a system with proper mingw-w64 toolchain.

## Project Structure (Key Files)

```
teamserver/
├── cmd/server/          # Entry point, dispatch, listener management
├── pkg/
│   ├── agent/           # Demon agent protocol, commands, magic value
│   ├── handlers/        # Listener implementations (http.go, dns.go, smb.go, external.go)
│   ├── common/builder/  # Payload compilation (invokes CMake/mingw)
│   └── events/          # Event system for client notifications

client/
├── include/
│   ├── global.hpp       # Listener structs, protocol types, config
│   └── UserInterface/Dialogs/Listener.hpp  # Listener dialog widgets
├── src/
│   ├── UserInterface/Dialogs/Listener.cc   # Listener create/edit GUI
│   ├── Havoc/Packager.cc                   # Network packet construction
│   └── Havoc/Service.cc                    # DemonMagicValue definition

payloads/Demon/
├── include/
│   ├── common/Defines.h    # DEMON_MAGIC_VALUE, constants
│   ├── Demon.h             # Main agent header
│   └── core/               # Transport, syscall, obfuscation headers
├── src/
│   ├── Demon.c             # Agent entry + main loop
│   └── core/               # Transport*.c, Obf.c, Syscalls.c, CallStack.c, HwBp*.c
├── scripts/
│   └── polymorphic_build.py  # Hash randomisation + magic value sync
└── KaynLdr/                  # Reflective loader
```

## Fork Changes (vs upstream HavocFramework/Havoc)

All changes are documented in detail in `WIKI.md`. Summary:

1. **Polymorphic FNV-1a hashing** — replaced DJB2, randomised per-build
2. **Syscall donor rotation** — 8 donors, round-robin for indirect syscalls
3. **XOR sleep encryption** — replaced SystemFunction032/RC4
4. **Synthetic call stack spoofing** — SilentMoonWalk-style
5. **ETW/AMSI HWBP bypass** — hardware breakpoint based, zero ETW events
6. **CLR inline-execute fix** — GetDefaultDomain() replacing CreateDomain()
7. **MCP server** — machine-to-machine tasking interface
8. **String obfuscation** — compile-time XOR for 15 module names
9. **HTTP/2 support** — explicit ALPN + http2.ConfigureServer
10. **DNS listener** — miekg/dns, base32 subdomain encoding, TXT/A responses, Qt GUI

## Workflow Rules

- **Never push to main** — always create a feature branch and submit a PR
- **One PR at a time for Havoc changes** — code → test → merge → next
- **Testing workflow**: Build shellcode via teamserver → SCP to Windows test machine → run loader → check scanner results
- **Windows test machine**: 192.168.0.24, user `Maldev`, teamserver port 8443

## Testing

### Teamserver
```bash
cd teamserver && go build ./...
```

### Listener-specific testing
- HTTP/HTTPS: Standard curl/browser against listener endpoint
- DNS: `dig @<teamserver-ip> <subdomain>.c2.example.com TXT` — should get base32-encoded responses
- SMB: Requires pivot agent already connected

### Demon payload
Generate through the client GUI or MCP server. Test on Windows target with appropriate EDR running. Use Hunt-Sleeping-Beacons, PE-sieve, and Moneta for memory scanner validation.
