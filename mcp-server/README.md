# Havoc MCP Server

An MCP (Model Context Protocol) server that provides tool access to the Havoc C2 teamserver.

## Features

| Tool | Description |
|------|-------------|
| `havoc_status` | Check teamserver connection and authenticate |
| `havoc_list_agents` | List all connected Demon agents |
| `havoc_shell` | Execute shell command on agent |
| `havoc_inline_dotnet` | Run .NET assembly inline on agent |
| `havoc_inline_execute` | Run BOF (Beacon Object File) inline on agent |
| `havoc_generate_payload` | Generate Demon shellcode for a listener |
| `havoc_create_listener` | Create HTTP/HTTPS listener |

## Requirements

- Python 3.10+
- Running Havoc teamserver
- `mcp` package (`pip install mcp`)
- `websockets` package (`pip install websockets`)

## Configuration

Edit the constants at the top of `havoc_mcp.py`:

```python
DEFAULT_TS_URL = "wss://127.0.0.1:40056/havoc/"
DEFAULT_USER = "jarvis"
DEFAULT_PASS = "testing123"
DEFAULT_DB_PATH = "/home/jam/clawd/havoc-research/teamserver/data/teamserver.db"
```

## Usage

### Standalone Test
```bash
# Test the MCP server directly
python3 havoc_mcp.py
```

### With mcporter
```bash
# Register the server
mcporter register havoc-mcp -- python3 /path/to/havoc_mcp.py

# List tools
mcporter tools havoc-mcp

# Call a tool
mcporter call havoc-mcp havoc_status
mcporter call havoc-mcp havoc_list_agents
mcporter call havoc-mcp havoc_shell '{"agent_id": "12345678", "command": "whoami"}'
```

### With Claude Desktop / Claude Code
Add to your MCP config:
```json
{
  "mcpServers": {
    "havoc": {
      "command": "python3",
      "args": ["/path/to/havoc_mcp.py"]
    }
  }
}
```

## Protocol Notes

### Command Execution

The server sends commands via WebSocket to the teamserver using the session input protocol:

```json
{
  "Head": {"Event": 7, "User": "...", "Time": "", "OneTime": ""},
  "Body": {"SubEvent": 3, "Info": {
    "DemonID": "agent_id",
    "TaskID": "unique_task_id",
    "CommandLine": "shell whoami",
    "CommandID": "4112",
    ...
  }}
}
```

### Key Command Codes

| Command | Code | Notes |
|---------|------|-------|
| COMMAND_PROC | 4112 (0x1010) | Shell commands |
| COMMAND_ASSEMBLY_INLINE_EXECUTE | 8193 (0x2001) | .NET inline |
| COMMAND_INLINEEXECUTE | 20 | BOF execution |

### Response Handling

- Agent default sleep: 2s + 15% jitter
- Shell commands: 60s timeout
- .NET/BOF: 120s timeout
- Output collected via Event 7 / SubEvent 4 messages

## Troubleshooting

### "No output - check agent sleep interval"
The agent hasn't checked in yet. Wait for the sleep interval (default 2s + jitter).

### "Failed to connect to teamserver"
- Ensure teamserver is running
- Check the WebSocket URL and port
- Verify credentials

### CLR/Dotnet failures
If `dotnet inline-execute` fails, ensure PR #8 (CLR fix) is merged — there was a long-standing bug with `CreateDomain()` vs `GetDefaultDomain()`.

## Related

- [Havoc Framework](https://github.com/HavocFramework/Havoc)
- [MCP Protocol](https://modelcontextprotocol.io/)
- PR #8: CLR inline-execute fix
