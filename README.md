# DARK MATER | MCP Kali Server v2.0

A production-ready Model Context Protocol (MCP) server for security testing with Kali Linux tools. Features enrollment-based authentication, schema-validated tool execution, artifact storage with auto-parsing, memory hooks, and comprehensive guardrails.

## Features

- 🔐 **Enrollment & API Key Authentication**: Secure server enrollment with bearer token auth
- 🛡️ **Schema Validation**: JSON Schema validation for all tool arguments
- 🎯 **Scope & Guardrails**: CIDR-based targeting with destructive operation controls
- 📦 **Artifact Storage**: Automatic storage and parsing of tool outputs with summaries
- 🧠 **Memory Hooks**: Lightweight observation recording for analysis patterns
- 🌐 **HTTP API**: RESTful endpoints for DARK MATER MCP Client integration
- 🔧 **Systemd Integration**: Production-ready service with automatic startup
- 🔒 **Optional TLS/mTLS**: Support for encrypted connections
- 🌐 **Ngrok Tunneling**: Remote access without port forwarding

## Quick Start

### Easy Installation & Startup

1. **Install the server** (requires root):
   ```bash
   curl -sSL https://raw.githubusercontent.com/khalilpreview/MCP-Kali-Server/main/install.sh | sudo bash
   ```

2. **Start with the CLI tool**:
   ```bash
   sudo dark-mater_kali-mcp start-server
   ```
   
   The CLI provides:
   - 🎨 **DARK MATER ASCII banner**
   - 🌐 **Interactive ngrok setup** (optional)
   - 🚀 **Automatic server startup**
   - 📋 **Enrollment information display**
   - 🎛️ **Interactive management menu**

## CLI Management Tool

The `dark-mater_kali-mcp` CLI tool provides comprehensive server management:

### Features
- 🎨 **Beautiful ASCII banner** with DARK MATER branding
- 🌐 **Interactive ngrok configuration** with token prompts
- 🚀 **Automatic server startup** and health monitoring  
- 📋 **Real-time enrollment status** and server information
- 🎛️ **Interactive control panel** with multiple options:
  - Server status monitoring
  - Server restart functionality
  - Log viewing capabilities
  - Health testing
  - Artifacts management
  - Graceful shutdown

### Usage
```bash
# Start the server with interactive setup
sudo dark-mater_kali-mcp start-server

# The CLI will guide you through:
# 1. Ngrok token configuration (optional)
# 2. Server startup
# 3. Enrollment information display
# 4. Interactive management menu
```

### Starting the Server

After installation, you have multiple ways to start the server:

#### **🎯 Recommended: CLI Tool** (Easy & Interactive)
```bash
# Start with the beautiful CLI interface
sudo dark-mater_kali-mcp start-server
```

This provides:
- Beautiful DARK MATER ASCII banner
- Interactive ngrok setup
- Automatic enrollment display
- Real-time server management

#### **⚙️ Systemd Service** (Background)
```bash
# Start as system service
sudo systemctl start mcp-kali-server
sudo systemctl status mcp-kali-server

# Enable auto-start on boot
sudo systemctl enable mcp-kali-server
```

#### **🚀 Direct Execution** (Development)
```bash
# Run directly (foreground)
sudo /opt/mcp-kali-server/venv/bin/python /opt/mcp-kali-server/kali_server.py --bind 0.0.0.0:5000

# With ngrok tunnel
sudo /opt/mcp-kali-server/venv/bin/python /opt/mcp-kali-server/kali_server.py --bind 0.0.0.0:5000 --ngrok --ngrok-authtoken YOUR_TOKEN
```

### Alternative: Manual Installation

```bash
# Download and run the installer
curl -sSL https://raw.githubusercontent.com/khalilpreview/MCP-Kali-Server/main/install.sh | sudo bash

# Or clone and run locally
git clone https://github.com/khalilpreview/MCP-Kali-Server.git
cd MCP-Kali-Server
sudo chmod +x install.sh
sudo ./install.sh
```

The installer will:
- Create a dedicated `mcpserver` user
- Install the server to `/opt/mcp-kali-server`
- Set up systemd service
- Generate enrollment token
- Install global CLI tool

### Optional: Enable Ngrok Tunneling

For remote access without port forwarding:

1. **Get ngrok auth token** from [ngrok dashboard](https://dashboard.ngrok.com/get-started/your-authtoken)

2. **Configure the service**:
   ```bash
   sudo systemctl edit mcp-kali-server
   ```
   Add:
   ```ini
   [Service]
   Environment="NGROK_AUTHTOKEN=your_token_here"
   ExecStart=
   ExecStart=/opt/mcp-kali-server/venv/bin/# Run in development mode
python kali_server.py --debug --bind 127.0.0.1:8000

# Run with ngrok tunnel for testing
python kali_server.py --debug --bind 127.0.0.1:8000 --ngrok --ngrok-authtoken YOUR_TOKEN
```

### Adding New Tools
   ```

3. **Restart the service**:
   ```bash
   sudo systemctl daemon-reload
   sudo systemctl restart mcp-kali-server
   ```

4. **Get the public URL**:
   ```bash
   sudo journalctl -u mcp-kali-server -f | grep "tunnel established"
   ```

### Enrollment

After installation, follow these steps to register your server:

#### Step 1 — Locate the enrollment token

The installer created this file:

```bash
/etc/mcp-kali/enroll.json
```

Check it:

```bash
cat /etc/mcp-kali/enroll.json
```

You'll see something like:

```json
{"id":"kali-host-1727890000","token":"AbCdEfGh123XYZ","created":"2025-10-02T12:00:00Z"}
```

#### Step 2 — Call the enroll endpoint

With the server running, send a POST to /enroll with that ID + token. Example:

```bash
curl -sS -X POST http://localhost:5000/enroll \
  -H "Content-Type: application/json" \
  -d '{"id":"kali-host-1727890000","token":"AbCdEfGh123XYZ","label":"Kali-Lab-1"}'
```

#### Step 3 — Get your API key

The server should respond like this:

```json
{
  "server_id": "kali-host-1727890000",
  "api_key": "3qP7eD9xL0...<long-random-key>...",
  "label": "Kali-Lab-1"
}
```

That `api_key` is what you'll use in the `Authorization: Bearer <api_key>` header for all other endpoints (`/health`, `/tools/list`, `/tools/call`, `/artifacts/...`).

#### Step 4 — Verify it works

```bash
curl -sS http://localhost:5000/health \
  -H "Authorization: Bearer <api_key>"
```

If you see `{ "ok": true, ... }`, your server is properly registered and ready.

## API Usage

### Health Check

```bash
curl -H "Authorization: Bearer YOUR_API_KEY" \
  "http://SERVER_IP:5000/health"
```

### List Available Tools

```bash
curl -H "Authorization: Bearer YOUR_API_KEY" \
  "http://SERVER_IP:5000/tools/list"
```

### Execute Network Scan

```bash
curl -X POST "http://SERVER_IP:5000/tools/call" \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "net.scan_basic",
    "arguments": {
      "target": "192.168.1.1",
      "fast": true
    }
  }'
```

### List Artifacts

```bash
curl -H "Authorization: Bearer YOUR_API_KEY" \
  "http://SERVER_IP:5000/artifacts/list?limit=10"
```

### Read Artifact

```bash
curl -H "Authorization: Bearer YOUR_API_KEY" \
  "http://SERVER_IP:5000/artifacts/read?uri=artifact://server-id/run-id/raw.xml"
```

## Configuration

### Scope Configuration

Edit `/etc/mcp-kali/scope.json` to control targeting and destructive operations:

```json
{
  "allowed_cidrs": [
    "10.0.0.0/8",
    "192.168.0.0/16", 
    "172.16.0.0/12"
  ],
  "allow_destructive": false
}
```

- `allowed_cidrs`: List of CIDR ranges that tools can target
- `allow_destructive`: Whether to allow potentially destructive operations

### TLS Configuration

Enable TLS with environment variables:

```bash
# Server TLS (HTTPS)
export MCP_TLS_CERT="/path/to/server.crt"
export MCP_TLS_KEY="/path/to/server.key"

# Mutual TLS (client certificates required)
export MCP_MTLS_CA="/path/to/ca.crt"

# Restart the service
sudo systemctl restart mcp-kali-server
```

## Available Tools

### net.scan_basic

Basic network scanning using nmap with safety constraints.

**Schema**: `/schemas/tools/net_scan_basic.json`

**Arguments**:
- `target` (required): IP address, hostname, or CIDR range
- `ports` (optional): Port specification (e.g., "80,443" or "1-1000") 
- `fast` (optional): Use fast scan mode (default: true)

**Example**:
```json
{
  "name": "net.scan_basic",
  "arguments": {
    "target": "192.168.1.0/24",
    "ports": "22,80,443",
    "fast": true
  }
}
```

## File Structure

```
/opt/mcp-kali-server/          # Installation directory
├── kali_server.py             # Main server entrypoint
├── mcp_server/                # Server package
│   ├── api.py                 # FastAPI application
│   ├── auth.py                # Authentication & enrollment
│   ├── artifacts.py           # Artifact storage & parsing
│   ├── memory.py              # Observation recording
│   ├── scope.py               # Guardrails & validation
│   ├── tools.py               # Tool execution
│   ├── util.py                # Utilities & schema validation
│   └── schemas/               # Tool schemas
│       └── tools/
│           └── net_scan_basic.json
├── requirements.txt           # Python dependencies
└── install.sh                # Installation script

/etc/mcp-kali/                 # Configuration directory
├── enroll.json               # Enrollment token (root only)
├── credentials.json          # API credentials (root only)
└── scope.json               # Scope configuration

/var/lib/mcp/                 # Data directory
├── artifacts/               # Tool output storage
│   └── {server-id}/
│       └── {run-id}/
│           ├── raw.xml       # Raw tool output
│           ├── summary.txt   # Auto-generated summary
│           ├── parsed.json   # Parsed structured data
│           └── metadata.json # Artifact metadata
└── memory/                  # Memory database
    └── observations.db      # SQLite database
```

## Service Management

```bash
# Check service status
sudo systemctl status mcp-kali-server

# View logs
sudo journalctl -u mcp-kali-server -f

# Restart service
sudo systemctl restart mcp-kali-server

# Stop service
sudo systemctl stop mcp-kali-server

# Disable service
sudo systemctl disable mcp-kali-server
```

## Testing Connection

Test the complete workflow:

```bash
#!/bin/bash
SERVER_IP="192.168.1.100"
API_KEY="your-api-key-here"

# 1. Health check
echo "Testing health endpoint..."
curl -s -H "Authorization: Bearer ${API_KEY}" \
  "http://${SERVER_IP}:5000/health" | jq

# 2. List tools
echo -e "\nListing available tools..."
curl -s -H "Authorization: Bearer ${API_KEY}" \
  "http://${SERVER_IP}:5000/tools/list" | jq

# 3. Run scan
echo -e "\nRunning network scan..."
curl -s -X POST "http://${SERVER_IP}:5000/tools/call" \
  -H "Authorization: Bearer ${API_KEY}" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "net.scan_basic",
    "arguments": {
      "target": "127.0.0.1",
      "fast": true
    }
  }' | jq

# 4. List artifacts
echo -e "\nListing artifacts..."
curl -s -H "Authorization: Bearer ${API_KEY}" \
  "http://${SERVER_IP}:5000/artifacts/list" | jq

# 5. Check memory
echo -e "\nChecking memory stats..."
curl -s -H "Authorization: Bearer ${API_KEY}" \
  "http://${SERVER_IP}:5000/memory/stats" | jq
```

## DARK MATER MCP Client

This server is designed to work seamlessly with the **DARK MATER MCP Client** - a sophisticated dashboard for managing multiple MCP servers and coordinating security testing operations.

### Key Integration Features
- 🔗 **Automatic Discovery**: The client can discover and connect to MCP servers
- 🎯 **Centralized Management**: Control multiple Kali servers from one interface
- 📊 **Real-time Monitoring**: Live server status and health monitoring
- 🛠️ **Tool Orchestration**: Execute security tools across multiple servers
- 📁 **Artifact Management**: Centralized collection and analysis of results
- 🧠 **Knowledge Base**: Shared memory and findings across servers

### Connection Setup
1. **Install and start** this MCP server using the CLI tool
2. **Enroll the server** to get your API credentials  
3. **Add server to client** using the enrollment details
4. **Start testing** with full dashboard capabilities

The DARK MATER ecosystem provides a complete security testing platform with distributed server management and comprehensive reporting capabilities.

## Security Considerations

### Network Security
- Run on isolated network segments
- Use firewall rules to restrict access
- Enable TLS for production deployments
- Consider mTLS for high-security environments

### Scope Limitations
- Configure `allowed_cidrs` to match your testing environment
- Set `allow_destructive: false` for reconnaissance-only mode
- Review scope configuration regularly

### Authentication
- Protect enrollment tokens (stored in `/etc/mcp-kali/enroll.json`)
- Rotate API keys periodically
- Monitor authentication failures in logs

### File Permissions
- Configuration files are root-only readable
- Service runs as unprivileged `mcpserver` user
- Artifacts stored with proper ownership

## Troubleshooting

### Service Won't Start

```bash
# Check service status
sudo systemctl status mcp-kali-server

# Check logs for errors
sudo journalctl -u mcp-kali-server --no-pager

# Common issues:
# - Python dependencies missing
# - Permissions on directories
# - Port already in use
```

### Authentication Failures

```bash
# Check if enrollment token exists
sudo ls -la /etc/mcp-kali/enroll.json

# Verify API credentials
sudo cat /etc/mcp-kali/credentials.json | jq

# Regenerate enrollment token
sudo rm /etc/mcp-kali/enroll.json
sudo ./install.sh  # Will generate new token
```

### Tool Execution Errors

```bash
# Check scope configuration
cat /etc/mcp-kali/scope.json

# Verify nmap is installed
which nmap

# Check tool logs
sudo journalctl -u mcp-kali-server | grep "Tool.*failed"
```

### Network Issues

```bash
# Test basic connectivity
curl -I http://SERVER_IP:5000/status

# Check if port is listening
sudo netstat -tlnp | grep :5000

# Verify firewall rules
sudo ufw status
```

## Uninstallation

```bash
# Run uninstaller
sudo ./install.sh --uninstall

# Manual cleanup if needed
sudo systemctl stop mcp-kali-server
sudo systemctl disable mcp-kali-server
sudo rm /etc/systemd/system/mcp-kali-server.service
sudo userdel mcpserver
sudo rm -rf /opt/mcp-kali-server
sudo rm -rf /var/lib/mcp

# Configuration files (remove manually if desired)
sudo rm -rf /etc/mcp-kali
```

## Development

### Manual Installation

For manual setup or customization:

```bash
# As root, create directory and set ownership
mkdir -p /opt/mcp-kali-server
chown -R mcpserver:mcpserver /opt/mcp-kali-server

# Clone repository as mcpserver user
sudo -u mcpserver git clone git@github.com:khalilpreview/MCP-Kali-Server.git /opt/mcp-kali-server

# Create virtual environment and install dependencies
sudo -u mcpserver python3 -m venv /opt/mcp-kali-server/venv
sudo -u mcpserver /opt/mcp-kali-server/venv/bin/pip install -r /opt/mcp-kali-server/requirements.txt
```

### Running Without Systemd

If you're running in Docker, WSL, chroot, or another environment without systemd:

```bash
# First, verify your init system (optional)
ps -p 1 -o comm=

# If you don't see "systemd", that's why systemctl fails
```

**Quickest way to run the server:**

```bash
# Start server in foreground
/opt/mcp-kali-server/venv/bin/python /opt/mcp-kali-server/kali_server.py --bind 0.0.0.0:5000

# Or run in background with nohup to keep it alive
nohup /opt/mcp-kali-server/venv/bin/python /opt/mcp-kali-server/kali_server.py --bind 0.0.0.0:5000 > /var/log/mcp-kali-server.log 2>&1 &

# With ngrok tunnel (if needed)
nohup /opt/mcp-kali-server/venv/bin/python /opt/mcp-kali-server/kali_server.py --bind 0.0.0.0:5000 --ngrok --ngrok-authtoken YOUR_TOKEN > /var/log/mcp-kali-server.log 2>&1 &
```

### Adding New Tools

1. Create schema in `mcp_server/schemas/tools/toolname.json`
2. Add tool executor to `ToolRegistry` in `mcp_server/tools.py`
3. Implement safe argument parsing and execution
4. Add scope and destructiveness checks
5. Test thoroughly in isolated environment

### API Extensions

The FastAPI app in `mcp_server/api.py` can be extended with additional endpoints. Follow the existing patterns for authentication and error handling.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

- GitHub Issues: https://github.com/khalilpreview/MCP-Kali-Server/issues
- Documentation: https://github.com/khalilpreview/MCP-Kali-Server/wiki

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes with tests
4. Submit a pull request

Please ensure all changes maintain security best practices and include appropriate tests.
