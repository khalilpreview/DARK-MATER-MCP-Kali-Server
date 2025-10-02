# DARK MATER | MCP Kali Server v2.0

A production-ready Model Context Protocol (MCP) server for security testing with Kali Linux tools. Features enrollment-based authentication, schema-validated tool execution, artifact storage with auto-parsing, memory hooks, and comprehensive guardrails.

## Features

- 🔐 **Enrollment & API Key Authentication**: Secure server enrollment with bearer token auth
- 🛡️ **Schema Validation**: JSON Schema validation for all tool arguments
- 🎯 **Scope & Guardrails**: CIDR-based targeting with destructive operation controls
- 📦 **Artifact Storage**: Automatic storage and parsing of tool outputs with summaries
- 🧠 **Memory Hooks**: Lightweight observation recording for analysis patterns
- 🌐 **HTTP API**: RESTful endpoints for dashboard integration
- 🔧 **Systemd Integration**: Production-ready service with automatic startup
- 🔒 **Optional TLS/mTLS**: Support for encrypted connections

## Quick Start

### Installation

Run the installer on your Kali Linux system:

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
- Display enrollment JSON for copying

### Enrollment

After installation, use the displayed enrollment JSON to register your server:

```bash
# Example enrollment (use your actual values)
SERVER_IP="192.168.1.100"
curl -X POST "http://${SERVER_IP}:5000/enroll" \
  -H "Content-Type: application/json" \
  -d '{
    "id": "a1b2c3d4",
    "token": "e5f6g7h8i9j0k1l2m3n4o5p6",
    "label": "Kali-Lab-1"
  }'
```

Response:
```json
{
  "server_id": "a1b2c3d4",
  "api_key": "your-64-char-api-key-here",
  "label": "Kali-Lab-1"
}
```

Save the `api_key` - you'll need it for all subsequent requests.

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

## Dashboard Integration

The server provides dashboard-friendly endpoints:

1. **Connection Test**: GET `/health` → returns server capabilities
2. **Tool Discovery**: GET `/tools/list` → returns available tools with schemas  
3. **Tool Execution**: POST `/tools/call` → executes tools with validation
4. **Artifact Access**: GET `/artifacts/list` and `/artifacts/read` → access results
5. **Memory Search**: GET `/memory/search` → search observations

### Required Fields for Dashboard

When connecting from a dashboard, you need:
- **Server URL**: `http://SERVER_IP:5000`  
- **API Key**: Bearer token from enrollment response
- **Server ID**: Returned in enrollment response (for artifact filtering)

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
