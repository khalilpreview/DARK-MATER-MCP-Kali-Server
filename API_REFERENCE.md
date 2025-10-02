# DARK MATER MCP Server - API Reference

## Quick Reference

### Base URL
- **Local**: `http://SERVER_IP:5000`  
- **Ngrok**: `https://RANDOM_ID.ngrok-free.app`

### Authentication
All endpoints except `/enroll` require:
```
Authorization: Bearer api_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

---

## Endpoints

### 🔐 Enrollment (Public)

**POST /enroll**

```json
{
  "id": "kali-hostname-timestamp",
  "token": "enrollment_token_from_server", 
  "label": "Dashboard Name"
}
```

**Response:**
```json
{
  "server_id": "kali-hostname-timestamp",
  "api_key": "api_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
  "label": "Dashboard Name"
}
```

---

### ❤️ Health Check

**GET /health**

**Response:**
```json
{
  "ok": true,
  "server_id": "kali-hostname-timestamp",
  "caps": {
    "tools": true,
    "artifacts": true,
    "memory": true
  },
  "time": "2025-10-02T23:40:46.451Z"
}
```

---

### 🛠️ Tools

**GET /tools/list**

**Response:**
```json
{
  "tools": [
    {
      "name": "net.scan_basic",
      "description": "Basic network scanning using nmap",
      "schema": "/schemas/tools/net_scan_basic.json"
    }
  ]
}
```

**POST /tools/call**

```json
{
  "name": "net.scan_basic",
  "arguments": {
    "target": "192.168.1.1",
    "ports": "80,443,22",
    "fast": true
  }
}
```

**Response:**
```json
{
  "rc": 0,
  "summary": "Scan completed: 3/3 ports open on 192.168.1.1",
  "artifact_uri": "artifact://server-id/run-id/raw.xml",
  "findings": [
    {
      "host": "192.168.1.1",
      "port": 80,
      "service": "http",
      "version": "nginx 1.18.0"
    }
  ]
}
```

---

### 📦 Artifacts

**GET /artifacts/list?limit=50&offset=0**

**Response:**
```json
{
  "items": [
    {
      "artifact_uri": "artifact://server-id/run-id/raw.xml",
      "summary": "Network scan of 192.168.1.1 - 3 ports discovered",
      "created": "2025-10-02T23:40:46.451Z"
    }
  ],
  "nextOffset": 50
}
```

**GET /artifacts/read?uri=artifact://server-id/run-id/raw.xml**

Returns raw file content (XML, JSON, or text)

---

### 🌐 Ngrok Info

**GET /ngrok/info**

**Response:**
```json
{
  "status": "active",
  "public_url": "https://abc123.ngrok-free.app",
  "local_port": 5000,
  "protocol": "http"
}
```

---

## Tool Schemas

### net.scan_basic

**Arguments:**
- `target` (required): IP address or hostname
- `ports` (optional): Port specification (e.g., "80,443,22" or "1-1000")
- `fast` (optional, default: true): Use fast scan mode

**Scope Validation:**
- Target must be within allowed CIDR ranges
- Configured in `/etc/mcp-kali/scope.json`

**Example:**
```json
{
  "name": "net.scan_basic",
  "arguments": {
    "target": "192.168.1.0/24",
    "ports": "22,80,443,8080", 
    "fast": false
  }
}
```

---

## Error Responses

### 401 Unauthorized
```json
{
  "detail": "Not authenticated"
}
```

### 403 Forbidden
```json
{
  "error": "Target out of scope",
  "detail": "192.168.1.1 not in allowed CIDR ranges"
}
```

### 400 Bad Request
```json
{
  "error": "Invalid arguments",
  "detail": "target is required"
}
```

### 500 Internal Server Error
```json
{
  "error": "Internal server error",
  "detail": "An unexpected error occurred"
}
```

---

## Rate Limits

- **Enrollment**: 5 requests per minute per IP
- **Tool Execution**: 10 concurrent executions per server
- **API Calls**: 1000 requests per hour per API key

---

## WebSocket Support

**Coming Soon**: Real-time updates for long-running tools

**Planned Endpoint**: `ws://SERVER/tools/execute/stream`

---

## Client Libraries

### Python Example

```python
import requests

class DarkMaterClient:
    def __init__(self, base_url, api_key):
        self.base_url = base_url
        self.headers = {"Authorization": f"Bearer {api_key}"}
    
    def health_check(self):
        response = requests.get(f"{self.base_url}/health", headers=self.headers)
        return response.json()
    
    def execute_tool(self, tool_name, arguments):
        payload = {"name": tool_name, "arguments": arguments}
        response = requests.post(
            f"{self.base_url}/tools/call", 
            json=payload, 
            headers=self.headers
        )
        return response.json()

# Usage
client = DarkMaterClient("http://192.168.1.100:5000", "api_xxx")
result = client.execute_tool("net.scan_basic", {"target": "192.168.1.1", "fast": True})
```

### JavaScript Example

```javascript
class DarkMaterClient {
    constructor(baseUrl, apiKey) {
        this.baseUrl = baseUrl;
        this.headers = {
            'Authorization': `Bearer ${apiKey}`,
            'Content-Type': 'application/json'
        };
    }
    
    async healthCheck() {
        const response = await fetch(`${this.baseUrl}/health`, {
            headers: this.headers
        });
        return response.json();
    }
    
    async executeTool(toolName, arguments) {
        const response = await fetch(`${this.baseUrl}/tools/call`, {
            method: 'POST',
            headers: this.headers,
            body: JSON.stringify({
                name: toolName,
                arguments: arguments
            })
        });
        return response.json();
    }
}

// Usage
const client = new DarkMaterClient('http://192.168.1.100:5000', 'api_xxx');
const result = await client.executeTool('net.scan_basic', {
    target: '192.168.1.1',
    fast: true
});
```

---

## Testing with curl

```bash
# Get enrollment token from server
cat /etc/mcp-kali/enroll.json

# Enroll dashboard
curl -X POST http://192.168.1.100:5000/enroll \
  -H "Content-Type: application/json" \
  -d '{"id":"SERVER_ID","token":"TOKEN","label":"My Dashboard"}'

# Health check
curl -H "Authorization: Bearer API_KEY" \
  http://192.168.1.100:5000/health

# Execute scan
curl -X POST http://192.168.1.100:5000/tools/call \
  -H "Authorization: Bearer API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"name":"net.scan_basic","arguments":{"target":"127.0.0.1","fast":true}}'

# List artifacts
curl -H "Authorization: Bearer API_KEY" \
  "http://192.168.1.100:5000/artifacts/list?limit=10"
```