# DARK MATER MCP Server - Integration Guide

## Overview

This document provides comprehensive integration guidance for connecting the **DARK MATER MCP Client Web Dashboard** to the **DARK MATER MCP Kali Server**. The integration follows a secure enrollment-based authentication model with RESTful API endpoints.

## Architecture Overview

```
┌─────────────────────────────────────┐    HTTP/HTTPS     ┌──────────────────────────────────────┐
│     DARK MATER Client Dashboard     │◄─────────────────►│    DARK MATER MCP Kali Server        │
│                                     │                   │                                      │
│  • React/Vue/Angular Frontend      │                   │  • FastAPI Backend                   │
│  • Node.js/Python/PHP Backend      │                   │  • Kali Linux Tools Integration     │
│  • Authentication Management       │                   │  • Ngrok Tunneling Support          │
│  • Server Management UI            │                   │  • Schema-Validated Tool Execution  │
└─────────────────────────────────────┘                   └──────────────────────────────────────┘
```

## Authentication Flow

### 1. Server Enrollment Process

```mermaid
sequenceDiagram
    participant Dashboard as Dashboard Backend
    participant KaliServer as Kali MCP Server
    participant Admin as Admin User

    Admin->>KaliServer: Install & Start Server
    KaliServer-->>Admin: Generate Enrollment Token
    Admin->>Dashboard: Enter Server Details + Token
    Dashboard->>KaliServer: POST /enroll
    KaliServer-->>Dashboard: Return API Key
    Dashboard->>Dashboard: Store API Key Securely
    Dashboard->>KaliServer: Use API Key for all requests
```

### 2. Connection Establishment

The dashboard backend needs to:

1. **Collect Server Information** from admin user
2. **Perform Enrollment** using one-time token
3. **Store API Credentials** securely
4. **Test Connection** before saving
5. **Use Bearer Authentication** for all subsequent requests

## API Endpoints

### Base URL Format
- **Local**: `http://SERVER_IP:5000`
- **Ngrok**: `https://RANDOM_ID.ngrok-free.app` (dynamic)

### 1. Enrollment (Public Endpoint)

**POST /enroll**

```json
// Request
{
  "id": "string",           // From enrollment token
  "token": "string",        // From enrollment token  
  "label": "string"         // Dashboard identifier
}

// Response (200)
{
  "server_id": "kali-hostname-timestamp",
  "api_key": "api_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
  "label": "DARK-MATER-Dashboard"
}

// Error Responses
{
  "error": "Invalid enrollment token",
  "detail": "Token expired or already used"
}
```

### 2. Health Check (Authenticated)

**GET /health**

```bash
Authorization: Bearer api_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

```json
// Response (200)
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

// Error (401)
{
  "detail": "Not authenticated"
}
```

### 3. Available Tools (Authenticated)

**GET /tools/list**

```json
// Response (200)
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

### 4. Execute Tool (Authenticated)

**POST /tools/call**

```json
// Request
{
  "name": "net.scan_basic",
  "arguments": {
    "target": "192.168.1.1",
    "ports": "80,443,22",
    "fast": true
  }
}

// Response (200)
{
  "rc": 0,
  "summary": "Scan completed: 3/3 ports open on 192.168.1.1",
  "artifact_uri": "artifact://kali-server-123/run-456/raw.xml",
  "findings": [
    {
      "host": "192.168.1.1",
      "port": 80,
      "service": "http",
      "version": "nginx 1.18.0"
    },
    {
      "host": "192.168.1.1", 
      "port": 443,
      "service": "https", 
      "version": "nginx 1.18.0"
    }
  ]
}

// Error (403) - Out of scope
{
  "error": "Target out of scope",
  "detail": "192.168.1.1 not in allowed CIDR ranges"
}
```

### 5. Artifacts Management (Authenticated)

**GET /artifacts/list**

Query Parameters:
- `limit`: Number of items (default: 50)
- `offset`: Pagination offset (default: 0)

```json
// Response (200)
{
  "items": [
    {
      "artifact_uri": "artifact://kali-server-123/run-456/raw.xml",
      "summary": "Network scan of 192.168.1.1 - 3 ports discovered",
      "created": "2025-10-02T23:40:46.451Z"
    }
  ],
  "nextOffset": 50
}
```

**GET /artifacts/read**

Query Parameters:
- `uri`: Full artifact URI

```json
// Response (200) - Returns raw file content
// Content-Type varies (application/xml, text/plain, application/json)
```

### 6. Ngrok Information (Authenticated)

**GET /ngrok/info**

```json
// Response (200)
{
  "status": "active",
  "public_url": "https://f0e7ca09d47d.ngrok-free.app",
  "local_port": 5000,
  "protocol": "http",
  "name": "http-5000-uuid"
}

// Response (200) - Inactive
{
  "status": "inactive"
}
```

## Integration Implementation

### Backend Requirements

Your dashboard backend needs to implement:

#### 1. Server Management Model

```python
# Example Python/Django Model
class KaliServer(models.Model):
    name = models.CharField(max_length=100)
    host = models.CharField(max_length=255)  # IP or ngrok URL
    port = models.IntegerField(default=5000)
    server_id = models.CharField(max_length=100, unique=True)
    api_key = models.CharField(max_length=200)  # Encrypted storage
    is_active = models.BooleanField(default=False)
    last_seen = models.DateTimeField(null=True)
    capabilities = models.JSONField(default=dict)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'kali_servers'
```

```javascript
// Example Node.js/MongoDB Schema
const serverSchema = new mongoose.Schema({
  name: { type: String, required: true },
  host: { type: String, required: true },
  port: { type: Number, default: 5000 },
  serverId: { type: String, unique: true, required: true },
  apiKey: { type: String, required: true }, // Encrypt this
  isActive: { type: Boolean, default: false },
  lastSeen: { type: Date },
  capabilities: { type: Object, default: {} },
  createdAt: { type: Date, default: Date.now }
});
```

#### 2. Server Registration Flow

```python
# Example Python Implementation
import requests
import json
from datetime import datetime

class KaliServerManager:
    
    def enroll_server(self, host, port, enrollment_data, label):
        """
        Enroll a new Kali MCP Server
        
        Args:
            host: Server hostname/IP
            port: Server port
            enrollment_data: {id, token} from server enrollment
            label: Dashboard identifier
        """
        url = f"http://{host}:{port}/enroll"
        
        payload = {
            "id": enrollment_data["id"],
            "token": enrollment_data["token"], 
            "label": label
        }
        
        try:
            response = requests.post(url, json=payload, timeout=10)
            response.raise_for_status()
            
            result = response.json()
            
            # Store server credentials
            server = KaliServer.objects.create(
                name=label,
                host=host,
                port=port,
                server_id=result["server_id"],
                api_key=self.encrypt_api_key(result["api_key"]),
                is_active=True
            )
            
            # Test connection
            if self.test_connection(server):
                return {"success": True, "server": server}
            else:
                server.delete()
                return {"success": False, "error": "Connection test failed"}
                
        except requests.exceptions.RequestException as e:
            return {"success": False, "error": str(e)}
    
    def test_connection(self, server):
        """Test server connectivity and update capabilities"""
        try:
            headers = {"Authorization": f"Bearer {self.decrypt_api_key(server.api_key)}"}
            url = f"http://{server.host}:{server.port}/health"
            
            response = requests.get(url, headers=headers, timeout=5)
            response.raise_for_status()
            
            health_data = response.json()
            
            # Update server info
            server.is_active = health_data["ok"]
            server.capabilities = health_data["caps"]
            server.last_seen = datetime.now()
            server.save()
            
            return True
            
        except Exception:
            server.is_active = False
            server.save()
            return False
```

```javascript
// Example Node.js Implementation
class KaliServerManager {
    
    async enrollServer(host, port, enrollmentData, label) {
        const url = `http://${host}:${port}/enroll`;
        
        const payload = {
            id: enrollmentData.id,
            token: enrollmentData.token,
            label: label
        };
        
        try {
            const response = await fetch(url, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });
            
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}`);
            }
            
            const result = await response.json();
            
            // Store server
            const server = new KaliServer({
                name: label,
                host: host,
                port: port,
                serverId: result.server_id,
                apiKey: this.encryptApiKey(result.api_key),
                isActive: true
            });
            
            await server.save();
            
            // Test connection
            const connectionOk = await this.testConnection(server);
            if (!connectionOk) {
                await server.deleteOne();
                throw new Error('Connection test failed');
            }
            
            return { success: true, server };
            
        } catch (error) {
            return { success: false, error: error.message };
        }
    }
    
    async testConnection(server) {
        try {
            const headers = {
                'Authorization': `Bearer ${this.decryptApiKey(server.apiKey)}`
            };
            
            const url = `http://${server.host}:${server.port}/health`;
            const response = await fetch(url, { headers });
            
            if (!response.ok) return false;
            
            const healthData = await response.json();
            
            // Update server
            server.isActive = healthData.ok;
            server.capabilities = healthData.caps;
            server.lastSeen = new Date();
            await server.save();
            
            return true;
            
        } catch (error) {
            server.isActive = false;
            await server.save();
            return false;
        }
    }
}
```

#### 3. Tool Execution

```python
def execute_tool(self, server, tool_name, arguments):
    """Execute a tool on the Kali server"""
    headers = {"Authorization": f"Bearer {self.decrypt_api_key(server.api_key)}"}
    url = f"http://{server.host}:{server.port}/tools/call"
    
    payload = {
        "name": tool_name,
        "arguments": arguments
    }
    
    try:
        response = requests.post(url, json=payload, headers=headers, timeout=300)
        response.raise_for_status()
        
        result = response.json()
        
        # Store execution result
        execution = ToolExecution.objects.create(
            server=server,
            tool_name=tool_name,
            arguments=arguments,
            return_code=result["rc"],
            summary=result["summary"],
            artifact_uri=result.get("artifact_uri"),
            findings=result.get("findings", [])
        )
        
        return {"success": True, "execution": execution, "result": result}
        
    except requests.exceptions.RequestException as e:
        return {"success": False, "error": str(e)}
```

### Frontend Integration

#### 1. Server Management UI

```jsx
// React Component Example
import React, { useState } from 'react';

const ServerEnrollment = () => {
    const [formData, setFormData] = useState({
        name: '',
        host: '',
        port: 5000,
        enrollmentId: '',
        enrollmentToken: ''
    });
    
    const handleEnroll = async (e) => {
        e.preventDefault();
        
        const response = await fetch('/api/servers/enroll', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(formData)
        });
        
        const result = await response.json();
        
        if (result.success) {
            // Redirect to server dashboard
            window.location.href = `/servers/${result.server.id}`;
        } else {
            alert(`Enrollment failed: ${result.error}`);
        }
    };
    
    return (
        <form onSubmit={handleEnroll}>
            <div>
                <label>Server Name:</label>
                <input 
                    type="text" 
                    value={formData.name}
                    onChange={(e) => setFormData({...formData, name: e.target.value})}
                    required 
                />
            </div>
            
            <div>
                <label>Host/IP:</label>
                <input 
                    type="text" 
                    value={formData.host}
                    onChange={(e) => setFormData({...formData, host: e.target.value})}
                    placeholder="192.168.1.100 or xxx.ngrok-free.app"
                    required 
                />
            </div>
            
            <div>
                <label>Port:</label>
                <input 
                    type="number" 
                    value={formData.port}
                    onChange={(e) => setFormData({...formData, port: parseInt(e.target.value)})}
                />
            </div>
            
            <div>
                <label>Enrollment ID:</label>
                <input 
                    type="text" 
                    value={formData.enrollmentId}
                    onChange={(e) => setFormData({...formData, enrollmentId: e.target.value})}
                    placeholder="From /etc/mcp-kali/enroll.json"
                    required 
                />
            </div>
            
            <div>
                <label>Enrollment Token:</label>
                <input 
                    type="text" 
                    value={formData.enrollmentToken}
                    onChange={(e) => setFormData({...formData, enrollmentToken: e.target.value})}
                    placeholder="From /etc/mcp-kali/enroll.json"
                    required 
                />
            </div>
            
            <button type="submit">Enroll Server</button>
        </form>
    );
};
```

#### 2. Tool Execution Interface

```jsx
const ToolExecution = ({ server }) => {
    const [selectedTool, setSelectedTool] = useState('');
    const [toolArgs, setToolArgs] = useState({});
    const [results, setResults] = useState(null);
    const [loading, setLoading] = useState(false);
    
    const executeTool = async () => {
        setLoading(true);
        
        const response = await fetch(`/api/servers/${server.id}/tools/execute`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                tool: selectedTool,
                arguments: toolArgs
            })
        });
        
        const result = await response.json();
        setResults(result);
        setLoading(false);
    };
    
    return (
        <div>
            <select value={selectedTool} onChange={(e) => setSelectedTool(e.target.value)}>
                <option value="">Select Tool</option>
                <option value="net.scan_basic">Network Scan (Basic)</option>
            </select>
            
            {selectedTool === 'net.scan_basic' && (
                <div>
                    <input 
                        placeholder="Target (IP/hostname)"
                        onChange={(e) => setToolArgs({...toolArgs, target: e.target.value})}
                    />
                    <input 
                        placeholder="Ports (80,443,22)"
                        onChange={(e) => setToolArgs({...toolArgs, ports: e.target.value})}
                    />
                    <label>
                        <input 
                            type="checkbox"
                            onChange={(e) => setToolArgs({...toolArgs, fast: e.target.checked})}
                        />
                        Fast scan
                    </label>
                </div>
            )}
            
            <button onClick={executeTool} disabled={loading || !selectedTool}>
                {loading ? 'Executing...' : 'Execute Tool'}
            </button>
            
            {results && (
                <div>
                    <h3>Results</h3>
                    <p><strong>Summary:</strong> {results.summary}</p>
                    <p><strong>Return Code:</strong> {results.rc}</p>
                    
                    {results.findings && (
                        <table>
                            <thead>
                                <tr>
                                    <th>Host</th>
                                    <th>Port</th>
                                    <th>Service</th>
                                    <th>Version</th>
                                </tr>
                            </thead>
                            <tbody>
                                {results.findings.map((finding, i) => (
                                    <tr key={i}>
                                        <td>{finding.host}</td>
                                        <td>{finding.port}</td>
                                        <td>{finding.service}</td>
                                        <td>{finding.version}</td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    )}
                </div>
            )}
        </div>
    );
};
```

## Error Handling

### Common Error Scenarios

1. **Server Unreachable**
   - Network connectivity issues
   - Server not running
   - Firewall blocking connections

2. **Authentication Errors**
   - Invalid API key
   - Expired enrollment token
   - Missing Authorization header

3. **Tool Execution Errors**
   - Target out of scope
   - Invalid arguments
   - Destructive operations blocked
   - Tool timeout

### Error Response Format

```json
{
  "error": "Error category",
  "detail": "Specific error message",
  "timestamp": "2025-10-02T23:40:46.451Z"
}
```

## Security Considerations

### 1. API Key Storage
- **Encrypt API keys** in your database
- Use strong encryption (AES-256)
- Store encryption keys separately

### 2. Network Security
- **Use HTTPS** when possible (ngrok provides HTTPS)
- **Validate SSL certificates** in production
- **Implement rate limiting** on your dashboard

### 3. Input Validation
- **Validate all user inputs** before sending to Kali server
- **Sanitize hostnames and IPs**
- **Prevent command injection** attempts

### 4. Access Control
- **Implement user authentication** on your dashboard
- **Role-based access control** for server management
- **Audit logging** for all tool executions

## Testing

### Connection Test Endpoint

Create a test endpoint in your dashboard:

```python
@app.route('/api/servers/<server_id>/test')
def test_server_connection(server_id):
    server = KaliServer.query.get_or_404(server_id)
    
    result = kali_manager.test_connection(server)
    
    return {
        "success": result,
        "server_id": server.server_id,
        "last_seen": server.last_seen.isoformat() if server.last_seen else None,
        "capabilities": server.capabilities
    }
```

### Sample curl Commands for Testing

```bash
# Test enrollment
curl -X POST http://localhost:5000/enroll \
  -H "Content-Type: application/json" \
  -d '{"id":"kali-server-123","token":"abc123","label":"test-dashboard"}'

# Test health check
curl -H "Authorization: Bearer api_xxxx" \
  http://localhost:5000/health

# Test tool execution
curl -X POST http://localhost:5000/tools/call \
  -H "Authorization: Bearer api_xxxx" \
  -H "Content-Type: application/json" \
  -d '{"name":"net.scan_basic","arguments":{"target":"127.0.0.1","fast":true}}'
```

## Deployment Considerations

### 1. Production Setup
- Use **reverse proxy** (nginx) for HTTPS termination
- Implement **load balancing** for multiple Kali servers
- Set up **monitoring and alerting**

### 2. Scaling
- Design for **multiple Kali servers** per dashboard
- Implement **server health monitoring**
- Handle **server disconnections** gracefully

### 3. Monitoring
- Monitor **API response times**
- Track **tool execution success rates**
- Alert on **server connectivity issues**

## Troubleshooting

### Common Integration Issues

1. **Enrollment fails**: Check server logs, verify token hasn't been used
2. **401 Unauthorized**: Verify API key format and Bearer header
3. **Connection timeout**: Check firewall, server status, network connectivity
4. **Tool execution fails**: Check target scope, server capabilities

### Debug Endpoints

The Kali server provides debug information:

```bash
# Server status
GET /health

# Available tools
GET /tools/list

# Ngrok status  
GET /ngrok/info
```

This integration guide provides everything needed to successfully connect your DARK MATER MCP Client dashboard to the Kali MCP Server. The provided code examples can be adapted to your specific backend technology stack.