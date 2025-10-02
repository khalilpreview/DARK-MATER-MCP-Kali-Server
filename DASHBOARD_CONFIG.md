# DARK MATER Dashboard Backend Configuration

## Environment Variables

Create a `.env` file in your dashboard backend with these variables:

```bash
# Database Configuration
DATABASE_URL=postgresql://user:password@localhost:5432/dark_mater_dashboard
# or
DATABASE_URL=mongodb://localhost:27017/dark_mater_dashboard

# Security
SECRET_KEY=your-super-secret-key-for-jwt-tokens
API_KEY_ENCRYPTION_KEY=your-32-byte-encryption-key-for-api-keys

# DARK MATER Settings
DASHBOARD_NAME=DARK MATER Control Center
DEFAULT_SERVER_PORT=5000
MAX_CONCURRENT_SCANS=5
SCAN_TIMEOUT_SECONDS=300

# Optional: Rate Limiting
RATE_LIMIT_ENABLED=true
REQUESTS_PER_MINUTE=100

# Optional: Logging
LOG_LEVEL=INFO
LOG_FILE=logs/dashboard.log

# Optional: Redis for Caching (if using)
REDIS_URL=redis://localhost:6379/0
```

## Database Tables/Collections

### PostgreSQL Schema

```sql
-- Kali Servers Table
CREATE TABLE kali_servers (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    host VARCHAR(255) NOT NULL,
    port INTEGER DEFAULT 5000,
    server_id VARCHAR(100) UNIQUE NOT NULL,
    api_key_encrypted TEXT NOT NULL,
    is_active BOOLEAN DEFAULT false,
    last_seen TIMESTAMP,
    capabilities JSONB DEFAULT '{}',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Tool Executions Table
CREATE TABLE tool_executions (
    id SERIAL PRIMARY KEY,
    server_id INTEGER REFERENCES kali_servers(id) ON DELETE CASCADE,
    tool_name VARCHAR(100) NOT NULL,
    arguments JSONB NOT NULL,
    return_code INTEGER,
    summary TEXT,
    artifact_uri VARCHAR(500),
    findings JSONB DEFAULT '[]',
    execution_time_ms INTEGER,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_by_user_id INTEGER -- If you have user management
);

-- Server Health History
CREATE TABLE server_health_history (
    id SERIAL PRIMARY KEY,
    server_id INTEGER REFERENCES kali_servers(id) ON DELETE CASCADE,
    is_healthy BOOLEAN NOT NULL,
    response_time_ms INTEGER,
    error_message TEXT,
    checked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Indexes
CREATE INDEX idx_kali_servers_server_id ON kali_servers(server_id);
CREATE INDEX idx_tool_executions_server_id ON tool_executions(server_id);
CREATE INDEX idx_tool_executions_created_at ON tool_executions(created_at);
CREATE INDEX idx_server_health_server_id ON server_health_history(server_id);
```

### MongoDB Schema

```javascript
// kali_servers collection
{
  _id: ObjectId,
  name: String,
  host: String,
  port: Number,
  serverId: String, // unique
  apiKeyEncrypted: String,
  isActive: Boolean,
  lastSeen: Date,
  capabilities: Object,
  createdAt: Date,
  updatedAt: Date
}

// tool_executions collection
{
  _id: ObjectId,
  serverId: ObjectId, // reference to kali_servers
  toolName: String,
  arguments: Object,
  returnCode: Number,
  summary: String,
  artifactUri: String,
  findings: Array,
  executionTimeMs: Number,
  createdAt: Date,
  createdByUserId: ObjectId // optional
}

// server_health_history collection
{
  _id: ObjectId,
  serverId: ObjectId,
  isHealthy: Boolean,
  responseTimeMs: Number,
  errorMessage: String,
  checkedAt: Date
}
```

## API Endpoints for Your Dashboard

Your dashboard backend should expose these endpoints:

### Server Management
- `POST /api/servers/enroll` - Enroll new Kali server
- `GET /api/servers` - List all servers
- `GET /api/servers/:id` - Get server details
- `PUT /api/servers/:id` - Update server settings
- `DELETE /api/servers/:id` - Remove server
- `POST /api/servers/:id/test` - Test server connection

### Tool Operations
- `GET /api/servers/:id/tools` - List available tools
- `POST /api/servers/:id/tools/execute` - Execute tool
- `GET /api/executions` - List tool execution history
- `GET /api/executions/:id` - Get execution details

### Artifacts
- `GET /api/artifacts` - List artifacts across all servers
- `GET /api/artifacts/:id` - Get artifact content
- `DELETE /api/artifacts/:id` - Delete artifact

### Dashboard Analytics  
- `GET /api/dashboard/stats` - Overall statistics
- `GET /api/dashboard/health` - All servers health status
- `GET /api/dashboard/recent-activity` - Recent tool executions

## Configuration Classes

### Python (Django/Flask)

```python
import os
from cryptography.fernet import Fernet

class DashboardConfig:
    # Database
    DATABASE_URL = os.getenv('DATABASE_URL')
    
    # Security
    SECRET_KEY = os.getenv('SECRET_KEY')
    API_KEY_ENCRYPTION_KEY = os.getenv('API_KEY_ENCRYPTION_KEY')
    
    # DARK MATER Settings
    DASHBOARD_NAME = os.getenv('DASHBOARD_NAME', 'DARK MATER Control Center')
    DEFAULT_SERVER_PORT = int(os.getenv('DEFAULT_SERVER_PORT', 5000))
    MAX_CONCURRENT_SCANS = int(os.getenv('MAX_CONCURRENT_SCANS', 5))
    SCAN_TIMEOUT_SECONDS = int(os.getenv('SCAN_TIMEOUT_SECONDS', 300))
    
    # Rate Limiting
    RATE_LIMIT_ENABLED = os.getenv('RATE_LIMIT_ENABLED', 'true').lower() == 'true'
    REQUESTS_PER_MINUTE = int(os.getenv('REQUESTS_PER_MINUTE', 100))
    
    @staticmethod
    def get_cipher():
        """Get Fernet cipher for API key encryption"""
        key = DashboardConfig.API_KEY_ENCRYPTION_KEY.encode()
        return Fernet(key)
    
    @staticmethod
    def encrypt_api_key(api_key):
        """Encrypt API key for storage"""
        cipher = DashboardConfig.get_cipher()
        return cipher.encrypt(api_key.encode()).decode()
    
    @staticmethod
    def decrypt_api_key(encrypted_key):
        """Decrypt API key for use"""
        cipher = DashboardConfig.get_cipher()
        return cipher.decrypt(encrypted_key.encode()).decode()
```

### Node.js (Express)

```javascript
const crypto = require('crypto');

class DashboardConfig {
    constructor() {
        // Database
        this.DATABASE_URL = process.env.DATABASE_URL;
        
        // Security
        this.SECRET_KEY = process.env.SECRET_KEY;
        this.API_KEY_ENCRYPTION_KEY = process.env.API_KEY_ENCRYPTION_KEY;
        
        // DARK MATER Settings
        this.DASHBOARD_NAME = process.env.DASHBOARD_NAME || 'DARK MATER Control Center';
        this.DEFAULT_SERVER_PORT = parseInt(process.env.DEFAULT_SERVER_PORT) || 5000;
        this.MAX_CONCURRENT_SCANS = parseInt(process.env.MAX_CONCURRENT_SCANS) || 5;
        this.SCAN_TIMEOUT_SECONDS = parseInt(process.env.SCAN_TIMEOUT_SECONDS) || 300;
        
        // Rate Limiting
        this.RATE_LIMIT_ENABLED = process.env.RATE_LIMIT_ENABLED !== 'false';
        this.REQUESTS_PER_MINUTE = parseInt(process.env.REQUESTS_PER_MINUTE) || 100;
    }
    
    encryptApiKey(apiKey) {
        const cipher = crypto.createCipher('aes-256-cbc', this.API_KEY_ENCRYPTION_KEY);
        let encrypted = cipher.update(apiKey, 'utf8', 'hex');
        encrypted += cipher.final('hex');
        return encrypted;
    }
    
    decryptApiKey(encryptedKey) {
        const decipher = crypto.createDecipher('aes-256-cbc', this.API_KEY_ENCRYPTION_KEY);
        let decrypted = decipher.update(encryptedKey, 'hex', 'utf8');
        decrypted += decipher.final('utf8');
        return decrypted;
    }
}

module.exports = new DashboardConfig();
```

## Middleware Requirements

### Authentication Middleware

```python
# Python/Flask example
from functools import wraps
from flask import request, jsonify

def require_auth(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token or not token.startswith('Bearer '):
            return jsonify({'error': 'Authentication required'}), 401
        
        # Validate JWT token here
        try:
            # your JWT validation logic
            user = validate_jwt_token(token.split(' ')[1])
            request.user = user
        except:
            return jsonify({'error': 'Invalid token'}), 401
        
        return f(*args, **kwargs)
    return decorated_function
```

### Rate Limiting Middleware

```javascript
// Node.js/Express example
const rateLimit = require('express-rate-limit');

const createRateLimit = (windowMs, max, message) => {
    return rateLimit({
        windowMs: windowMs,
        max: max,
        message: { error: message },
        standardHeaders: true,
        legacyHeaders: false,
    });
};

// Different limits for different endpoints
const generalLimit = createRateLimit(15 * 60 * 1000, 100, 'Too many requests');
const toolExecutionLimit = createRateLimit(60 * 1000, 10, 'Too many tool executions');

module.exports = {
    generalLimit,
    toolExecutionLimit
};
```

## Validation Schemas

### Server Enrollment Validation

```python
# Python with Pydantic
from pydantic import BaseModel, validator
import re

class ServerEnrollmentRequest(BaseModel):
    name: str
    host: str
    port: int = 5000
    enrollment_id: str
    enrollment_token: str
    
    @validator('name')
    def validate_name(cls, v):
        if len(v) < 1 or len(v) > 100:
            raise ValueError('Name must be 1-100 characters')
        return v
    
    @validator('host')
    def validate_host(cls, v):
        # Basic IP/hostname validation
        if not re.match(r'^[a-zA-Z0-9.-]+$', v):
            raise ValueError('Invalid hostname format')
        return v
    
    @validator('port')
    def validate_port(cls, v):
        if v < 1 or v > 65535:
            raise ValueError('Port must be 1-65535')
        return v
```

### Tool Execution Validation

```javascript
// Node.js with Joi
const Joi = require('joi');

const toolExecutionSchema = Joi.object({
    toolName: Joi.string().valid('net.scan_basic').required(),
    arguments: Joi.object({
        target: Joi.string().required(),
        ports: Joi.string().optional(),
        fast: Joi.boolean().default(true)
    }).required()
});

const validateToolExecution = (req, res, next) => {
    const { error } = toolExecutionSchema.validate(req.body);
    if (error) {
        return res.status(400).json({
            error: 'Invalid request',
            detail: error.details[0].message
        });
    }
    next();
};
```

This configuration setup gives you a solid foundation for your DARK MATER dashboard backend! All the files are ready to help you integrate with the Kali MCP Server.