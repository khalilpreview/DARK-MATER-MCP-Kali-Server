#!/usr/bin/env python3
"""
Simplified DARK MATER MCP Server Startup
Generates API key directly without enrollment process
"""

import json
import secrets
import socket
import os
from datetime import datetime
from pathlib import Path

def generate_server_credentials():
    """Generate server credentials directly"""
    
    # Generate server ID and API key
    hostname = socket.gethostname()
    timestamp = int(datetime.now().timestamp())
    server_id = f'kali-{hostname}-{timestamp}'
    api_key = f"dk_{secrets.token_urlsafe(32)}"  # dk = dark kali
    
    # Create credentials
    credentials = {
        "server_id": server_id,
        "api_key": api_key,
        "label": "DARK-MATER-Server",
        "created": datetime.now().isoformat(),
        "auto_generated": True
    }
    
    # Ensure config directory exists
    if os.name == 'nt':  # Windows
        config_dir = Path.home() / ".mcp-kali"
    else:  # Linux
        config_dir = Path("/etc/mcp-kali")
    
    config_dir.mkdir(parents=True, exist_ok=True)
    
    # Save credentials
    creds_file = config_dir / "credentials.json"
    with open(creds_file, 'w') as f:
        json.dump(credentials, f, indent=2)
    
    # Set permissions (on Unix-like systems)
    if os.name != 'nt':
        os.chmod(creds_file, 0o600)
    
    print(f"✅ Server credentials generated!")
    print(f"📋 Server ID: {server_id}")
    print(f"🔑 API Key: {api_key}")
    print(f"💾 Saved to: {creds_file}")
    
    return credentials

if __name__ == "__main__":
    # Generate credentials
    creds = generate_server_credentials()
    
    # Show usage
    print(f"\n🚀 Ready to use!")
    print(f"Start server: python kali_server.py --bind 127.0.0.1:5001")
    print(f"Test health: curl -H 'Authorization: Bearer {creds['api_key']}' http://localhost:5001/health")