#!/usr/bin/env python3
"""
Get credentials and server info for MCP Kali Server.
"""

import json
import os
from pathlib import Path
from datetime import datetime

def get_credentials():
    """Get server credentials and enrollment info."""
    
    # Configuration paths for Windows
    config_dir = Path.home() / ".mcp-kali"
    enroll_file = config_dir / "enroll.json"
    credentials_file = config_dir / "credentials.json"
    
    print("🔍 MCP Kali Server - Credentials & Info")
    print("=" * 50)
    
    # Check enrollment info
    if enroll_file.exists():
        print("\n📋 ENROLLMENT INFO:")
        try:
            with open(enroll_file, 'r') as f:
                enroll_data = json.load(f)
            
            print(f"  Server ID: {enroll_data.get('id', 'N/A')}")
            print(f"  Token: {enroll_data.get('token', 'N/A')}")
            print(f"  Created: {enroll_data.get('created', 'N/A')}")
            
        except Exception as e:
            print(f"  Error reading enrollment file: {e}")
    else:
        print("\n📋 ENROLLMENT INFO: Not found")
    
    # Check credentials
    if credentials_file.exists():
        print("\n🔑 API CREDENTIALS:")
        try:
            with open(credentials_file, 'r') as f:
                creds_data = json.load(f)
            
            # Handle both single credential and multiple credentials format
            if 'server_id' in creds_data:
                # Single credential format
                print(f"  Server ID: {creds_data.get('server_id', 'N/A')}")
                print(f"  API Key: {creds_data.get('api_key', 'N/A')}")
                print(f"  Label: {creds_data.get('label', 'N/A')}")
                print(f"  Created: {creds_data.get('created', 'N/A')}")
                if creds_data.get('auto_generated'):
                    print("  Type: Auto-generated")
            else:
                # Multiple credentials format
                for server_id, cred in creds_data.items():
                    print(f"  Server ID: {server_id}")
                    print(f"  API Key: {cred.get('api_key', 'N/A')}")
                    print(f"  Label: {cred.get('label', 'N/A')}")
                    print(f"  Created: {cred.get('created', 'N/A')}")
                    print("  ---")
            
        except Exception as e:
            print(f"  Error reading credentials file: {e}")
    else:
        print("\n🔑 API CREDENTIALS: Not found")
    
    # Show configuration paths
    print(f"\n📁 CONFIG PATHS:")
    print(f"  Config Dir: {config_dir}")
    print(f"  Enrollment: {enroll_file}")
    print(f"  Credentials: {credentials_file}")
    
    # Show server status
    print(f"\n🌐 SERVER INFO:")
    print(f"  Default Port: 5000")
    print(f"  Health Check: GET http://localhost:5000/health")
    print(f"  Tools List: GET http://localhost:5000/tools/list")
    
    # Show curl examples if credentials exist
    if credentials_file.exists():
        try:
            with open(credentials_file, 'r') as f:
                creds_data = json.load(f)
            
            api_key = creds_data.get('api_key')
            if api_key:
                print(f"\n💻 QUICK TEST COMMANDS:")
                print(f"  # Health check")
                print(f'  curl -H "Authorization: Bearer {api_key}" http://localhost:5000/health')
                print(f"\n  # List tools")
                print(f'  curl -H "Authorization: Bearer {api_key}" http://localhost:5000/tools/list')
                print(f"\n  # Run nmap scan")
                print(f'''  curl -X POST -H "Authorization: Bearer {api_key}" -H "Content-Type: application/json" \\
    -d '{{"name":"net.scan_basic","arguments":{{"target":"127.0.0.1","fast":true}}}}' \\
    http://localhost:5000/tools/call''')
        except:
            pass
    
    print(f"\n⚡ QUICK START:")
    print(f"  1. Start server: python kali_server.py --bind 0.0.0.0:5000")
    print(f"  2. Test health: Use curl command above")
    print(f"  3. Run tools: Use tools/call endpoint")
    
    return True

if __name__ == "__main__":
    get_credentials()