#!/usr/bin/env python3
"""
Quick test script for DARK MATER MCP Server
Run this to test the server locally from Windows
"""

import json
import requests
import secrets
import socket
import datetime
import os
import time
import subprocess
import sys

def print_colored(text, color="white"):
    colors = {
        "red": "\033[91m",
        "green": "\033[92m", 
        "yellow": "\033[93m",
        "blue": "\033[94m",
        "cyan": "\033[96m",
        "white": "\033[97m",
        "end": "\033[0m"
    }
    print(f"{colors.get(color, '')}{text}{colors['end']}")

def test_server():
    """Test the MCP server"""
    print_colored("🧪 DARK MATER MCP Server Test", "cyan")
    print_colored("=" * 50, "blue")
    
    # Step 1: Check if server is running
    print_colored("\n1️⃣ Checking if server is running...", "blue")
    try:
        response = requests.get("http://localhost:5000/health", timeout=5)
        print_colored(f"✅ Server responding with status: {response.status_code}", "green")
        
        if response.status_code == 403:
            print_colored("ℹ️  403 Forbidden - Server needs enrollment", "yellow")
        elif response.status_code == 401:
            print_colored("ℹ️  401 Unauthorized - Missing API key", "yellow")
            
    except requests.exceptions.ConnectionError:
        print_colored("❌ Server not running on localhost:5000", "red")
        print_colored("💡 Start server with: python kali_server.py --bind 127.0.0.1:5000", "yellow")
        return False
    except Exception as e:
        print_colored(f"❌ Error connecting: {e}", "red")
        return False
    
    # Step 2: Generate enrollment token
    print_colored("\n2️⃣ Generating enrollment token...", "blue")
    try:
        server_id = f'kali-{socket.gethostname()}-{int(datetime.datetime.now().timestamp())}'
        token = secrets.token_urlsafe(32)
        
        enrollment_data = {
            'id': server_id,
            'token': token,
            'created': datetime.datetime.now().isoformat()
        }
        
        # Save to temp file
        os.makedirs('temp_config', exist_ok=True)
        with open('temp_config/enroll.json', 'w') as f:
            json.dump(enrollment_data, f, indent=2)
            
        print_colored(f"✅ Token generated: {server_id}", "green")
        
    except Exception as e:
        print_colored(f"❌ Failed to generate token: {e}", "red")
        return False
    
    # Step 3: Enroll server
    print_colored("\n3️⃣ Enrolling server...", "blue")
    try:
        payload = {
            'id': server_id,
            'token': token,
            'label': 'Dev-Test-Server'
        }
        
        response = requests.post(
            "http://localhost:5000/enroll",
            json=payload,
            headers={'Content-Type': 'application/json'},
            timeout=10
        )
        
        if response.status_code == 200:
            creds = response.json()
            print_colored("✅ Server enrolled successfully!", "green")
            print_colored(f"Server ID: {creds['server_id']}", "white")
            print_colored(f"Label: {creds['label']}", "white")
            print_colored(f"API Key: {creds['api_key'][:20]}...", "white")
            
            # Save credentials
            with open('temp_config/credentials.json', 'w') as f:
                json.dump(creds, f, indent=2)
                
            api_key = creds['api_key']
            
        else:
            print_colored(f"❌ Enrollment failed: HTTP {response.status_code}", "red")
            print_colored(f"Response: {response.text}", "red")
            return False
            
    except Exception as e:
        print_colored(f"❌ Enrollment error: {e}", "red")
        return False
    
    # Step 4: Test authenticated health check
    print_colored("\n4️⃣ Testing authenticated health check...", "blue")
    try:
        response = requests.get(
            "http://localhost:5000/health",
            headers={'Authorization': f'Bearer {api_key}'},
            timeout=5
        )
        
        if response.status_code == 200:
            health_data = response.json()
            print_colored("✅ Authenticated health check successful!", "green")
            print_colored(f"Server OK: {health_data.get('ok', False)}", "white")
            print_colored(f"Server ID: {health_data.get('server_id', 'Unknown')}", "white")
            print_colored(f"Capabilities: {health_data.get('caps', {})}", "white")
            
            if health_data.get('ngrok_tunnel'):
                tunnel_info = health_data['ngrok_tunnel']
                print_colored(f"🌐 Ngrok Status: {tunnel_info.get('status', 'unknown')}", "cyan")
                if tunnel_info.get('public_url'):
                    print_colored(f"🔗 Public URL: {tunnel_info['public_url']}", "cyan")
                    
        else:
            print_colored(f"❌ Health check failed: HTTP {response.status_code}", "red")
            return False
            
    except Exception as e:
        print_colored(f"❌ Health check error: {e}", "red")
        return False
    
    # Step 5: Test tools endpoint
    print_colored("\n5️⃣ Testing tools endpoint...", "blue")
    try:
        response = requests.get(
            "http://localhost:5000/tools/list",
            headers={'Authorization': f'Bearer {api_key}'},
            timeout=5
        )
        
        if response.status_code == 200:
            tools_data = response.json()
            print_colored("✅ Tools endpoint working!", "green")
            print_colored(f"Available tools: {len(tools_data.get('tools', []))}", "white")
            
            for tool in tools_data.get('tools', []):
                print_colored(f"  - {tool.get('name', 'Unknown')}: {tool.get('description', 'No description')}", "white")
                
        else:
            print_colored(f"⚠️ Tools endpoint returned: HTTP {response.status_code}", "yellow")
            
    except Exception as e:
        print_colored(f"❌ Tools endpoint error: {e}", "red")
    
    print_colored("\n🎉 Server test completed successfully!", "green")
    print_colored("=" * 50, "blue")
    print_colored(f"💾 Credentials saved to: temp_config/credentials.json", "cyan")
    print_colored(f"🔑 API Key: {api_key}", "cyan")
    print_colored("🌐 Server URL: http://localhost:5000", "cyan")
    
    return True

if __name__ == "__main__":
    test_server()