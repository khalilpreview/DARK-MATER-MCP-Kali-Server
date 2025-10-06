#!/usr/bin/env python3
"""
Script to demonstrate MCP server logs with test requests.
"""

import uvicorn
from mcp_server.api import app
import logging
import sys
import requests
import threading
import time
import json
from datetime import datetime

def make_test_requests():
    """Make test requests to generate logs."""
    api_key = 'dk_U8BE1DBs0bOuSGIyc7e0xgqUD_goVqJOCI38ICSnCt4'
    headers = {'Authorization': f'Bearer {api_key}', 'Content-Type': 'application/json'}
    
    # Wait for server to start
    print("🔄 Waiting for server to start...")
    time.sleep(3)
    
    print("🧪 Starting test requests to generate logs...")
    
    try:
        # Test 1: Health check
        print("📋 1. Testing /health endpoint...")
        response = requests.get('http://127.0.0.1:5001/health', headers=headers, timeout=5)
        print(f"   Response: {response.status_code}")
        
        time.sleep(1)
        
        # Test 2: Tools list
        print("📋 2. Testing /tools/list endpoint...")
        response = requests.get('http://127.0.0.1:5001/tools/list', headers=headers, timeout=5)
        print(f"   Response: {response.status_code}")
        
        time.sleep(1)
        
        # Test 3: Simple tool execution
        print("📋 3. Testing /tools/call endpoint (nmap scan)...")
        payload = {
            'name': 'net.scan_basic',
            'arguments': {
                'target': '127.0.0.1',
                'fast': True
            }
        }
        response = requests.post('http://127.0.0.1:5001/tools/call', 
                               headers=headers, 
                               data=json.dumps(payload), 
                               timeout=30)
        print(f"   Response: {response.status_code}")
        
        time.sleep(1)
        
        # Test 4: Artifacts
        print("📋 4. Testing /artifacts/list endpoint...")
        response = requests.get('http://127.0.0.1:5001/artifacts/list', headers=headers, timeout=5)
        print(f"   Response: {response.status_code}")
        
        print("✅ Test requests completed!")
        
    except Exception as e:
        print(f"❌ Test request failed: {e}")

def start_server_with_logs():
    """Start server with comprehensive logging."""
    
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
        handlers=[logging.StreamHandler(sys.stdout)]
    )
    
    print("🚀 MCP Kali Server - LOG MONITORING DEMO")
    print("=" * 60)
    print(f"📡 Server URL: http://127.0.0.1:5001") 
    print(f"🔑 API Key: dk_U8BE1DBs0bOuSGIyc7e0xgqUD_goVqJOCI38ICSnCt4")
    print(f"⏰ Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)
    
    # Start test requests in background thread
    test_thread = threading.Thread(target=make_test_requests, daemon=True)
    test_thread.start()
    
    try:
        uvicorn.run(
            app,
            host='127.0.0.1',
            port=5001,
            log_level='info',
            access_log=True,
            use_colors=True
        )
    except KeyboardInterrupt:
        print(f"\n⏹️ Server stopped at {datetime.now().strftime('%H:%M:%S')}")
    except Exception as e:
        print(f"\n❌ Server error: {e}")

if __name__ == "__main__":
    start_server_with_logs()