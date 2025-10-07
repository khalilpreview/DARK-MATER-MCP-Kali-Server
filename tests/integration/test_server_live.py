#!/usr/bin/env python3
"""
Live Server Testing Script
Starts the MCP Kali Server and generates test requests to demonstrate functionality.
"""

import subprocess
import time
import requests
import json
import threading
import sys
import os

def start_server():
    """Start the server in a separate process"""
    print("🚀 Starting MCP Kali Server...")
    proc = subprocess.Popen([
        sys.executable, 'start_monitored_server.py'
    ], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
    
    # Print server output until it's ready
    for line in iter(proc.stdout.readline, ''):
        print(line.rstrip())
        if 'Uvicorn running on' in line:
            break
    
    return proc

def test_server():
    """Test the server with various requests"""
    api_key = 'dk_U8BE1DBs0bOuSGIyc7e0xgqUD_goVqJOCI38ICSnCt4'
    headers = {'Authorization': f'Bearer {api_key}', 'Content-Type': 'application/json'}
    
    time.sleep(3)  # Wait for server to fully start
    
    print('\n🔥 TESTING SERVER - Generating activity...')
    print('=' * 50)
    
    tests = [
        ('Health Check', 'GET', 'http://127.0.0.1:5001/health', None),
        ('Tools List', 'GET', 'http://127.0.0.1:5001/tools/list', None),
        ('Valid Target Test', 'POST', 'http://127.0.0.1:5001/tools/call', {
            'name': 'net.scan_basic',
            'arguments': {'target': '192.168.1.1', 'fast': True}
        }),
        ('Invalid Target Test', 'POST', 'http://127.0.0.1:5001/tools/call', {
            'name': 'net.scan_basic', 
            'arguments': {'target': '127.0.0.1', 'fast': True}
        }),
        ('Artifacts List', 'GET', 'http://127.0.0.1:5001/artifacts/list', None),
    ]
    
    for i, (name, method, url, payload) in enumerate(tests, 1):
        print(f'{i}. {name}...')
        try:
            if method == 'GET':
                response = requests.get(url, headers=headers, timeout=10)
            else:
                response = requests.post(url, headers=headers, json=payload, timeout=10)
            
            print(f'   ✅ Status: {response.status_code}')
            
            if response.status_code == 200:
                data = response.json()
                if 'error' in data:
                    print(f'   🛡️  Security: {data["error"]}')
                elif 'summary' in data:
                    print(f'   📊 Summary: {data["summary"][:50]}...')
                elif 'tools' in data:
                    print(f'   📊 Tools: {len(data["tools"])} available')
                elif 'ok' in data:
                    print(f'   💚 Health: OK')
                
        except Exception as e:
            print(f'   ❌ Error: {e}')
        
        time.sleep(2)
    
    print('\n🎯 Test complete! Server logs should show all activity.')

def main():
    """Main function to run the live test"""
    # Start server
    server_proc = start_server()
    
    # Start testing in a separate thread
    test_thread = threading.Thread(target=test_server)
    test_thread.start()
    
    # Wait for testing to complete
    test_thread.join()
    
    print('\n⏹️  Tests completed. Server is still running for monitoring.')
    print('   Press Ctrl+C to stop the server.')
    
    # Keep server running and show its output
    try:
        for line in iter(server_proc.stdout.readline, ''):
            print(line.rstrip())
    except KeyboardInterrupt:
        print('\n🛑 Stopping server...')
        server_proc.terminate()
        server_proc.wait()

if __name__ == '__main__':
    main()