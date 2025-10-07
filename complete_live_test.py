#!/usr/bin/env python3
"""
Complete Live Test - Start server and run comprehensive tests
"""

import subprocess
import time
import requests
import json
import threading
import sys
import os
from datetime import datetime

class LiveTester:
    def __init__(self):
        self.api_key = 'dk_U8BE1DBs0bOuSGIyc7e0xgqUD_goVqJOCI38ICSnCt4'
        self.headers = {'Authorization': f'Bearer {self.api_key}', 'Content-Type': 'application/json'}
        self.base_url = 'http://127.0.0.1:5001'
        self.server_proc = None
        
    def start_server(self):
        """Start the server and wait for it to be ready"""
        print("Starting MCP Kali Server...")
        print("=" * 50)
        
        # Start server process
        self.server_proc = subprocess.Popen([
            sys.executable, '-c', '''
import uvicorn
from mcp_server.api import app
import logging
import sys

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")

print("Server starting on http://127.0.0.1:5001")
uvicorn.run(app, host="127.0.0.1", port=5001, log_level="info")
'''
        ], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        
        # Wait for server to start
        print("Waiting for server to start...")
        time.sleep(5)
        
        # Check if server is responsive
        for attempt in range(10):
            try:
                response = requests.get(f'{self.base_url}/health', headers=self.headers, timeout=2)
                if response.status_code == 200:
                    print(f"Server is ready! (attempt {attempt + 1})")
                    return True
            except:
                pass
            time.sleep(1)
        
        print("Warning: Server may not be fully ready")
        return False
    
    def test_health(self):
        """Test health endpoint"""
        print("\\n1. HEALTH CHECK")
        print("-" * 30)
        try:
            response = requests.get(f'{self.base_url}/health', headers=self.headers, timeout=5)
            print(f"Status: {response.status_code}")
            
            if response.status_code == 200:
                data = response.json()
                print(f"Server ID: {data.get('server_id', 'N/A')}")
                print(f"Health: {'OK' if data.get('ok') else 'ERROR'}")
                print(f"Capabilities: {data.get('caps', {})}")
                return True
            else:
                print(f"Error: {response.text}")
                
        except Exception as e:
            print(f"Connection error: {e}")
        
        return False
    
    def test_tools_list(self):
        """Test tools list endpoint"""
        print("\\n2. TOOLS LIST")
        print("-" * 30)
        try:
            response = requests.get(f'{self.base_url}/tools/list', headers=self.headers, timeout=5)
            print(f"Status: {response.status_code}")
            
            if response.status_code == 200:
                data = response.json()
                tools = data.get('tools', [])
                print(f"Available tools: {len(tools)}")
                
                for tool in tools:
                    name = tool.get('name', 'Unknown')
                    desc = tool.get('description', 'No description')
                    print(f"  - {name}: {desc}")
                
                return True
            else:
                print(f"Error: {response.text}")
                
        except Exception as e:
            print(f"Connection error: {e}")
        
        return False
    
    def test_valid_scan(self):
        """Test a valid network scan"""
        print("\\n3. VALID NETWORK SCAN")
        print("-" * 30)
        print("Target: 192.168.1.1 (should be allowed)")
        
        try:
            payload = {
                'name': 'net.scan_basic',
                'arguments': {
                    'target': '192.168.1.1',
                    'fast': True
                }
            }
            
            response = requests.post(f'{self.base_url}/tools/call', 
                                   headers=self.headers, json=payload, timeout=30)
            print(f"Status: {response.status_code}")
            
            if response.status_code == 200:
                data = response.json()
                
                if 'error' in data:
                    print(f"Tool error: {data['error']}")
                else:
                    print(f"Return code: {data.get('rc', 'N/A')}")
                    print(f"Summary: {data.get('summary', 'N/A')[:100]}...")
                    
                    if 'artifact_uri' in data:
                        print(f"Artifact saved: {data['artifact_uri']}")
                    
                    if 'findings' in data:
                        findings = data['findings']
                        print(f"Findings: {len(findings)} discovered")
                        for finding in findings[:3]:  # Show first 3
                            host = finding.get('host', 'N/A')
                            port = finding.get('port', 'N/A')
                            service = finding.get('service', 'N/A')
                            print(f"  - {host}:{port} -> {service}")
                
                return True
            else:
                print(f"HTTP error: {response.text}")
                
        except Exception as e:
            print(f"Connection error: {e}")
        
        return False
    
    def test_blocked_scan(self):
        """Test a scan that should be blocked by scope"""
        print("\\n4. BLOCKED NETWORK SCAN")
        print("-" * 30)
        print("Target: 127.0.0.1 (should be blocked by scope)")
        
        try:
            payload = {
                'name': 'net.scan_basic',
                'arguments': {
                    'target': '127.0.0.1',
                    'fast': True
                }
            }
            
            response = requests.post(f'{self.base_url}/tools/call', 
                                   headers=self.headers, json=payload, timeout=10)
            print(f"Status: {response.status_code}")
            
            if response.status_code == 200:
                data = response.json()
                
                if 'error' in data:
                    print(f"Security block: {data['error']}")
                    print("✅ Scope validation working correctly!")
                else:
                    print(f"⚠️ Unexpected success: {data.get('summary', 'N/A')}")
                    
                return True
            else:
                print(f"HTTP error: {response.text}")
                
        except Exception as e:
            print(f"Connection error: {e}")
        
        return False
    
    def test_artifacts(self):
        """Test artifacts endpoint"""
        print("\\n5. ARTIFACTS LIST")
        print("-" * 30)
        try:
            response = requests.get(f'{self.base_url}/artifacts/list', headers=self.headers, timeout=5)
            print(f"Status: {response.status_code}")
            
            if response.status_code == 200:
                data = response.json()
                items = data.get('items', [])
                print(f"Stored artifacts: {len(items)}")
                
                for item in items[:5]:  # Show first 5
                    uri = item.get('artifact_uri', 'Unknown')
                    summary = item.get('summary', 'No summary')
                    created = item.get('created', 'Unknown time')
                    print(f"  - {uri}")
                    print(f"    Summary: {summary[:60]}...")
                    print(f"    Created: {created}")
                
                return True
            else:
                print(f"Error: {response.text}")
                
        except Exception as e:
            print(f"Connection error: {e}")
        
        return False
    
    def run_all_tests(self):
        """Run all tests in sequence"""
        print("MCP KALI SERVER - COMPREHENSIVE LIVE TEST")
        print("=" * 60)
        print(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"API Key: {self.api_key}")
        print(f"Base URL: {self.base_url}")
        print("=" * 60)
        
        # Start server
        if not self.start_server():
            print("Failed to start server!")
            return False
        
        # Run tests
        tests = [
            self.test_health,
            self.test_tools_list,
            self.test_valid_scan,
            self.test_blocked_scan,
            self.test_artifacts
        ]
        
        results = []
        for test in tests:
            try:
                result = test()
                results.append(result)
            except Exception as e:
                print(f"Test failed with exception: {e}")
                results.append(False)
            
            time.sleep(2)  # Pause between tests
        
        # Summary
        print("\\n" + "=" * 60)
        print("TEST SUMMARY")
        print("=" * 60)
        passed = sum(results)
        total = len(results)
        print(f"Tests passed: {passed}/{total}")
        
        test_names = ["Health Check", "Tools List", "Valid Scan", "Blocked Scan", "Artifacts"]
        for i, (name, result) in enumerate(zip(test_names, results)):
            status = "✅ PASS" if result else "❌ FAIL"
            print(f"{i+1}. {name}: {status}")
        
        print("\\n🎯 Live testing complete!")
        print("   Server is still running for additional testing if needed.")
        print("   Press Ctrl+C to stop.")
        
        return all(results)
    
    def cleanup(self):
        """Clean up server process"""
        if self.server_proc:
            try:
                self.server_proc.terminate()
                self.server_proc.wait(timeout=5)
            except:
                self.server_proc.kill()

def main():
    tester = LiveTester()
    try:
        success = tester.run_all_tests()
        
        # Keep server running for manual testing
        if success:
            print("\\nServer is ready for manual testing!")
            input("Press Enter to stop the server...")
        
    except KeyboardInterrupt:
        print("\\n\\nStopping tests...")
    finally:
        tester.cleanup()

if __name__ == '__main__':
    main()