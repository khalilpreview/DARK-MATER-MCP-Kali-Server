#!/usr/bin/env python3
"""
Test MCP servers on different ports.
"""

import requests
import json

def test_mcp_servers():
    api_key = 'dk_U8BE1DBs0bOuSGIyc7e0xgqUD_goVqJOCI38ICSnCt4'
    headers = {'Authorization': f'Bearer {api_key}'}

    def test_endpoint(port, endpoint, description):
        try:
            url = f'http://127.0.0.1:{port}{endpoint}'
            response = requests.get(url, headers=headers, timeout=5)
            print(f'✅ {description} (Port {port})')
            print(f'   Status: {response.status_code}')
            if response.status_code == 200:
                try:
                    data = response.json()
                    if 'server_id' in data:
                        print(f'   Server ID: {data["server_id"]}')
                    if 'caps' in data:
                        caps = list(data['caps'].keys())
                        print(f'   Capabilities: {caps}')
                    if 'tools' in data:
                        print(f'   Tools available: {len(data["tools"])}')
                        for tool in data['tools'][:3]:  # Show first 3 tools
                            print(f'     - {tool.get("name", "N/A")}: {tool.get("description", "N/A")[:50]}...')
                    
                    # Show key response data
                    key_data = {k: v for k, v in data.items() if k in ['server_id', 'ok', 'time', 'caps']}
                    print(f'   Key data: {json.dumps(key_data, indent=2)}')
                except Exception as e:
                    print(f'   JSON parse error: {e}')
                    print(f'   Raw response: {response.text[:200]}...')
            else:
                print(f'   Error: {response.text[:100]}')
            return response
        except Exception as e:
            print(f'❌ {description} (Port {port}): {e}')
            return None

    print('🔍 Testing MCP Servers with API Key')
    print('=' * 60)

    # Test both ports
    for port in [5000, 5001]:
        print(f'\n📡 Testing Port {port}:')
        
        # Test health endpoint
        health_resp = test_endpoint(port, '/health', 'Health Check')
        
        # Test tools list if health works
        if health_resp and health_resp.status_code == 200:
            tools_resp = test_endpoint(port, '/tools/list', 'Tools List')
        
        print('-' * 40)

if __name__ == "__main__":
    test_mcp_servers()