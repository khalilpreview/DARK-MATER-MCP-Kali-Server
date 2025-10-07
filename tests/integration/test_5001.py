#!/usr/bin/env python3
"""
Test the MCP server on port 5001.
"""

import requests
import time
import json

def test_server_5001():
    api_key = 'dk_U8BE1DBs0bOuSGIyc7e0xgqUD_goVqJOCI38ICSnCt4'
    headers = {'Authorization': f'Bearer {api_key}'}

    print('🔄 Testing MCP Server on port 5001...')
    
    try:
        response = requests.get('http://127.0.0.1:5001/health', headers=headers, timeout=5)
        if response.status_code == 200:
            data = response.json()
            print('✅ MCP Server is running successfully on port 5001!')
            print(f'   Server ID: {data.get("server_id", "N/A")}')
            print(f'   Status: {data.get("ok", "N/A")}')
            print(f'   Capabilities: {list(data.get("caps", {}).keys())}')
            print(f'   Time: {data.get("time", "N/A")}')
            
            # Test tools endpoint
            print('\n🔧 Testing tools endpoint...')
            tools_response = requests.get('http://127.0.0.1:5001/tools/list', headers=headers, timeout=5)
            if tools_response.status_code == 200:
                tools_data = tools_response.json()
                print(f'✅ Tools endpoint working!')
                print(f'   Available tools: {len(tools_data.get("tools", []))}')
                for tool in tools_data.get("tools", [])[:3]:
                    print(f'     - {tool.get("name", "N/A")}: {tool.get("description", "N/A")[:50]}...')
            else:
                print(f'❌ Tools endpoint failed: {tools_response.status_code}')
            
            return True
        else:
            print(f'❌ Server responded with status: {response.status_code}')
            print(f'   Response: {response.text[:200]}...')
            return False
    except Exception as e:
        print(f'❌ Error connecting to server: {e}')
        return False

if __name__ == "__main__":
    test_server_5001()