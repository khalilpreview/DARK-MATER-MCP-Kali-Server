"""
Test script for LLM Configuration System
"""
import requests
import json
import time
import sys

def test_llm_config():
    """Test the LLM configuration system"""
    
    print("🧪 LLM Configuration System Test")
    print("=" * 50)
    
    base_url = "http://127.0.0.1:5000"
    
    # Test server connectivity
    try:
        response = requests.get(f"{base_url}/", timeout=5)
        if response.status_code != 200:
            print(f"❌ Server not responding: {response.status_code}")
            return False
        print("✅ Server is running")
        
    except Exception as e:
        print(f"❌ Cannot connect to server: {e}")
        print("💡 Make sure the server is running on port 5000")
        return False
    
    # Create enrollment
    print("\n🔐 Creating enrollment...")
    enrollment_data = {
        "id": "kali-lab-01",
        "token": "test-token-for-llm-config-123456789",
        "label": "LLM Configuration Test"
    }
    
    try:
        enroll_response = requests.post(f"{base_url}/enroll", json=enrollment_data, timeout=10)
        
        if enroll_response.status_code != 200:
            print(f"❌ Enrollment failed: {enroll_response.status_code}")
            print(f"📋 Response: {enroll_response.text}")
            return False
            
        credentials = enroll_response.json()
        api_key = credentials["api_key"]
        server_id = credentials["server_id"]
        
        print(f"✅ Enrolled server: {server_id}")
        print(f"🔑 API Key: {api_key[:20]}...")
        
    except Exception as e:
        print(f"❌ Enrollment error: {e}")
        return False
    
    # Test LLM configuration endpoints
    headers = {"Authorization": f"Bearer {api_key}"}
    
    print(f"\n📋 Testing LLM Configuration Endpoints...")
    
    # Get default configuration
    try:
        config_response = requests.get(f"{base_url}/llm/config", headers=headers, timeout=5)
        
        if config_response.status_code != 200:
            print(f"❌ Failed to get LLM config: {config_response.status_code}")
            return False
            
        current_config = config_response.json()
        print("✅ Retrieved default LLM configuration")
        print(f"📋 Current ETag: {current_config.get('etag', 'none')}")
        print(f"📋 System Prompt: {current_config.get('system_prompt', '')[:100]}...")
        
    except Exception as e:
        print(f"❌ Error getting LLM config: {e}")
        return False
    
    # Apply your target configuration
    print(f"\n🔧 Applying target LLM configuration...")
    
    target_config = {
        "system_prompt": "You are the MCP Server Assistant for Kali-Lab-01. Use only provided memory, knowledge, and live context. Respond with explicit, copy-pastable steps. If action is risky, ask for confirmation and suggest a dry run. Keep answers under 200 tokens unless logs are requested.",
        "guardrails": {
            "disallowed": ["secrets", "credentials", "api_keys"], 
            "style": "concise"
        },
        "runtime_hints": {
            "preferred_model": "phi3:mini", 
            "num_ctx": 768, 
            "temperature": 0.2, 
            "num_gpu": 0, 
            "keep_alive": 0
        },
        "tools_allowed": ["nmap-scan", "cme-enum", "zap-active"]
    }
    
    try:
        # Use ETag for optimistic concurrency
        update_headers = {**headers, "If-Match": current_config.get("etag", "")}
        
        update_response = requests.put(
            f"{base_url}/llm/config",
            json=target_config,
            headers=update_headers,
            timeout=10
        )
        
        if update_response.status_code != 200:
            print(f"❌ Failed to update LLM config: {update_response.status_code}")
            print(f"📋 Response: {update_response.text}")
            return False
            
        updated_config = update_response.json()
        print("✅ Successfully updated LLM configuration!")
        print(f"📋 New ETag: {updated_config.get('etag', 'none')}")
        
        # Verify the configuration was applied
        verify_response = requests.get(f"{base_url}/llm/config", headers=headers, timeout=5)
        if verify_response.status_code == 200:
            verified_config = verify_response.json()
            
            print(f"\n📋 Configuration Applied Successfully:")
            print(f"   🎯 Server ID: {verified_config['server_id']}")
            print(f"   🤖 Model: {verified_config['runtime_hints'].get('preferred_model', 'not set')}")
            print(f"   🌡️  Temperature: {verified_config['runtime_hints'].get('temperature', 'not set')}")
            print(f"   🛠️  Tools Allowed: {len(verified_config.get('tools_allowed', []))} tools")
            print(f"   🛡️  Guardrails: {list(verified_config.get('guardrails', {}).keys())}")
            
            # Show the actual configuration
            print(f"\n📝 Full Configuration:")
            print(json.dumps(verified_config, indent=2))
            
        return True
        
    except Exception as e:
        print(f"❌ Error updating LLM config: {e}")
        return False
    
    # Test other LLM endpoints
    print(f"\n🧠 Testing other LLM endpoints...")
    
    # Test JWT token creation
    try:
        token_request = {"api_key": api_key}
        token_response = requests.post(f"{base_url}/auth/token", json=token_request, timeout=5)
        
        if token_response.status_code == 200:
            token_data = token_response.json()
            print(f"✅ JWT token created successfully")
            print(f"🔑 Token type: {token_data.get('token_type', 'unknown')}")
            print(f"⏰ Expires in: {token_data.get('expires_in', 0)} seconds")
        else:
            print(f"❌ JWT token creation failed: {token_response.status_code}")
            
    except Exception as e:
        print(f"❌ JWT token error: {e}")
    
    # Test live context
    try:
        context_response = requests.get(f"{base_url}/llm/context", headers=headers, timeout=5)
        
        if context_response.status_code == 200:
            context_data = context_response.json()
            print(f"✅ Live context retrieved")
            print(f"📊 Uptime: {context_data.get('uptime', 'unknown')}")
            print(f"💽 Disk usage: {context_data.get('disk_usage', 'unknown')}")
            print(f"🚨 Alerts: {len(context_data.get('alerts', []))}")
        else:
            print(f"❌ Live context failed: {context_response.status_code}")
            
    except Exception as e:
        print(f"❌ Live context error: {e}")
    
    print(f"\n🎉 LLM Configuration System Test Complete!")
    return True

if __name__ == "__main__":
    success = test_llm_config()
    if success:
        print(f"\n✅ All tests passed!")
        sys.exit(0)
    else:
        print(f"\n❌ Some tests failed!")
        sys.exit(1)