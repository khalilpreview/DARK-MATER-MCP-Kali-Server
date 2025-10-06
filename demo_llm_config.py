"""
LLM Configuration Demonstration

This shows how your LLM configuration would be applied to the MCP Kali Server
once the server is running.
"""

import json

# Your target LLM configuration
target_config = {
    "server_id": "kali-lab-01",
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

print("🔧 LLM Configuration for MCP Kali Server")
print("=" * 60)
print()

print("📝 Configuration Summary:")
print(f"   🎯 Server ID: {target_config['server_id']}")
print(f"   🤖 Model: {target_config['runtime_hints']['preferred_model']}")
print(f"   🌡️  Temperature: {target_config['runtime_hints']['temperature']}")
print(f"   🧠 Context Size: {target_config['runtime_hints']['num_ctx']} tokens")
print(f"   🛠️  Allowed Tools: {len(target_config['tools_allowed'])} tools")
print(f"   🛡️  Guardrails: {len(target_config['guardrails']['disallowed'])} restricted terms")
print()

print("🤖 System Prompt:")
print("-" * 40)
print(target_config['system_prompt'])
print()

print("🛡️ Guardrails:")
print("-" * 40)
print(f"Disallowed terms: {', '.join(target_config['guardrails']['disallowed'])}")
print(f"Response style: {target_config['guardrails']['style']}")
print()

print("⚙️ Runtime Hints:")
print("-" * 40)
for key, value in target_config['runtime_hints'].items():
    print(f"  {key}: {value}")
print()

print("🛠️ Allowed Tools:")
print("-" * 40)
for tool in target_config['tools_allowed']:
    print(f"  ✓ {tool}")
print()

print("📡 API Commands to Apply This Configuration:")
print("-" * 60)

print("""
# 1. Start the MCP server
python -m uvicorn mcp_server.api:app --host 127.0.0.1 --port 5000

# 2. Enroll the server (get API key)
curl -X POST http://127.0.0.1:5000/enroll \\
  -H "Content-Type: application/json" \\
  -d '{"id": "kali-lab-01", "token": "your-enrollment-token", "label": "LLM Test Server"}'

# 3. Get current LLM configuration (with API key from step 2)
curl -H "Authorization: Bearer YOUR_API_KEY" \\
  http://127.0.0.1:5000/llm/config

# 4. Update LLM configuration with your settings
curl -X PUT http://127.0.0.1:5000/llm/config \\
  -H "Authorization: Bearer YOUR_API_KEY" \\
  -H "Content-Type: application/json" \\
  -H "If-Match: CURRENT_ETAG" \\
  -d '{
    "system_prompt": "You are the MCP Server Assistant for Kali-Lab-01...",
    "guardrails": {"disallowed": ["secrets","credentials","api_keys"], "style": "concise"},
    "runtime_hints": {"preferred_model": "phi3:mini", "num_ctx": 768, "temperature": 0.2},
    "tools_allowed": ["nmap-scan","cme-enum","zap-active"]
  }'

# 5. Verify configuration was applied
curl -H "Authorization: Bearer YOUR_API_KEY" \\
  http://127.0.0.1:5000/llm/config
""")

print()
print("🧠 Knowledge Management Examples:")
print("-" * 40)

print("""
# Add knowledge document
curl -X POST http://127.0.0.1:5000/llm/knowledge/docs \\
  -H "Authorization: Bearer YOUR_API_KEY" \\
  -d '{"title": "Kali Security Guide", "source": "manual", "tags": ["security", "pentesting"]}'

# Add knowledge chunks
curl -X POST http://127.0.0.1:5000/llm/knowledge/docs/DOC_ID/chunks \\
  -H "Authorization: Bearer YOUR_API_KEY" \\
  -d '{"chunks": ["Use nmap for network discovery", "CME for credential enumeration"]}'

# Search knowledge
curl -H "Authorization: Bearer YOUR_API_KEY" \\
  "http://127.0.0.1:5000/llm/knowledge/search?q=nmap%20scanning&top_k=3"
""")

print()
print("💬 Memory Management Examples:")
print("-" * 40)

print("""
# Append conversation
curl -X POST http://127.0.0.1:5000/memory/append \\
  -H "Authorization: Bearer YOUR_API_KEY" \\
  -d '{"thread_id": "session-123", "role": "user", "content": "Scan 192.168.1.0/24"}'

# Retrieve conversation with context
curl -H "Authorization: Bearer YOUR_API_KEY" \\
  "http://127.0.0.1:5000/memory/retrieve?thread_id=session-123&q=network%20scanning&limit=10"
""")

print()
print("📊 Live Context Example:")
print("-" * 40)

print("""
# Get dynamic server context
curl -H "Authorization: Bearer YOUR_API_KEY" \\
  http://127.0.0.1:5000/llm/context
""")

print()
print("🔐 JWT Authentication:")
print("-" * 40)

print("""
# Get JWT token for dashboard
curl -X POST http://127.0.0.1:5000/auth/token \\
  -d '{"api_key": "YOUR_API_KEY"}'

# Use JWT token
curl -H "Authorization: Bearer JWT_TOKEN" \\
  http://127.0.0.1:5000/llm/config
""")

print()
print("✅ Configuration Ready!")
print("🚀 Once the server is running, these endpoints will configure the LLM system")
print("🤖 Your AI assistant will be configured with the specified prompt and guardrails")
print("🧠 Knowledge and memory systems will be available for context-aware responses")
print()

# Save configuration to file for easy reference
with open("llm_config_target.json", "w") as f:
    json.dump(target_config, f, indent=2)

print("💾 Configuration saved to: llm_config_target.json")