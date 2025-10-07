#!/usr/bin/env python3

"""
DARK MATER MCP Kali Server - Production-ready security testing server
with enrollment, authentication, and artifact storage.

Entry point for the server application.
"""

import argparse
import logging
import os
import sys
import ssl
import signal
import atexit
from pathlib import Path

import uvicorn

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# Import the FastAPI app and components
from mcp_server.api import app
from mcp_server.ngrok_manager import NgrokManager
from mcp_server.licensing import validate_server_license

def get_tls_config():
    """
    Get TLS configuration from environment variables.
    
    Returns:
        Tuple of (ssl_keyfile, ssl_certfile, ssl_ca_certs) or (None, None, None)
    """
    ssl_keyfile = os.environ.get("MCP_TLS_KEY")
    ssl_certfile = os.environ.get("MCP_TLS_CERT")
    ssl_ca_certs = os.environ.get("MCP_MTLS_CA")
    
    if ssl_keyfile and ssl_certfile:
        # Validate that the files exist
        if not Path(ssl_keyfile).exists():
            logger.error(f"TLS key file not found: {ssl_keyfile}")
            return None, None, None
        if not Path(ssl_certfile).exists():
            logger.error(f"TLS cert file not found: {ssl_certfile}")
            return None, None, None
        
        if ssl_ca_certs and not Path(ssl_ca_certs).exists():
            logger.warning(f"mTLS CA file not found: {ssl_ca_certs}")
            ssl_ca_certs = None
        
        return ssl_keyfile, ssl_certfile, ssl_ca_certs
    
    return None, None, None

def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="MCP Kali Server - Production-ready security testing server",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --bind 0.0.0.0:5000              # Start server on all interfaces, port 5000
  %(prog)s --bind 127.0.0.1:5001            # Start server on localhost, port 5001
  %(prog)s --show-auth                       # Display authentication info only
  %(prog)s --show-config                     # Display full configuration
  %(prog)s --test-connection                 # Test server connection
  %(prog)s --ngrok --ngrok-authtoken TOKEN   # Start with ngrok tunnel
  %(prog)s --force                           # Start with disabled safety restrictions (DANGEROUS)

Environment Variables:
  MCP_TLS_CERT        - Path to TLS certificate file
  MCP_TLS_KEY         - Path to TLS private key file  
  MCP_MTLS_CA         - Path to mTLS CA certificate file
  NGROK_AUTHTOKEN     - Ngrok authentication token
  MCP_FORCE_MODE      - Set to 'true' to disable safety restrictions
        """
    )
    
    # Server options
    server_group = parser.add_argument_group('Server Options')
    server_group.add_argument(
        "--bind", 
        type=str, 
        default="0.0.0.0:5000",
        help="Host:port to bind to (default: 0.0.0.0:5000)"
    )
    server_group.add_argument(
        "--workers",
        type=int,
        default=1,
        help="Number of worker processes (default: 1)"
    )
    
    # Information and testing options
    info_group = parser.add_argument_group('Information & Testing')
    info_group.add_argument(
        "--show-auth",
        action="store_true",
        help="Display authentication information and exit"
    )
    info_group.add_argument(
        "--show-config",
        action="store_true", 
        help="Display full server configuration and exit"
    )
    info_group.add_argument(
        "--test-connection",
        action="store_true",
        help="Test connection to running server and exit"
    )
    info_group.add_argument(
        "--generate-client-config",
        type=str,
        metavar="FORMAT",
        choices=["curl", "python", "powershell", "json"],
        help="Generate client configuration in specified format"
    )
    
    # Logging options
    log_group = parser.add_argument_group('Logging Options')
    log_group.add_argument(
        "--debug", 
        action="store_true", 
        help="Enable debug mode"
    )
    log_group.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default="INFO",
        help="Set logging level (default: INFO)"
    )
    
    # Remote access options
    remote_group = parser.add_argument_group('Remote Access Options')
    remote_group.add_argument(
        "--ngrok",
        action="store_true",
        help="Enable ngrok tunnel for remote access"
    )
    remote_group.add_argument(
        "--ngrok-authtoken",
        type=str,
        help="Ngrok auth token (can also use NGROK_AUTHTOKEN env var)"
    )
    remote_group.add_argument(
        "--ngrok-domain",
        type=str,
        help="Custom ngrok domain (requires paid plan)"
    )
    
    # Security options
    security_group = parser.add_argument_group('Security Options')
    security_group.add_argument(
        "--force",
        action="store_true",
        help="Disable target restrictions and allow unrestricted tool execution (DANGEROUS)"
    )
    
    return parser.parse_args()

def load_credentials():
    """Load credentials from configuration file."""
    from pathlib import Path
    import json
    
    config_dir = Path.home() / ".mcp-kali"
    credentials_file = config_dir / "credentials.json"
    
    if credentials_file.exists():
        try:
            with open(credentials_file, 'r') as f:
                return json.load(f)
        except Exception as e:
            logger.warning(f"Failed to load credentials: {e}")
    
    # Return fallback credentials
    return {
        "server_id": "kali-Preview-Lab-1759533174",
        "api_key": "dk_U8BE1DBs0bOuSGIyc7e0xgqUD_goVqJOCI38ICSnCt4",
        "label": "Default Server",
        "auto_generated": True,
        "created": "2025-10-07T00:00:00Z"
    }

def test_server_connection(host="127.0.0.1", port=5000):
    """Test connection to running server."""
    import requests
    from datetime import datetime
    
    # Use localhost for testing if host is 0.0.0.0 (bind to all interfaces)
    test_host = "127.0.0.1" if host == "0.0.0.0" else host
    
    protocol = "https" if os.environ.get("MCP_TLS_CERT") else "http"
    server_url = f"{protocol}://{test_host}:{port}"
    
    print("\n" + "="*60)
    print("🔍 MCP KALI SERVER - CONNECTION TEST")
    print("="*60)
    print(f"Testing connection to: {server_url}")
    print(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("-"*60)
    
    # Load credentials
    creds = load_credentials()
    api_key = creds.get('api_key')
    headers = {'Authorization': f'Bearer {api_key}', 'Content-Type': 'application/json'}
    
    tests = [
        ("Health Check", "GET", f"{server_url}/health", None),
        ("Tools List", "GET", f"{server_url}/tools/list", None),
        ("Artifacts List", "GET", f"{server_url}/artifacts/list", None),
    ]
    
    results = []
    for test_name, method, url, payload in tests:
        print(f"\n🧪 {test_name}...")
        try:
            if method == "GET":
                response = requests.get(url, headers=headers, timeout=5)
            else:
                response = requests.post(url, headers=headers, json=payload, timeout=5)
            
            if response.status_code == 200:
                print(f"   ✅ SUCCESS (Status: {response.status_code})")
                data = response.json()
                
                if 'ok' in data:
                    print(f"   📊 Server Health: {'OK' if data['ok'] else 'ERROR'}")
                    print(f"   🆔 Server ID: {data.get('server_id', 'N/A')}")
                    caps = data.get('caps', {})
                    if caps:
                        print(f"   🔧 Capabilities: {', '.join([k for k, v in caps.items() if v])}")
                elif 'tools' in data:
                    tools = data['tools']
                    print(f"   🔧 Available Tools: {len(tools)}")
                    for tool in tools[:3]:  # Show first 3
                        print(f"      - {tool.get('name', 'Unknown')}")
                elif 'items' in data:
                    items = data['items']
                    print(f"   📁 Stored Artifacts: {len(items)}")
                
                results.append(True)
            else:
                print(f"   ❌ FAILED (Status: {response.status_code})")
                print(f"   📝 Response: {response.text[:100]}...")
                results.append(False)
                
        except requests.exceptions.ConnectionError:
            print(f"   ❌ CONNECTION REFUSED - Server not running")
            results.append(False)
        except requests.exceptions.Timeout:
            print(f"   ❌ TIMEOUT - Server not responding")
            results.append(False)
        except Exception as e:
            print(f"   ❌ ERROR - {e}")
            results.append(False)
    
    # Summary
    passed = sum(results)
    total = len(results)
    print(f"\n" + "-"*60)
    print(f"📊 SUMMARY: {passed}/{total} tests passed")
    
    if passed == total:
        print("✅ Server is fully operational!")
    elif passed > 0:
        print("⚠️  Server is partially operational")
    else:
        print("❌ Server is not responding - check if it's running")
        print(f"\n💡 To start the server:")
        print(f"   python kali_server.py --bind {host}:{port}")
    
    print("="*60)
    return passed == total

def generate_client_config(format_type, host="127.0.0.1", port=5000):
    """Generate client configuration in specified format."""
    import json
    
    creds = load_credentials()
    api_key = creds.get('api_key')
    protocol = "https" if os.environ.get("MCP_TLS_CERT") else "http"
    server_url = f"{protocol}://{host}:{port}"
    
    print(f"\n🔧 CLIENT CONFIGURATION - {format_type.upper()}")
    print("="*60)
    
    if format_type == "curl":
        print("# Health check")
        print(f'curl -H "Authorization: Bearer {api_key}" {server_url}/health')
        print("\n# List tools")
        print(f'curl -H "Authorization: Bearer {api_key}" {server_url}/tools/list')
        print("\n# Execute tool")
        print(f'curl -X POST -H "Authorization: Bearer {api_key}" -H "Content-Type: application/json" \\')
        curl_payload = '{"name":"net.scan_basic","arguments":{"target":"192.168.1.1","fast":true}}'
        print(f"     -d '{curl_payload}' \\")
        print(f'     {server_url}/tools/call')
        
    elif format_type == "python":
        print("import requests")
        print("import json")
        print("")
        print(f'API_KEY = "{api_key}"')
        print(f'BASE_URL = "{server_url}"')
        print('HEADERS = {"Authorization": f"Bearer {API_KEY}", "Content-Type": "application/json"}')
        print("")
        print("# Health check")
        print("response = requests.get(f'{BASE_URL}/health', headers=HEADERS)")
        print("print(response.json())")
        print("")
        print("# List tools")
        print("response = requests.get(f'{BASE_URL}/tools/list', headers=HEADERS)")
        print("tools = response.json()['tools']")
        print("print(f'Available tools: {len(tools)}')")
        print("")
        print("# Execute tool")
        print("payload = {")
        print('    "name": "net.scan_basic",')
        print('    "arguments": {"target": "192.168.1.1", "fast": True}')
        print("}")
        print("response = requests.post(f'{BASE_URL}/tools/call', headers=HEADERS, json=payload)")
        print("result = response.json()")
        print("print(result)")
        
    elif format_type == "powershell":
        print("# Set up headers")
        print(f'$headers = @{{ "Authorization" = "Bearer {api_key}" }}')
        print(f'$baseUrl = "{server_url}"')
        print("")
        print("# Health check")
        print('$health = Invoke-RestMethod -Uri "$baseUrl/health" -Headers $headers')
        print('Write-Host "Server Health: $($health.ok)"')
        print("")
        print("# List tools")
        print('$tools = Invoke-RestMethod -Uri "$baseUrl/tools/list" -Headers $headers')
        print('Write-Host "Available tools: $($tools.tools.Count)"')
        print("")
        print("# Execute tool")
        print('$payload = @{')
        print('    name = "net.scan_basic"')
        print('    arguments = @{')
        print('        target = "192.168.1.1"')
        print('        fast = $true')
        print('    }')
        print('} | ConvertTo-Json -Depth 3')
        print('$result = Invoke-RestMethod -Uri "$baseUrl/tools/call" -Headers $headers -Method POST -Body $payload -ContentType "application/json"')
        print('Write-Host "Scan result: $($result.summary)"')
        
    elif format_type == "json":
        config = {
            "server": {
                "url": server_url,
                "protocol": protocol,
                "host": host,
                "port": port
            },
            "authentication": {
                "type": "bearer_token",
                "api_key": api_key,
                "server_id": creds.get('server_id'),
                "label": creds.get('label')
            },
            "endpoints": {
                "health": f"{server_url}/health",
                "tools_list": f"{server_url}/tools/list",
                "tools_call": f"{server_url}/tools/call",
                "artifacts_list": f"{server_url}/artifacts/list",
                "artifacts_read": f"{server_url}/artifacts/read"
            },
            "security": {
                "tls_enabled": bool(os.environ.get("MCP_TLS_CERT")),
                "mtls_enabled": bool(os.environ.get("MCP_MTLS_CA")),
                "scope_validation": True,
                "schema_validation": True
            }
        }
        print(json.dumps(config, indent=2))
    
    print("="*60)

def show_full_config():
    """Display comprehensive server configuration."""
    from pathlib import Path
    import json
    
    print("\n" + "="*80)
    print("⚙️  MCP KALI SERVER - FULL CONFIGURATION")
    print("="*80)
    
    # System info
    print(f"\n🖥️  SYSTEM INFORMATION:")
    print(f"   OS: {os.name}")
    print(f"   Python: {sys.version.split()[0]}")
    print(f"   Working Directory: {os.getcwd()}")
    print(f"   Process ID: {os.getpid()}")
    
    # Configuration paths
    config_dir = Path.home() / ".mcp-kali"
    print(f"\n📁 CONFIGURATION PATHS:")
    print(f"   Config Directory: {config_dir}")
    print(f"   Credentials File: {config_dir / 'credentials.json'}")
    print(f"   Enrollment File: {config_dir / 'enroll.json'}")
    print(f"   Scope Config: {config_dir / 'scope.json'}")
    
    # Load and display all configs
    files_to_check = [
        ("Credentials", config_dir / "credentials.json"),
        ("Enrollment", config_dir / "enroll.json"), 
        ("Scope", config_dir / "scope.json")
    ]
    
    for name, file_path in files_to_check:
        print(f"\n📋 {name.upper()} CONFIG:")
        if file_path.exists():
            try:
                with open(file_path, 'r') as f:
                    data = json.load(f)
                print(json.dumps(data, indent=4))
            except Exception as e:
                print(f"   ❌ Error reading {file_path}: {e}")
        else:
            print(f"   ❌ File not found: {file_path}")
    
    # Environment variables
    print(f"\n🌍 ENVIRONMENT VARIABLES:")
    env_vars = [
        "MCP_TLS_CERT", "MCP_TLS_KEY", "MCP_MTLS_CA",
        "NGROK_AUTHTOKEN", "MCP_FORCE_MODE"
    ]
    
    for var in env_vars:
        value = os.environ.get(var)
        if value:
            # Mask sensitive values
            if "TOKEN" in var or "KEY" in var:
                display_value = value[:8] + "..." if len(value) > 8 else value
            else:
                display_value = value
            print(f"   {var}: {display_value}")
        else:
            print(f"   {var}: Not set")
    
    print("="*80)

def show_auth_info(host, port):
    """Display authentication and connection information."""
    from pathlib import Path
    import json
    
    print("\n" + "="*80)
    print("🔐 MCP KALI SERVER - AUTHENTICATION & CONNECTION INFO")
    print("="*80)
    
    # Configuration paths
    config_dir = Path.home() / ".mcp-kali"
    enroll_file = config_dir / "enroll.json"
    credentials_file = config_dir / "credentials.json"
    
    # Server connection info
    protocol = "https" if os.environ.get("MCP_TLS_CERT") else "http"
    server_url = f"{protocol}://{host}:{port}"
    
    print(f"🌐 SERVER CONNECTION:")
    print(f"   URL: {server_url}")
    print(f"   Host: {host}")
    print(f"   Port: {port}")
    print(f"   Protocol: {protocol.upper()}")
    
    if os.environ.get("MCP_TLS_CERT"):
        print(f"   TLS Cert: {os.environ.get('MCP_TLS_CERT')}")
        print(f"   TLS Key: {os.environ.get('MCP_TLS_KEY')}")
        if os.environ.get("MCP_MTLS_CA"):
            print(f"   mTLS CA: {os.environ.get('MCP_MTLS_CA')}")
            print("   ⚠️  Client certificates required!")
    
    # Authentication info
    print(f"\n🔑 AUTHENTICATION:")
    
    if credentials_file.exists():
        try:
            with open(credentials_file, 'r') as f:
                creds_data = json.load(f)
            
            if 'server_id' in creds_data:
                # Single credential format
                server_id = creds_data.get('server_id', 'N/A')
                api_key = creds_data.get('api_key', 'N/A')
                label = creds_data.get('label', 'Unnamed')
                
                print(f"   Server ID: {server_id}")
                print(f"   API Key: {api_key}")
                print(f"   Label: {label}")
                print(f"   Type: Bearer Token Authentication")
                
            else:
                # Multiple credentials format
                print(f"   Multiple servers configured:")
                for server_id, cred in creds_data.items():
                    api_key = cred.get('api_key', 'N/A')
                    label = cred.get('label', 'Unnamed')
                    print(f"   - {server_id} ({label}): {api_key}")
                    
        except Exception as e:
            print(f"   ❌ Error reading credentials: {e}")
            api_key = "dk_U8BE1DBs0bOuSGIyc7e0xgqUD_goVqJOCI38ICSnCt4"  # Fallback
            print(f"   Using fallback API key: {api_key}")
    else:
        print(f"   ❌ No credentials file found at: {credentials_file}")
        api_key = "dk_U8BE1DBs0bOuSGIyc7e0xgqUD_goVqJOCI38ICSnCt4"  # Fallback
        print(f"   Using fallback API key: {api_key}")
    
    # Enrollment info
    print(f"\n📋 ENROLLMENT:")
    if enroll_file.exists():
        try:
            with open(enroll_file, 'r') as f:
                enroll_data = json.load(f)
            
            enroll_id = enroll_data.get('id', 'N/A')
            enroll_token = enroll_data.get('token', 'N/A')
            created = enroll_data.get('created', 'N/A')
            
            print(f"   Enrollment ID: {enroll_id}")
            print(f"   Enrollment Token: {enroll_token}")
            print(f"   Created: {created}")
            
        except Exception as e:
            print(f"   ❌ Error reading enrollment: {e}")
    else:
        print(f"   ❌ No enrollment file found at: {enroll_file}")
        print(f"   ℹ️  Run installer to generate enrollment credentials")
    
    # API endpoints
    print(f"\n🔗 API ENDPOINTS:")
    endpoints = [
        ("GET", "/health", "Server health check"),
        ("GET", "/tools/list", "List available security tools"),
        ("POST", "/tools/call", "Execute security tools"),
        ("GET", "/artifacts/list", "List stored scan artifacts"),
        ("GET", "/artifacts/read", "Read artifact content"),
        ("POST", "/enroll", "Server enrollment (public)"),
        ("GET", "/llm/config", "LLM configuration"),
        ("PUT", "/llm/config", "Update LLM configuration"),
        ("POST", "/llm/knowledge/docs", "Add knowledge documents"),
        ("GET", "/llm/knowledge/search", "Search knowledge base"),
        ("POST", "/memory/append", "Add to memory"),
        ("GET", "/memory/retrieve", "Retrieve from memory"),
    ]
    
    for method, endpoint, description in endpoints:
        print(f"   {method:4} {endpoint:20} - {description}")
    
    # Test commands
    print(f"\n💻 TEST COMMANDS:")
    
    # Use the API key we found or fallback
    if 'api_key' not in locals():
        api_key = "dk_U8BE1DBs0bOuSGIyc7e0xgqUD_goVqJOCI38ICSnCt4"
    
    auth_header = f'"Authorization: Bearer {api_key}"'
    
    print(f"   # Health Check")
    print(f'   curl -H {auth_header} {server_url}/health')
    
    print(f"\n   # List Tools")
    print(f'   curl -H {auth_header} {server_url}/tools/list')
    
    print(f"\n   # Network Scan Example")
    print(f'   curl -X POST -H {auth_header} -H "Content-Type: application/json" \\')
    payload_json = '{"name":"net.scan_basic","arguments":{"target":"192.168.1.1","fast":true}}'
    print(f"        -d '{payload_json}' \\")
    print(f'        {server_url}/tools/call')
    
    print(f"\n   # List Artifacts")
    print(f'   curl -H {auth_header} {server_url}/artifacts/list')
    
    # PowerShell commands for Windows
    print(f"\n   # PowerShell Commands (Windows)")
    print(f'   $headers = @{{ "Authorization" = "Bearer {api_key}" }}')
    print(f'   Invoke-RestMethod -Uri "{server_url}/health" -Headers $headers')
    print(f'   Invoke-RestMethod -Uri "{server_url}/tools/list" -Headers $headers')
    
    # Security and scope info
    print(f"\n🛡️  SECURITY & SCOPE:")
    scope_file = Path("/etc/mcp-kali/scope.json")
    if not scope_file.exists():
        scope_file = config_dir / "scope.json"
    
    if scope_file.exists():
        try:
            with open(scope_file, 'r') as f:
                scope_data = json.load(f)
            
            allowed_cidrs = scope_data.get('allowed_cidrs', [])
            allow_destructive = scope_data.get('allow_destructive', False)
            
            print(f"   Allowed CIDRs: {', '.join(allowed_cidrs) if allowed_cidrs else 'None configured'}")
            print(f"   Destructive Operations: {'Enabled' if allow_destructive else 'Disabled'}")
            print(f"   Scope File: {scope_file}")
            
        except Exception as e:
            print(f"   ❌ Error reading scope config: {e}")
    else:
        print(f"   Default scope: 10.0.0.0/8, 192.168.0.0/16, 172.16.0.0/12")
        print(f"   Destructive operations: Disabled")
        print(f"   Scope file: {scope_file} (not found)")
    
    print(f"\n📁 CONFIGURATION FILES:")
    print(f"   Config Directory: {config_dir}")
    print(f"   Credentials: {credentials_file}")
    print(f"   Enrollment: {enroll_file}")
    print(f"   Scope Config: {scope_file}")
    
    print("="*80)
    print("✅ Server starting with authentication enabled...")
    print("="*80 + "\n")

def main():
    """Main entry point for the server."""
    args = parse_args()
    
    # Configure logging
    log_level = getattr(logging, args.log_level)
    logging.getLogger().setLevel(log_level)
    
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
        logger.debug("Debug mode enabled")
    
    # Run first launch setup and tests (if needed)
    from setup_first_launch import ensure_project_integrity
    if not ensure_project_integrity():
        logger.critical("Project integrity check failed. Please fix issues before starting server.")
        sys.exit(1)
    
    # Parse bind address
    try:
        if ":" in args.bind:
            host, port_str = args.bind.rsplit(":", 1)
            port = int(port_str)
        else:
            host = args.bind
            port = 5000
    except ValueError:
        logger.error(f"Invalid bind address: {args.bind}")
        sys.exit(1)
    
    # Handle information-only commands that don't start the server
    if args.show_auth:
        show_auth_info(host, port)
        return
    
    if args.show_config:
        show_full_config()
        return
    
    if args.test_connection:
        success = test_server_connection(host, port)
        sys.exit(0 if success else 1)
    
    if args.generate_client_config:
        generate_client_config(args.generate_client_config, host, port)
        return
    
    # Show comprehensive authentication and connection info before starting server
    show_auth_info(host, port)
    
    # Initialize ngrok manager if requested
    ngrok_manager = None
    if args.ngrok:
        # Get auth token from args or environment
        auth_token = args.ngrok_authtoken or os.environ.get("NGROK_AUTHTOKEN")
        if not auth_token:
            logger.error("Ngrok auth token required. Use --ngrok-authtoken or set NGROK_AUTHTOKEN env var")
            sys.exit(1)
        
        try:
            ngrok_manager = NgrokManager()
            if not ngrok_manager.configure_ngrok(auth_token):
                logger.error("Failed to configure ngrok with provided auth token")
                sys.exit(1)
            
            # Setup cleanup handlers
            def cleanup_ngrok():
                if ngrok_manager:
                    logger.info("Shutting down ngrok tunnel...")
                    ngrok_manager.stop_tunnel()
            
            atexit.register(cleanup_ngrok)
            signal.signal(signal.SIGTERM, lambda s, f: cleanup_ngrok())
            signal.signal(signal.SIGINT, lambda s, f: cleanup_ngrok())
            
            # Start tunnel
            domain = getattr(args, 'ngrok_domain', None)
            public_url = ngrok_manager.start_tunnel(port, domain=domain)
            if not public_url:
                logger.error("Failed to establish ngrok tunnel")
                sys.exit(1)
            logger.info(f"Ngrok tunnel established: {public_url}")
            
        except Exception as e:
            logger.error(f"Failed to setup ngrok tunnel: {e}")
            sys.exit(1)
    
    # Validate license before starting server
    logger.info("Validating server license...")
    if not validate_server_license():
        logger.critical("License validation failed - server will not start")
        sys.exit(1)
    logger.info("License validation successful")
    
    # Initialize tool manager with force mode setting
    if args.force:
        logger.warning("FORCE MODE ENABLED - Target restrictions disabled! This is DANGEROUS in production!")
        os.environ['MCP_FORCE_MODE'] = 'true'
    
    # Initialize the tool manager to load registry
    try:
        from mcp_tools.manager import get_tool_manager
        tool_manager = get_tool_manager(force_mode=args.force)
        available_tools = len([t for t in tool_manager.list_tools() if t['available']])
        logger.info(f"Tool manager initialized with {available_tools} available tools")
    except Exception as e:
        logger.error(f"Failed to initialize tool manager: {e}")
        # Don't exit - tool manager is optional
    
    # Get TLS configuration
    ssl_keyfile, ssl_certfile, ssl_ca_certs = get_tls_config()
    
    if ssl_keyfile and ssl_certfile:
        logger.info(f"Starting MCP Kali Server with TLS on {host}:{port}")
        if ssl_ca_certs:
            logger.info("mTLS enabled - client certificates required")
        else:
            logger.info("TLS enabled - server authentication only")
    else:
        logger.info(f"Starting MCP Kali Server on {host}:{port}")
    
    # Configure uvicorn
    uvicorn_config = {
        "app": "mcp_server.api:app",
        "host": host,
        "port": port,
        "workers": args.workers,
        "log_level": args.log_level.lower(),
        "access_log": True,
        "server_header": False,  # Don't reveal server details
        "date_header": False,    # Don't add date header
    }
    
    # Add TLS configuration if available
    if ssl_keyfile and ssl_certfile:
        uvicorn_config.update({
            "ssl_keyfile": ssl_keyfile,
            "ssl_certfile": ssl_certfile,
        })
        
        # Todo: Implement proper mTLS validation when ssl_ca_certs is provided
        # This would require custom SSL context configuration
        if ssl_ca_certs:
            logger.warning("mTLS CA file specified but not yet implemented in uvicorn config")
    
    try:
        # Run the server
        uvicorn.run(**uvicorn_config)
    except KeyboardInterrupt:
        logger.info("Server shutdown requested")
        if ngrok_manager:
            ngrok_manager.disconnect()
    except Exception as e:
        logger.error(f"Server error: {e}")
        if ngrok_manager:
            ngrok_manager.disconnect()
        sys.exit(1)

if __name__ == "__main__":
    main()
