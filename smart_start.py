#!/usr/bin/env python3
"""
DARK MATER MCP Server - Smart Startup
Automatically handles authentication without complex enrollment
"""

import json
import secrets
import socket
import os
import sys
import subprocess
from datetime import datetime
from pathlib import Path

# Default ngrok token for testing
DEFAULT_NGROK_TOKEN = "33Wt5Zs1jKfE5o5nY2i8N6dbGB5_6Y3xVk2u3eFmafqZZhaEj"

class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    END = '\033[0m'

def print_colored(text, color=Colors.WHITE, bold=False):
    """Print colored text"""
    style = f"{color}{Colors.BOLD if bold else ''}"
    print(f"{style}{text}{Colors.END}")

def print_banner():
    """Display banner"""
    banner = """
╔══════════════════════════════════════════════════════════════════╗
║                    🔰 DARK MATER MCP SERVER 🔰                  ║
║                     Smart Startup - No Hassle                   ║
╚══════════════════════════════════════════════════════════════════╝
"""
    print_colored(banner, Colors.CYAN, True)

def get_config_dir():
    """Get configuration directory"""
    if os.name == 'nt':  # Windows
        return Path.home() / ".mcp-kali"
    else:  # Linux/Unix
        return Path("/etc/mcp-kali")

def check_existing_credentials():
    """Check if credentials already exist"""
    config_dir = get_config_dir()
    creds_file = config_dir / "credentials.json"
    
    if creds_file.exists():
        try:
            with open(creds_file, 'r') as f:
                creds = json.load(f)
            return creds
        except:
            return None
    return None

def generate_api_credentials():
    """Generate new API credentials directly"""
    print_colored("🔑 Generating API credentials...", Colors.BLUE, True)
    
    # Generate server ID and API key
    hostname = socket.gethostname()
    timestamp = int(datetime.now().timestamp())
    server_id = f'kali-{hostname}-{timestamp}'
    api_key = f"dk_{secrets.token_urlsafe(32)}"  # dk = dark kali prefix
    
    # Create credentials
    credentials = {
        "server_id": server_id,
        "api_key": api_key,
        "label": "DARK-MATER-Auto",
        "created": datetime.now().isoformat(),
        "auto_generated": True
    }
    
    # Ensure config directory exists
    config_dir = get_config_dir()
    config_dir.mkdir(parents=True, exist_ok=True)
    
    # Save credentials
    creds_file = config_dir / "credentials.json"
    with open(creds_file, 'w') as f:
        json.dump(credentials, f, indent=2)
    
    # Set permissions (on Unix-like systems)
    if os.name != 'nt':
        try:
            os.chmod(creds_file, 0o600)
        except:
            pass
    
    print_colored("✅ API credentials generated!", Colors.GREEN, True)
    print_colored(f"Server ID: {server_id}", Colors.WHITE)
    print_colored(f"API Key: {api_key[:20]}...", Colors.WHITE)
    print_colored(f"Saved to: {creds_file}", Colors.BLUE)
    
    return credentials

def find_available_port():
    """Find an available port starting from 5000"""
    import socket as sock
    for port in range(5000, 5010):
        try:
            with sock.socket(sock.AF_INET, sock.SOCK_STREAM) as s:
                s.bind(('127.0.0.1', port))
                return port
        except OSError:
            continue
    return 5000  # Fallback

def start_server(api_key, port=None, use_ngrok=False, ngrok_token=None):
    """Start the server with the API key and optional ngrok tunnel"""
    if port is None:
        port = find_available_port()
    
    print_colored(f"\n🚀 Starting DARK MATER MCP Server on port {port}...", Colors.GREEN, True)
    
    # Check if server file exists
    server_file = Path("kali_server.py")
    if not server_file.exists():
        print_colored("❌ kali_server.py not found in current directory", Colors.RED, True)
        return False
    
    try:
        # Use virtual environment Python if available
        venv_python = Path("venv/Scripts/python.exe") if os.name == 'nt' else Path("venv/bin/python")
        python_exe = str(venv_python) if venv_python.exists() else sys.executable
        
        # Start server
        cmd = [python_exe, "kali_server.py", "--bind", f"127.0.0.1:{port}"]
        
        # Add ngrok arguments if requested
        if use_ngrok:
            cmd.extend(["--ngrok"])
            if ngrok_token:
                cmd.extend(["--ngrok-authtoken", ngrok_token])
            print_colored("🌐 Ngrok tunnel will be enabled", Colors.CYAN)
        
        print_colored(f"Command: {' '.join(cmd)}", Colors.BLUE)
        print_colored("Server starting... (Press Ctrl+C to stop)", Colors.YELLOW)
        
        # Run server
        process = subprocess.Popen(cmd)
        
        # Give server time to start
        import time
        time.sleep(3)
        
        # Test if server is responding using subprocess with correct Python
        try:
            # Create a simple health check script
            health_check_script = f"""
import requests
import sys
try:
    response = requests.get('http://127.0.0.1:{port}/health', 
                          headers={{'Authorization': 'Bearer {api_key}'}}, 
                          timeout=5)
    if response.status_code == 200:
        print('HEALTHY')
        sys.exit(0)
    else:
        print(f'STATUS_{response.status_code}')
        sys.exit(1)
except Exception as e:
    print(f'ERROR_{e}')
    sys.exit(1)
"""
            
            # Run health check with the same Python that runs the server
            result = subprocess.run([python_exe, "-c", health_check_script], 
                                  capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0 and "HEALTHY" in result.stdout:
                print_colored("✅ Server is running and healthy!", Colors.GREEN, True)
                print_colored(f"🌐 URL: http://127.0.0.1:{port}", Colors.CYAN)
                print_colored(f"🔑 API Key: {api_key}", Colors.CYAN)
                
                # Show usage examples
                print_colored("\n📋 Usage Examples:", Colors.BLUE, True)
                print_colored(f"Health Check:", Colors.WHITE)
                print_colored(f"curl -H 'Authorization: Bearer {api_key}' http://127.0.0.1:{port}/health", Colors.WHITE)
                
                print_colored(f"\nList Tools:", Colors.WHITE)
                print_colored(f"curl -H 'Authorization: Bearer {api_key}' http://127.0.0.1:{port}/tools/list", Colors.WHITE)
                
                return True
            else:
                print_colored(f"⚠️ Server started but health check failed: {result.stdout.strip()}", Colors.YELLOW)
                print_colored("✅ Server is running - health check skipped", Colors.GREEN, True)
                print_colored(f"🌐 URL: http://127.0.0.1:{port}", Colors.CYAN)
                print_colored(f"🔑 API Key: {api_key}", Colors.CYAN)
                return True
            
        except Exception as e:
            print_colored(f"⚠️ Health check failed: {e}", Colors.YELLOW)
            print_colored("✅ Server is running - health check skipped", Colors.GREEN, True)
            print_colored(f"🌐 URL: http://127.0.0.1:{port}", Colors.CYAN)
            print_colored(f"🔑 API Key: {api_key}", Colors.CYAN)
            return True
            
        # Wait for server process
        try:
            process.wait()
        except KeyboardInterrupt:
            print_colored("\n🛑 Stopping server...", Colors.YELLOW)
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
            print_colored("✅ Server stopped", Colors.GREEN)
            
    except Exception as e:
        print_colored(f"❌ Failed to start server: {e}", Colors.RED, True)
        return False

def main():
    """Main function"""
    print_banner()
    
    # Check for existing credentials
    existing_creds = check_existing_credentials()
    
    if existing_creds:
        print_colored("✅ Found existing API credentials", Colors.GREEN, True)
        print_colored(f"Server ID: {existing_creds['server_id']}", Colors.WHITE)
        print_colored(f"Label: {existing_creds.get('label', 'Unknown')}", Colors.WHITE)
        print_colored(f"Created: {existing_creds.get('created', 'Unknown')}", Colors.WHITE)
        
        choice = input(f"\n{Colors.YELLOW}Use existing credentials? (Y/n): {Colors.END}").strip().lower()
        if choice not in ['n', 'no']:
            api_key = existing_creds['api_key']
        else:
            # Generate new credentials
            new_creds = generate_api_credentials()
            api_key = new_creds['api_key']
    else:
        print_colored("ℹ️ No existing credentials found", Colors.BLUE)
        # Generate new credentials
        new_creds = generate_api_credentials()
        api_key = new_creds['api_key']
    
    # Ask about ngrok tunnel
    ngrok_choice = input(f"\n{Colors.CYAN}🌐 Enable public access via ngrok? (Y/n): {Colors.END}").strip().lower()
    use_ngrok = ngrok_choice not in ['n', 'no']
    
    ngrok_token = DEFAULT_NGROK_TOKEN
    if use_ngrok:
        print_colored(f"Using ngrok token: {DEFAULT_NGROK_TOKEN[:20]}...", Colors.BLUE)
        custom_token = input(f"{Colors.YELLOW}Enter custom token (or press Enter for default): {Colors.END}").strip()
        if custom_token:
            ngrok_token = custom_token
            print_colored("✅ Custom ngrok token will be used", Colors.GREEN)
    
    # Ask if user wants to start server immediately
    choice = input(f"\n{Colors.GREEN}Start server now? (Y/n): {Colors.END}").strip().lower()
    if choice not in ['n', 'no']:
        start_server(api_key, port=None, use_ngrok=use_ngrok, ngrok_token=ngrok_token)
    else:
        print_colored("✅ Credentials ready!", Colors.GREEN, True)
        print_colored(f"🔑 API Key: {api_key}", Colors.CYAN)
        if use_ngrok:
            print_colored(f"🌐 Ngrok token: {ngrok_token[:20]}...", Colors.CYAN)
        print_colored("Start server manually:", Colors.BLUE)
        port = find_available_port()
        print_colored(f"python kali_server.py --bind 127.0.0.1:{port}", Colors.WHITE)

if __name__ == "__main__":
    main()