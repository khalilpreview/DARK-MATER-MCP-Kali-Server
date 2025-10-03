#!/usr/bin/env python3
"""
DARK MATER MCP Kali Server - Enhanced CLI Management Tool
Production-ready security testing platform management interface
"""

import os
import sys
import json
import time
import socket
import subprocess
import requests
from pathlib import Path
from datetime import datetime
from typing import Optional, Dict, Any

# Default ngrok token
DEFAULT_NGROK_TOKEN = "33Wt5Zs1jKfE5o5nY2i8N6dbGB5_6Y3xVk2u3eFmafqZZhaEj"

class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    END = '\033[0m'

def print_colored(text, color=Colors.WHITE, bold=False):
    """Print colored text"""
    style = f"{color}{Colors.BOLD if bold else ''}"
    print(f"{style}{text}{Colors.END}")

def show_banner():
    """Display the DARK MATER banner."""
    print_colored("""
╔══════════════════════════════════════════════════════════════════╗
║ ██████╗  █████╗ ██████╗ ██╗  ██╗    ███╗   ███╗ █████╗ ████████╗║
║ ██╔══██╗██╔══██╗██╔══██╗██║ ██╔╝    ████╗ ████║██╔══██╗╚══██╔══╝║
║ ██║  ██║███████║██████╔╝█████╔╝     ██╔████╔██║███████║   ██║   ║
║ ██║  ██║██╔══██║██╔══██╗██╔═██╗     ██║╚██╔╝██║██╔══██║   ██║   ║
║ ██████╔╝██║  ██║██║  ██║██║  ██╗    ██║ ╚═╝ ██║██║  ██║   ██║   ║
║ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝    ╚═╝     ╚═╝╚═╝  ╚═╝   ╚═╝   ║
║                                                                  ║
║                    🔰 MCP KALI SERVER v2.0 🔰                   ║
║                 Production Security Testing Platform             ║
║                      Enhanced CLI Management                     ║
╚══════════════════════════════════════════════════════════════════╝
    """, Colors.PURPLE)

def get_config_dir() -> Path:
    """Get the appropriate config directory for the platform."""
    if os.name == 'nt':  # Windows
        return Path.home() / ".mcp-kali"
    else:  # Linux/Unix
        return Path("/etc/mcp-kali")

def get_server_process():
    """Find the server process if running."""
    try:
        if os.name == 'nt':  # Windows
            result = subprocess.run([
                "powershell", "-Command", 
                "Get-Process | Where-Object {$_.ProcessName -eq 'python' -and $_.CommandLine -like '*kali_server*'} | Select-Object Id, ProcessName"
            ], capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0 and result.stdout.strip():
                lines = result.stdout.strip().split('\n')[2:]  # Skip header
                for line in lines:
                    if line.strip():
                        parts = line.split()
                        if len(parts) >= 2:
                            return int(parts[0])
        else:  # Linux
            result = subprocess.run([
                "pgrep", "-f", "kali_server.py"
            ], capture_output=True, text=True)
            
            if result.returncode == 0 and result.stdout.strip():
                return int(result.stdout.strip().split()[0])
                
    except Exception as e:
        print_colored(f"Error finding server process: {e}", Colors.YELLOW)
    
    return None

def get_server_port() -> Optional[int]:
    """Get the port the server is running on."""
    try:
        if os.name == 'nt':  # Windows
            result = subprocess.run([
                "netstat", "-ano"
            ], capture_output=True, text=True)
            
            for line in result.stdout.split('\n'):
                if 'LISTENING' in line and '127.0.0.1:50' in line:
                    parts = line.split()
                    addr = parts[1]
                    port = int(addr.split(':')[1])
                    if 5000 <= port <= 5010:
                        return port
        else:  # Linux
            result = subprocess.run([
                "netstat", "-tlnp"
            ], capture_output=True, text=True)
            
            for line in result.stdout.split('\n'):
                if '127.0.0.1:50' in line and 'LISTEN' in line:
                    parts = line.split()
                    addr = parts[3]
                    port = int(addr.split(':')[1])
                    if 5000 <= port <= 5010:
                        return port
                        
    except Exception:
        pass
    
    return None

def is_server_running() -> bool:
    """Check if the server is running."""
    return get_server_process() is not None

def load_credentials() -> Optional[Dict[str, Any]]:
    """Load API credentials."""
    config_dir = get_config_dir()
    creds_file = config_dir / "credentials.json"
    
    if creds_file.exists():
        try:
            with open(creds_file) as f:
                return json.load(f)
        except Exception as e:
            print_colored(f"Error loading credentials: {e}", Colors.RED)
    
    return None

def check_server_status():
    """Check comprehensive server status."""
    print_colored("🔍 Checking server status...", Colors.CYAN, True)
    print("=" * 50)
    
    # Process check
    pid = get_server_process()
    if pid:
        print_colored(f"✅ Server process running (PID: {pid})", Colors.GREEN)
    else:
        print_colored("❌ Server process not running", Colors.RED)
        return False
    
    # Port check
    port = get_server_port()
    if port:
        print_colored(f"✅ Server listening on port {port}", Colors.GREEN)
    else:
        print_colored("❌ Server port not detected", Colors.RED)
        return False
    
    # Configuration check
    config_dir = get_config_dir()
    if (config_dir / "credentials.json").exists():
        print_colored("✅ API credentials found", Colors.GREEN)
    else:
        print_colored("⚠️  No API credentials found", Colors.YELLOW)
    
    # Ngrok status
    check_ngrok_status()
    
    print("=" * 50)
    return True

def check_ngrok_status():
    """Check ngrok tunnel status."""
    try:
        # Check if ngrok process is running
        if os.name == 'nt':  # Windows
            result = subprocess.run([
                "powershell", "-Command", 
                "Get-Process | Where-Object {$_.ProcessName -eq 'ngrok'}"
            ], capture_output=True, text=True, timeout=5)
            ngrok_running = result.returncode == 0 and result.stdout.strip()
        else:  # Linux
            result = subprocess.run([
                "pgrep", "-f", "ngrok"
            ], capture_output=True, text=True)
            ngrok_running = result.returncode == 0 and result.stdout.strip()
        
        if ngrok_running:
            # Try to get tunnel info
            try:
                response = requests.get("http://127.0.0.1:4040/api/tunnels", timeout=3)
                if response.status_code == 200:
                    tunnels = response.json().get("tunnels", [])
                    for tunnel in tunnels:
                        if tunnel.get("proto") == "https":
                            public_url = tunnel.get("public_url", "")
                            print_colored(f"🌐 Ngrok tunnel active: {public_url}", Colors.GREEN)
                            return
                            
                print_colored("🌐 Ngrok process running but no tunnel found", Colors.YELLOW)
            except Exception:
                print_colored("🌐 Ngrok process running (status unknown)", Colors.YELLOW)
        else:
            print_colored("🌐 Ngrok tunnel not running", Colors.RED)
            
    except Exception as e:
        print_colored(f"🌐 Error checking ngrok status: {e}", Colors.YELLOW)

def test_server_health():
    """Test server health with detailed checks."""
    print_colored("🧪 Testing server health...", Colors.CYAN, True)
    
    port = get_server_port()
    if not port:
        print_colored("❌ Server is not running", Colors.RED)
        return False
    
    # Basic connectivity test
    try:
        response = requests.get(f"http://127.0.0.1:{port}/health", timeout=5)
        if response.status_code == 200:
            print_colored("✅ Server is responding", Colors.GREEN)
        else:
            print_colored(f"⚠️  Server responded but with status {response.status_code}", Colors.YELLOW)
    except Exception as e:
        print_colored(f"❌ Server is not responding: {e}", Colors.RED)
        return False
    
    # Authenticated test
    creds = load_credentials()
    if creds:
        api_key = creds.get("api_key", "") if isinstance(creds, dict) else ""
        if api_key:
            try:
                response = requests.get(
                    f"http://127.0.0.1:{port}/health",
                    headers={"Authorization": f"Bearer {api_key}"},
                    timeout=5
                )
                
                if response.status_code == 200:
                    health_data = response.json()
                    print_colored("✅ Authenticated health check passed", Colors.GREEN)
                    print_colored(f"Server ID: {health_data.get('server_id', 'Unknown')}", Colors.WHITE)
                    print_colored(f"Version: {health_data.get('version', 'Unknown')}", Colors.WHITE)
                    print_colored(f"Capabilities: {', '.join(health_data.get('caps', {}).keys())}", Colors.WHITE)
                else:
                    print_colored(f"❌ Authentication failed: {response.status_code}", Colors.RED)
                    
            except Exception as e:
                print_colored(f"❌ Authenticated test failed: {e}", Colors.RED)
    
    return True

def start_server_enhanced():
    """Start server with enhanced options."""
    print_colored("🚀 Starting DARK MATER MCP Server...", Colors.GREEN, True)
    
    if is_server_running():
        print_colored("⚠️  Server is already running", Colors.YELLOW)
        return
    
    # Ask about ngrok
    ngrok_choice = input(f"{Colors.CYAN}🌐 Enable ngrok tunnel? [Y/n]: {Colors.END}").strip().lower()
    use_ngrok = ngrok_choice not in ['n', 'no']
    
    ngrok_token = DEFAULT_NGROK_TOKEN
    if use_ngrok:
        print_colored(f"Default token: {DEFAULT_NGROK_TOKEN[:20]}...", Colors.BLUE)
        custom_token = input(f"{Colors.YELLOW}Custom token (or Enter for default): {Colors.END}").strip()
        if custom_token:
            ngrok_token = custom_token
    
    # Build command
    cmd = [sys.executable, "kali_server.py", "--bind", "0.0.0.0:5000"]
    if use_ngrok:
        cmd.extend(["--ngrok", "--ngrok-authtoken", ngrok_token])
    
    print_colored(f"Command: {' '.join(cmd[:3])}{'...' if len(cmd) > 3 else ''}", Colors.BLUE)
    
    try:
        # Start server
        if os.name == 'nt':  # Windows
            subprocess.Popen(cmd, creationflags=subprocess.CREATE_NEW_CONSOLE)
        else:  # Linux
            subprocess.Popen(cmd, start_new_session=True)
        
        print_colored("✅ Server startup initiated", Colors.GREEN)
        print_colored("⏳ Waiting for server to start...", Colors.BLUE)
        
        # Wait and check
        for i in range(10):
            time.sleep(2)
            if is_server_running():
                print_colored("✅ Server started successfully!", Colors.GREEN, True)
                time.sleep(2)
                check_server_status()
                return
        
        print_colored("⚠️  Server may be starting (check manually)", Colors.YELLOW)
        
    except Exception as e:
        print_colored(f"❌ Failed to start server: {e}", Colors.RED)

def stop_server():
    """Stop the server."""
    print_colored("🛑 Stopping server...", Colors.YELLOW, True)
    
    pid = get_server_process()
    if not pid:
        print_colored("⚠️  Server is not running", Colors.YELLOW)
        return
    
    try:
        if os.name == 'nt':  # Windows
            subprocess.run(["taskkill", "/F", "/PID", str(pid)], check=True)
        else:  # Linux
            subprocess.run(["kill", str(pid)], check=True)
        
        time.sleep(2)
        
        if not is_server_running():
            print_colored("✅ Server stopped successfully", Colors.GREEN)
        else:
            print_colored("⚠️  Server may still be running", Colors.YELLOW)
            
    except Exception as e:
        print_colored(f"❌ Error stopping server: {e}", Colors.RED)

def view_logs():
    """View server logs."""
    print_colored("📋 Server Logs", Colors.CYAN, True)
    
    config_dir = get_config_dir()
    log_file = config_dir / "server.log"
    
    if not log_file.exists():
        print_colored("❌ Log file not found", Colors.RED)
        print_colored(f"Expected location: {log_file}", Colors.YELLOW)
        return
    
    print_colored(f"Log file: {log_file}", Colors.BLUE)
    print("=" * 50)
    
    try:
        with open(log_file, 'r') as f:
            lines = f.readlines()
            # Show last 50 lines
            for line in lines[-50:]:
                line = line.strip()
                if 'ERROR' in line:
                    print_colored(line, Colors.RED)
                elif 'WARNING' in line:
                    print_colored(line, Colors.YELLOW)
                elif 'INFO' in line:
                    print_colored(line, Colors.GREEN)
                else:
                    print(line)
                    
    except Exception as e:
        print_colored(f"❌ Error reading log file: {e}", Colors.RED)

def manage_ngrok():
    """Manage ngrok tunnel."""
    while True:
        print_colored("\n🌐 Ngrok Manager", Colors.PURPLE, True)
        print("=" * 30)
        print("1. 📊 Show Status")
        print("2. 🚀 Start Tunnel")
        print("3. 🛑 Stop Tunnel")
        print("4. 🔧 Configure Token")
        print("5. ← Back")
        
        choice = input(f"\n{Colors.CYAN}Select option (1-5): {Colors.END}").strip()
        
        if choice == '1':
            check_ngrok_status()
        elif choice == '2':
            start_ngrok_tunnel()
        elif choice == '3':
            stop_ngrok_tunnel()
        elif choice == '4':
            configure_ngrok_token()
        elif choice == '5':
            break
        else:
            print_colored("❌ Invalid option", Colors.RED)
        
        input(f"\n{Colors.BLUE}Press Enter to continue...{Colors.END}")

def start_ngrok_tunnel():
    """Start ngrok tunnel."""
    print_colored("🚀 Starting ngrok tunnel...", Colors.CYAN)
    
    port = get_server_port() or 5000
    
    # Configure token
    token = input(f"{Colors.YELLOW}Ngrok token (Enter for default): {Colors.END}").strip()
    if not token:
        token = DEFAULT_NGROK_TOKEN
    
    try:
        # Configure token
        subprocess.run(["ngrok", "config", "add-authtoken", token], check=True)
        print_colored("✅ Token configured", Colors.GREEN)
        
        # Start tunnel
        if os.name == 'nt':  # Windows
            subprocess.Popen(["ngrok", "http", str(port)], creationflags=subprocess.CREATE_NEW_CONSOLE)
        else:  # Linux
            subprocess.Popen(["ngrok", "http", str(port)], start_new_session=True)
        
        print_colored("✅ Ngrok tunnel starting...", Colors.GREEN)
        time.sleep(3)
        check_ngrok_status()
        
    except FileNotFoundError:
        print_colored("❌ Ngrok not found. Please install ngrok first.", Colors.RED)
    except Exception as e:
        print_colored(f"❌ Error starting tunnel: {e}", Colors.RED)

def stop_ngrok_tunnel():
    """Stop ngrok tunnel."""
    print_colored("🛑 Stopping ngrok tunnel...", Colors.YELLOW)
    
    try:
        if os.name == 'nt':  # Windows
            subprocess.run(["taskkill", "/F", "/IM", "ngrok.exe"], check=True)
        else:  # Linux
            subprocess.run(["pkill", "-f", "ngrok"], check=True)
        
        print_colored("✅ Ngrok tunnel stopped", Colors.GREEN)
        
    except Exception as e:
        print_colored(f"❌ Error stopping tunnel: {e}", Colors.RED)

def configure_ngrok_token():
    """Configure ngrok authentication token."""
    print_colored("🔧 Configure Ngrok Token", Colors.CYAN, True)
    
    print_colored(f"Current default: {DEFAULT_NGROK_TOKEN[:20]}...", Colors.BLUE)
    token = input(f"{Colors.YELLOW}Enter new token: {Colors.END}").strip()
    
    if token:
        try:
            subprocess.run(["ngrok", "config", "add-authtoken", token], check=True)
            print_colored("✅ Token configured successfully", Colors.GREEN)
        except Exception as e:
            print_colored(f"❌ Error configuring token: {e}", Colors.RED)
    else:
        print_colored("❌ No token provided", Colors.RED)

def main_menu():
    """Display main menu."""
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        show_banner()
        
        print_colored("🎛️  DARK MATER Control Panel", Colors.WHITE, True)
        print("=" * 40)
        print("1. 📊 Server Status")
        print("2. 🚀 Start Server")
        print("3. 🛑 Stop Server")
        print("4. 🧪 Test Health")
        print("5. 📋 View Logs")
        print("6. 🌐 Ngrok Manager")
        print("7. 🔄 Restart Server")
        print("8. ⚙️  Show Config")
        print("9. ❌ Exit")
        
        choice = input(f"\n{Colors.CYAN}Select option (1-9): {Colors.END}").strip()
        
        if choice == '1':
            check_server_status()
        elif choice == '2':
            start_server_enhanced()
        elif choice == '3':
            stop_server()
        elif choice == '4':
            test_server_health()
        elif choice == '5':
            view_logs()
        elif choice == '6':
            manage_ngrok()
        elif choice == '7':
            stop_server()
            time.sleep(2)
            start_server_enhanced()
        elif choice == '8':
            show_config()
        elif choice == '9':
            print_colored("👋 Goodbye!", Colors.CYAN)
            break
        else:
            print_colored("❌ Invalid option", Colors.RED)
        
        if choice != '9':
            input(f"\n{Colors.BLUE}Press Enter to continue...{Colors.END}")

def show_config():
    """Show current configuration."""
    print_colored("⚙️  Current Configuration", Colors.CYAN, True)
    print("=" * 30)
    
    config_dir = get_config_dir()
    print_colored(f"Config Directory: {config_dir}", Colors.WHITE)
    
    # Check credentials
    creds_file = config_dir / "credentials.json"
    if creds_file.exists():
        print_colored("✅ Credentials file exists", Colors.GREEN)
        try:
            creds = load_credentials()
            if creds:
                server_id = creds.get("server_id", "Unknown") if isinstance(creds, dict) else "Unknown" 
                print_colored(f"Server ID: {server_id}", Colors.WHITE)
        except Exception as e:
            print_colored(f"❌ Error reading credentials: {e}", Colors.RED)
    else:
        print_colored("❌ No credentials file", Colors.RED)
    
    # Check server status
    if is_server_running():
        port = get_server_port()
        print_colored(f"✅ Server running on port {port}", Colors.GREEN)
    else:
        print_colored("❌ Server not running", Colors.RED)
    
    # Ngrok status
    print_colored(f"Ngrok Token: {DEFAULT_NGROK_TOKEN[:20]}...", Colors.BLUE)

if __name__ == "__main__":
    if len(sys.argv) > 1:
        # Command line mode
        command = sys.argv[1].lower()
        if command == "status":
            check_server_status()
        elif command == "start":
            start_server_enhanced()
        elif command == "stop":
            stop_server()
        elif command == "health":
            test_server_health()
        else:
            print_colored(f"Unknown command: {command}", Colors.RED)
    else:
        # Interactive mode
        main_menu()