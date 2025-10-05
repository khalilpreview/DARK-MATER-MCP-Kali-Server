#!/usr/bin/env python3
"""
Server Log Monitor - Real-time log monitoring for DARK MATER MCP Server
"""

import time
import os
from pathlib import Path

def monitor_logs():
    log_file = Path("server.log")
    error_log_file = Path("server_error.log")
    
    print("🔍 DARK MATER MCP Server - Log Monitor")
    print("=" * 50)
    print(f"📊 Server Status: Running on http://0.0.0.0:5001")
    print(f"🔑 API Key: dk_U8BE1DBs0bOuSGIyc7e0xgqUD_goVqJOCI38ICSnCt4")
    print("=" * 50)
    
    # Show recent logs
    if log_file.exists():
        print("\n📋 Recent Server Logs:")
        with open(log_file, 'r') as f:
            lines = f.readlines()
            for line in lines[-10:]:
                print(f"  {line.strip()}")
    
    if error_log_file.exists():
        print("\n⚠️  Error Logs:")
        with open(error_log_file, 'r') as f:
            lines = f.readlines()
            for line in lines[-5:]:
                print(f"  {line.strip()}")
    
    print(f"\n👁️  Monitoring for new requests... (Press Ctrl+C to stop)")
    print("-" * 50)
    
    # Monitor for new logs
    if log_file.exists():
        # Get current file size
        last_size = log_file.stat().st_size
        
        try:
            while True:
                current_size = log_file.stat().st_size
                if current_size > last_size:
                    # New content added
                    with open(log_file, 'r') as f:
                        f.seek(last_size)
                        new_content = f.read()
                        if new_content.strip():
                            print(f"📡 {new_content.strip()}")
                    last_size = current_size
                
                time.sleep(0.5)  # Check every 500ms
                
        except KeyboardInterrupt:
            print("\n👋 Log monitoring stopped")

if __name__ == "__main__":
    monitor_logs()