#!/usr/bin/env python3
"""
MCP Kali Server with detailed logging and monitoring (Windows-compatible).
"""

import uvicorn
from mcp_server.api import app
import logging
import sys
from datetime import datetime

def start_server_with_monitoring():
    """Start the MCP server with comprehensive logging and monitoring."""
    
    # Configure comprehensive logging
    logging.basicConfig(
        level=logging.DEBUG,
        format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
        handlers=[logging.StreamHandler(sys.stdout)]
    )

    # Set specific logger levels for cleaner output
    logging.getLogger('uvicorn').setLevel(logging.INFO)
    logging.getLogger('uvicorn.access').setLevel(logging.INFO) 
    logging.getLogger('fastapi').setLevel(logging.INFO)
    logging.getLogger('mcp_server').setLevel(logging.DEBUG)

    print('MCP Kali Server - DETAILED MONITORING')
    print('=' * 60)
    print(f'Server URL: http://127.0.0.1:5001')
    print(f'API Key: dk_U8BE1DBs0bOuSGIyc7e0xgqUD_goVqJOCI38ICSnCt4')
    print(f'Started: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}')
    print(f'Log Level: DEBUG (All operations will be logged)')
    print(f'Monitoring: Access logs, API calls, errors, and performance')
    print('=' * 60)
    print()

    print('Available Endpoints:')
    print('   * GET  /health          - Server health check')
    print('   * GET  /tools/list      - List available tools')
    print('   * POST /tools/call      - Execute security tools')
    print('   * GET  /artifacts/list  - List stored artifacts')
    print('   * GET  /artifacts/read  - Read artifact content')
    print('   * POST /enroll          - Server enrollment')
    print()

    print('LIVE MONITORING - Press Ctrl+C to stop')
    print('=' * 60)

    # Start the server
    try:
        uvicorn.run(
            app,
            host="127.0.0.1",
            port=5001,
            log_level="info",
            access_log=True,
            reload=False
        )
    except KeyboardInterrupt:
        print("\nServer stopped by user.")
    except Exception as e:
        print(f"Server error: {e}")

if __name__ == "__main__":
    start_server_with_monitoring()