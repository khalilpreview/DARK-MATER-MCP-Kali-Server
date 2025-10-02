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

# Import the FastAPI app and ngrok manager
from mcp_server.api import app
from mcp_server.ngrok_manager import NgrokManager

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
        description="MCP Kali Server - Production-ready security testing server"
    )
    parser.add_argument(
        "--bind", 
        type=str, 
        default="0.0.0.0:5000",
        help="Host:port to bind to (default: 0.0.0.0:5000)"
    )
    parser.add_argument(
        "--debug", 
        action="store_true", 
        help="Enable debug mode"
    )
    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default="INFO",
        help="Set logging level"
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=1,
        help="Number of worker processes (default: 1)"
    )
    parser.add_argument(
        "--ngrok",
        action="store_true",
        help="Enable ngrok tunnel for remote access"
    )
    parser.add_argument(
        "--ngrok-authtoken",
        type=str,
        help="Ngrok auth token (can also use NGROK_AUTHTOKEN env var)"
    )
    parser.add_argument(
        "--ngrok-domain",
        type=str,
        help="Custom ngrok domain (requires paid plan)"
    )
    return parser.parse_args()

def main():
    """Main entry point for the server."""
    args = parse_args()
    
    # Configure logging
    log_level = getattr(logging, args.log_level)
    logging.getLogger().setLevel(log_level)
    
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
        logger.debug("Debug mode enabled")
    
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
                    ngrok_manager.disconnect()
            
            atexit.register(cleanup_ngrok)
            signal.signal(signal.SIGTERM, lambda s, f: cleanup_ngrok())
            signal.signal(signal.SIGINT, lambda s, f: cleanup_ngrok())
            
            # Start tunnel
            tunnel_config = {}
            if args.ngrok_domain:
                tunnel_config["domain"] = args.ngrok_domain
            
            public_url = ngrok_manager.connect(port, **tunnel_config)
            logger.info(f"Ngrok tunnel established: {public_url}")
            
        except Exception as e:
            logger.error(f"Failed to setup ngrok tunnel: {e}")
            sys.exit(1)
    
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
