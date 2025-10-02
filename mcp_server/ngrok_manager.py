"""
Ngrok integration module for MCP Kali Server.
Provides secure tunneling to make the server accessible from anywhere.
"""

import os
import logging
import time
from typing import Optional, Dict, Any
import requests
from pyngrok import ngrok, conf, exception

logger = logging.getLogger(__name__)

class NgrokManager:
    """Manages ngrok tunneling for the MCP server."""
    
    def __init__(self):
        self.tunnel = None
        self.public_url = None
        self.local_port = None
        self.auth_token = None
        
    def configure_ngrok(self, auth_token: Optional[str] = None) -> bool:
        """
        Configure ngrok with authentication token if provided.
        
        Args:
            auth_token: Ngrok authentication token
            
        Returns:
            True if configured successfully, False otherwise
        """
        try:
            # Get auth token from environment or parameter
            self.auth_token = auth_token or os.environ.get("NGROK_AUTH_TOKEN")
            
            if self.auth_token:
                ngrok.set_auth_token(self.auth_token)
                logger.info("Ngrok authentication token configured")
                return True
            else:
                logger.warning("No ngrok auth token provided - using free tier with limitations")
                return True
                
        except Exception as e:
            logger.error(f"Error configuring ngrok: {e}")
            return False
    
    def start_tunnel(self, port: int, protocol: str = "http", domain: Optional[str] = None) -> Optional[str]:
        """
        Start ngrok tunnel for the specified port.
        
        Args:
            port: Local port to tunnel
            protocol: Protocol (http or https)
            domain: Optional custom domain (requires paid plan)
            
        Returns:
            Public URL if successful, None otherwise
        """
        try:
            self.local_port = port
            
            # Configure ngrok settings
            conf.get_default().monitor_thread = False
            
            # Create tunnel with optional domain
            logger.info(f"Starting ngrok tunnel for port {port}...")
            if domain:
                logger.info(f"Using custom domain: {domain}")
                self.tunnel = ngrok.connect(port, protocol, hostname=domain)
            else:
                self.tunnel = ngrok.connect(port, protocol)
            
            self.public_url = self.tunnel.public_url
            
            logger.info(f"Ngrok tunnel established: {self.public_url}")
            return self.public_url
            
        except exception.PyngrokNgrokError as e:
            logger.error(f"Ngrok error: {e}")
            return None
        except Exception as e:
            logger.error(f"Error starting ngrok tunnel: {e}")
            return None
    
    def get_tunnel_info(self) -> Dict[str, Any]:
        """
        Get information about the active tunnel.
        
        Returns:
            Dictionary with tunnel information
        """
        if not self.tunnel:
            return {"status": "inactive"}
            
        try:
            return {
                "status": "active",
                "public_url": self.public_url,
                "local_port": self.local_port,
                "protocol": self.tunnel.proto,
                "name": self.tunnel.name,
                "created_at": getattr(self.tunnel, 'created_at', 'unknown')
            }
        except Exception as e:
            logger.error(f"Error getting tunnel info: {e}")
            return {"status": "error", "error": str(e)}
    
    def get_tunnel_metrics(self) -> Optional[Dict[str, Any]]:
        """
        Get tunnel metrics from ngrok API.
        
        Returns:
            Dictionary with tunnel metrics or None if unavailable
        """
        try:
            if not self.tunnel:
                return None
                
            # Get ngrok API URL
            api_url = "http://127.0.0.1:4040/api/tunnels"
            response = requests.get(api_url, timeout=5)
            
            if response.status_code == 200:
                data = response.json()
                tunnels = data.get("tunnels", [])
                
                for tunnel in tunnels:
                    if tunnel.get("public_url") == self.public_url:
                        return {
                            "connections": tunnel.get("metrics", {}).get("conns", {}).get("count", 0),
                            "http_requests": tunnel.get("metrics", {}).get("http", {}).get("count", 0),
                            "bytes_in": tunnel.get("metrics", {}).get("conns", {}).get("bytes_in", 0),
                            "bytes_out": tunnel.get("metrics", {}).get("conns", {}).get("bytes_out", 0)
                        }
            
            return None
            
        except Exception as e:
            logger.debug(f"Could not get tunnel metrics: {e}")
            return None
    
    def stop_tunnel(self) -> bool:
        """
        Stop the active ngrok tunnel.
        
        Returns:
            True if stopped successfully, False otherwise
        """
        try:
            if self.tunnel:
                logger.info(f"Stopping ngrok tunnel: {self.public_url}")
                ngrok.disconnect(self.tunnel.public_url)
                self.tunnel = None
                self.public_url = None
                self.local_port = None
                logger.info("Ngrok tunnel stopped")
                return True
            else:
                logger.info("No active ngrok tunnel to stop")
                return True
                
        except Exception as e:
            logger.error(f"Error stopping ngrok tunnel: {e}")
            return False
    
    def restart_tunnel(self, port: int, protocol: str = "http") -> Optional[str]:
        """
        Restart the ngrok tunnel.
        
        Args:
            port: Local port to tunnel
            protocol: Protocol (http or https)
            
        Returns:
            New public URL if successful, None otherwise
        """
        self.stop_tunnel()
        time.sleep(1)  # Brief pause
        return self.start_tunnel(port, protocol)
    
    def cleanup(self):
        """Clean up ngrok resources."""
        try:
            self.stop_tunnel()
            ngrok.kill()
            logger.info("Ngrok cleanup completed")
        except Exception as e:
            logger.error(f"Error during ngrok cleanup: {e}")

# Global ngrok manager instance
ngrok_manager = NgrokManager()

def setup_ngrok(port: int, auth_token: Optional[str] = None) -> Optional[str]:
    """
    Set up ngrok tunnel for the server.
    
    Args:
        port: Local port to tunnel
        auth_token: Optional ngrok auth token
        
    Returns:
        Public URL if successful, None otherwise
    """
    if ngrok_manager.configure_ngrok(auth_token):
        return ngrok_manager.start_tunnel(port)
    return None

def get_ngrok_info() -> Dict[str, Any]:
    """Get ngrok tunnel information."""
    return ngrok_manager.get_tunnel_info()

def get_ngrok_metrics() -> Optional[Dict[str, Any]]:
    """Get ngrok tunnel metrics."""
    return ngrok_manager.get_tunnel_metrics()

def stop_ngrok() -> bool:
    """Stop ngrok tunnel."""
    return ngrok_manager.stop_tunnel()

def cleanup_ngrok():
    """Clean up ngrok resources."""
    ngrok_manager.cleanup()