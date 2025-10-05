"""
Advanced Tool API Integrations
Provides REST API integrations for tools like Metasploit, Bettercap, ZAP, GoPhish, Empire
"""

import asyncio
import aiohttp
import json
import logging
import base64
from typing import Dict, Any, Optional, List
from urllib.parse import urljoin

logger = logging.getLogger(__name__)

class APIIntegration:
    """Base class for tool API integrations."""
    
    def __init__(self, base_url: str, auth_method: str = None, auth_data: Dict[str, Any] = None):
        self.base_url = base_url.rstrip('/')
        self.auth_method = auth_method
        self.auth_data = auth_data or {}
        self.session = None
    
    async def __aenter__(self):
        """Async context manager entry."""
        self.session = aiohttp.ClientSession()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        if self.session:
            await self.session.close()
    
    def _get_auth_headers(self) -> Dict[str, str]:
        """Get authentication headers based on auth method."""
        headers = {"Content-Type": "application/json"}
        
        if self.auth_method == "api_key":
            headers["X-API-Key"] = self.auth_data.get("api_key", "")
        elif self.auth_method == "bearer_token":
            headers["Authorization"] = f"Bearer {self.auth_data.get('token', '')}"
        elif self.auth_method == "basic_auth":
            username = self.auth_data.get("username", "")
            password = self.auth_data.get("password", "")
            credentials = base64.b64encode(f"{username}:{password}".encode()).decode()
            headers["Authorization"] = f"Basic {credentials}"
        elif self.auth_method == "jwt_token":
            headers["Authorization"] = f"Bearer {self.auth_data.get('jwt', '')}"
        
        return headers
    
    async def request(self, method: str, endpoint: str, data: Dict[str, Any] = None) -> Dict[str, Any]:
        """Make an authenticated request to the API."""
        if not self.session:
            raise RuntimeError("APIIntegration must be used as async context manager")
        
        url = urljoin(f"{self.base_url}/", endpoint.lstrip('/'))
        headers = self._get_auth_headers()
        
        try:
            async with self.session.request(
                method, url, 
                headers=headers, 
                json=data,
                timeout=aiohttp.ClientTimeout(total=30)
            ) as response:
                
                if response.content_type == 'application/json':
                    result = await response.json()
                else:
                    text = await response.text()
                    result = {"raw_response": text}
                
                result["status_code"] = response.status
                result["success"] = 200 <= response.status < 300
                
                return result
                
        except aiohttp.ClientError as e:
            logger.error(f"API request failed: {e}")
            return {"error": str(e), "success": False}
        except Exception as e:
            logger.error(f"Unexpected error in API request: {e}")
            return {"error": f"Unexpected error: {e}", "success": False}

class MetasploitAPI(APIIntegration):
    """Metasploit REST API integration via msfrpcd."""
    
    def __init__(self, base_url: str = "http://localhost:55553", username: str = "msf", password: str = ""):
        super().__init__(base_url, "basic_auth", {"username": username, "password": password})
        self.token = None
    
    async def authenticate(self) -> bool:
        """Authenticate with Metasploit RPC and get token."""
        try:
            auth_data = {
                "method": "auth.login",
                "params": [self.auth_data["username"], self.auth_data["password"]]
            }
            
            result = await self.request("POST", "/api/", auth_data)
            
            if result.get("success") and "result" in result:
                self.token = result["result"].get("token")
                return self.token is not None
            
            return False
            
        except Exception as e:
            logger.error(f"Metasploit authentication failed: {e}")
            return False
    
    async def list_exploits(self, search: str = "") -> Dict[str, Any]:
        """List available exploit modules."""
        if not self.token:
            await self.authenticate()
        
        data = {
            "method": "module.exploits",
            "token": self.token
        }
        
        result = await self.request("POST", "/api/", data)
        
        if search:
            # Filter results by search term
            exploits = result.get("result", {}).get("modules", [])
            filtered = [exp for exp in exploits if search.lower() in exp.lower()]
            result["result"]["modules"] = filtered
        
        return result
    
    async def run_exploit(self, module: str, target: str, payload: str = "generic/shell_reverse_tcp") -> Dict[str, Any]:
        """Run an exploit module."""
        if not self.token:
            await self.authenticate()
        
        # Configure exploit
        config_data = {
            "method": "module.use",
            "token": self.token,
            "params": ["exploit", module]
        }
        
        config_result = await self.request("POST", "/api/", config_data)
        if not config_result.get("success"):
            return config_result
        
        # Set options
        options = [
            ("RHOSTS", target),
            ("PAYLOAD", payload)
        ]
        
        for option, value in options:
            option_data = {
                "method": "module.options",
                "token": self.token,
                "params": ["exploit", module, {option: value}]
            }
            await self.request("POST", "/api/", option_data)
        
        # Execute exploit
        exec_data = {
            "method": "module.execute",
            "token": self.token,
            "params": ["exploit", module]
        }
        
        return await self.request("POST", "/api/", exec_data)

class BettercapAPI(APIIntegration):
    """Bettercap REST API integration."""
    
    def __init__(self, base_url: str = "http://localhost:8081", username: str = "admin", password: str = "admin"):
        super().__init__(base_url, "basic_auth", {"username": username, "password": password})
    
    async def get_session_info(self) -> Dict[str, Any]:
        """Get current session information."""
        return await self.request("GET", "/api/session")
    
    async def start_wifi_recon(self) -> Dict[str, Any]:
        """Start WiFi reconnaissance."""
        return await self.request("POST", "/api/session", {"cmd": "wifi.recon on"})
    
    async def get_wifi_networks(self) -> Dict[str, Any]:
        """Get discovered WiFi networks."""
        return await self.request("GET", "/api/session/wifi")
    
    async def start_net_recon(self) -> Dict[str, Any]:
        """Start network reconnaissance."""
        return await self.request("POST", "/api/session", {"cmd": "net.recon on"})
    
    async def get_network_hosts(self) -> Dict[str, Any]:
        """Get discovered network hosts."""
        return await self.request("GET", "/api/session/lan")

class ZAPAPI(APIIntegration):
    """OWASP ZAP API integration."""
    
    def __init__(self, base_url: str = "http://localhost:8080", api_key: str = ""):
        super().__init__(base_url, "api_key", {"api_key": api_key})
    
    async def spider_url(self, url: str) -> Dict[str, Any]:
        """Start spidering a URL."""
        endpoint = f"/JSON/spider/action/scan/?url={url}&apikey={self.auth_data.get('api_key', '')}"
        return await self.request("GET", endpoint)
    
    async def active_scan(self, url: str) -> Dict[str, Any]:
        """Start active scanning of a URL."""
        endpoint = f"/JSON/ascan/action/scan/?url={url}&apikey={self.auth_data.get('api_key', '')}"
        return await self.request("GET", endpoint)
    
    async def get_alerts(self, base_url: str = "") -> Dict[str, Any]:
        """Get security alerts/vulnerabilities found."""
        endpoint = f"/JSON/core/view/alerts/?baseurl={base_url}&apikey={self.auth_data.get('api_key', '')}"
        return await self.request("GET", endpoint)
    
    async def get_scan_status(self, scan_id: str) -> Dict[str, Any]:
        """Get status of active scan."""
        endpoint = f"/JSON/ascan/view/status/?scanId={scan_id}&apikey={self.auth_data.get('api_key', '')}"
        return await self.request("GET", endpoint)

class GoPhishAPI(APIIntegration):
    """GoPhish REST API integration."""
    
    def __init__(self, base_url: str = "https://localhost:3333", api_key: str = ""):
        super().__init__(base_url, "api_key", {"api_key": api_key})
    
    async def get_campaigns(self) -> Dict[str, Any]:
        """Get list of phishing campaigns."""
        return await self.request("GET", "/api/campaigns/")
    
    async def create_campaign(self, name: str, template_id: int, page_id: int, 
                            smtp_id: int, groups: List[int]) -> Dict[str, Any]:
        """Create a new phishing campaign."""
        data = {
            "name": name,
            "template": {"id": template_id},
            "page": {"id": page_id},
            "smtp": {"id": smtp_id},
            "groups": [{"id": gid} for gid in groups]
        }
        return await self.request("POST", "/api/campaigns/", data)
    
    async def get_campaign_results(self, campaign_id: int) -> Dict[str, Any]:
        """Get results of a phishing campaign."""
        return await self.request("GET", f"/api/campaigns/{campaign_id}/results")
    
    async def get_templates(self) -> Dict[str, Any]:
        """Get email templates."""
        return await self.request("GET", "/api/templates/")

class EmpireAPI(APIIntegration):
    """PowerShell Empire REST API integration."""
    
    def __init__(self, base_url: str = "http://localhost:1337", token: str = ""):
        super().__init__(base_url, "bearer_token", {"token": token})
    
    async def get_listeners(self) -> Dict[str, Any]:
        """Get active listeners."""
        return await self.request("GET", "/api/listeners")
    
    async def create_listener(self, name: str, listener_type: str = "http", port: int = 80) -> Dict[str, Any]:
        """Create a new listener."""
        data = {
            "name": name,
            "type": listener_type,
            "port": port
        }
        return await self.request("POST", "/api/listeners", data)
    
    async def get_agents(self) -> Dict[str, Any]:
        """Get active agents."""
        return await self.request("GET", "/api/agents")
    
    async def execute_module(self, agent_name: str, module_name: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """Execute a module on an agent."""
        data = {
            "module": module_name,
            "options": options or {}
        }
        return await self.request("POST", f"/api/agents/{agent_name}/modules", data)

# Tool API registry for easy access
API_INTEGRATIONS = {
    "metasploit": MetasploitAPI,
    "bettercap": BettercapAPI,
    "zap": ZAPAPI,
    "gophish": GoPhishAPI,
    "empire": EmpireAPI
}

async def get_api_integration(tool_name: str, **kwargs) -> Optional[APIIntegration]:
    """Get an API integration instance for a tool."""
    integration_class = API_INTEGRATIONS.get(tool_name.lower())
    if not integration_class:
        return None
    
    return integration_class(**kwargs)

async def test_api_connectivity(tool_name: str, config: Dict[str, Any]) -> Dict[str, Any]:
    """Test connectivity to a tool's API."""
    try:
        async with await get_api_integration(tool_name, **config) as api:
            if hasattr(api, 'get_session_info'):
                result = await api.get_session_info()
            elif hasattr(api, 'authenticate'):
                result = {"success": await api.authenticate()}
            else:
                # Generic connectivity test
                result = await api.request("GET", "/")
            
            return {
                "tool": tool_name,
                "connected": result.get("success", False),
                "details": result
            }
    
    except Exception as e:
        logger.error(f"API connectivity test failed for {tool_name}: {e}")
        return {
            "tool": tool_name,
            "connected": False,
            "error": str(e)
        }