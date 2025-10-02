"""
Tools module for MCP Kali Server.
Provides schema-validated, safe execution of security testing tools.
"""

import subprocess
import logging
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
import shlex
import time

from .util import validate_tool_args, generate_run_id, format_duration, truncate_output
from .scope import validate_scope_and_destructiveness
from .artifacts import save_artifact
from .memory import record_observation

logger = logging.getLogger(__name__)

class ToolResult:
    """Result of a tool execution."""
    
    def __init__(self, rc: int, summary: str, artifact_uri: Optional[str] = None, 
                 findings: Optional[List[Dict[str, Any]]] = None, duration: float = 0):
        self.rc = rc
        self.summary = summary
        self.artifact_uri = artifact_uri
        self.findings = findings or []
        self.duration = duration
        
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "rc": self.rc,
            "summary": self.summary,
            "artifact_uri": self.artifact_uri,
            "findings": self.findings,
            "duration": self.duration,
            "duration_formatted": format_duration(self.duration)
        }

class ToolRegistry:
    """Registry of available tools and their metadata."""
    
    def __init__(self):
        self.tools = {
            "net.scan_basic": {
                "name": "net.scan_basic",
                "description": "Basic network scan using nmap with safety constraints",
                "schema": "/schemas/tools/net_scan_basic.json",
                "executor": self._execute_nmap_basic
            }
        }
    
    def list_tools(self) -> List[Dict[str, Any]]:
        """
        Get list of available tools with metadata.
        
        Returns:
            List of tool metadata dictionaries
        """
        return [
            {
                "name": tool["name"],
                "description": tool["description"],
                "schema": tool["schema"]
            }
            for tool in self.tools.values()
        ]
    
    def get_tool(self, name: str) -> Optional[Dict[str, Any]]:
        """
        Get tool metadata by name.
        
        Args:
            name: Tool name
            
        Returns:
            Tool metadata or None if not found
        """
        return self.tools.get(name)
    
    def _execute_nmap_basic(self, server_id: str, args: Dict[str, Any]) -> ToolResult:
        """
        Execute basic nmap scan safely.
        
        Args:
            server_id: Server ID for artifact storage
            args: Validated tool arguments
            
        Returns:
            ToolResult with scan results
        """
        start_time = time.time()
        run_id = generate_run_id()
        
        try:
            target = args["target"]
            ports = args.get("ports", "")
            fast = args.get("fast", True)
            
            # Build nmap command safely (no shell injection)
            cmd = ["nmap", "-sV", "--open"]
            
            # Add fast scan option
            if fast:
                cmd.append("-F")
                
            # Add port specification
            if ports:
                cmd.extend(["-p", ports])
                
            # Add timing and timeout options for safety
            cmd.extend(["-T2", "--host-timeout", "2m"])
            
            # Output in XML format for parsing
            cmd.append("-oX")
            cmd.append("-")  # Output to stdout
            
            # Add target last
            cmd.append(target)
            
            logger.info(f"Executing nmap scan: {' '.join(cmd[:-1])} [target]")
            
            # Execute with timeout
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120,  # 2 minute timeout
                check=False
            )
            
            duration = time.time() - start_time
            
            # Parse XML output
            findings = []
            if result.stdout and result.returncode == 0:
                findings = self._parse_nmap_xml(result.stdout)
            
            # Create summary
            if result.returncode == 0:
                if findings:
                    open_ports = sum(len(host.get("ports", [])) for host in findings)
                    summary = f"Scan completed successfully. Found {len(findings)} hosts with {open_ports} open ports."
                else:
                    summary = "Scan completed successfully. No open ports found."
            else:
                summary = f"Scan failed with return code {result.returncode}"
                if result.stderr:
                    summary += f": {result.stderr[:200]}"
            
            # Save artifact
            artifact_uri = None
            if result.stdout:
                artifact_data = {
                    "command": " ".join(cmd[:-1]) + " [target]",
                    "target": target,
                    "xml_output": result.stdout,
                    "stderr": result.stderr,
                    "return_code": result.returncode,
                    "duration": duration
                }
                artifact_uri = save_artifact(server_id, run_id, "nmap_scan", artifact_data)
            
            # Record observation in memory
            if findings:
                observation_summary = f"Nmap scan of {target} found {len(findings)} hosts"
                record_observation(server_id, "network_scan", observation_summary, findings)
            
            return ToolResult(
                rc=result.returncode,
                summary=summary,
                artifact_uri=artifact_uri,
                findings=findings,
                duration=duration
            )
            
        except subprocess.TimeoutExpired:
            duration = time.time() - start_time
            summary = f"Scan timed out after {format_duration(duration)}"
            logger.warning(f"Nmap scan timed out: {target}")
            
            return ToolResult(
                rc=-1,
                summary=summary,
                duration=duration
            )
            
        except Exception as e:
            duration = time.time() - start_time
            summary = f"Scan failed: {str(e)}"
            logger.error(f"Nmap scan error: {e}")
            
            return ToolResult(
                rc=-1,
                summary=summary,
                duration=duration
            )
    
    def _parse_nmap_xml(self, xml_output: str) -> List[Dict[str, Any]]:
        """
        Parse nmap XML output to extract structured findings.
        
        Args:
            xml_output: XML output from nmap
            
        Returns:
            List of host findings with ports and services
        """
        try:
            root = ET.fromstring(xml_output)
            findings = []
            
            for host in root.findall("host"):
                # Get host address
                address_elem = host.find(".//address[@addrtype='ipv4']")
                if address_elem is None:
                    continue
                    
                host_ip = address_elem.get("addr")
                
                # Get hostname if available
                hostname_elem = host.find(".//hostname")
                hostname = hostname_elem.get("name") if hostname_elem is not None else None
                
                # Get host state
                status_elem = host.find("status")
                host_state = status_elem.get("state") if status_elem is not None else "unknown"
                
                if host_state != "up":
                    continue
                
                # Get ports
                ports = []
                ports_elem = host.find("ports")
                if ports_elem is not None:
                    for port in ports_elem.findall("port"):
                        port_id = port.get("portid")
                        protocol = port.get("protocol")
                        
                        # Get port state
                        state_elem = port.find("state")
                        port_state = state_elem.get("state") if state_elem is not None else "unknown"
                        
                        if port_state not in ["open", "open|filtered"]:
                            continue
                        
                        # Get service info
                        service_elem = port.find("service")
                        service_name = service_elem.get("name") if service_elem is not None else "unknown"
                        service_version = service_elem.get("version") if service_elem is not None else ""
                        service_product = service_elem.get("product") if service_elem is not None else ""
                        
                        port_info = {
                            "port": int(port_id),
                            "protocol": protocol,
                            "state": port_state,
                            "service": service_name,
                            "version": service_version,
                            "product": service_product
                        }
                        ports.append(port_info)
                
                if ports:  # Only include hosts with open ports
                    host_info = {
                        "host": host_ip,
                        "hostname": hostname,
                        "state": host_state,
                        "ports": ports
                    }
                    findings.append(host_info)
            
            logger.debug(f"Parsed {len(findings)} hosts from nmap XML")
            return findings
            
        except Exception as e:
            logger.error(f"Error parsing nmap XML: {e}")
            return []

# Global tool registry instance
tool_registry = ToolRegistry()

def list_tools() -> List[Dict[str, Any]]:
    """
    Get list of available tools.
    
    Returns:
        List of tool metadata
    """
    return tool_registry.list_tools()

def call_tool(server_id: str, name: str, args: Dict[str, Any]) -> Dict[str, Any]:
    """
    Execute a tool with validation and safety checks.
    
    Args:
        server_id: Server ID for authentication and artifact storage
        name: Tool name to execute
        args: Tool arguments
        
    Returns:
        Tool execution result dictionary
    """
    try:
        # Get tool metadata
        tool = tool_registry.get_tool(name)
        if not tool:
            return {
                "rc": -1,
                "summary": f"Tool not found: {name}",
                "error": "TOOL_NOT_FOUND"
            }
        
        # Validate arguments against schema
        is_valid, validation_error = validate_tool_args(name, args)
        if not is_valid:
            return {
                "rc": -1,
                "summary": f"Invalid arguments: {validation_error}",
                "error": "VALIDATION_FAILED"
            }
        
        # Check scope and destructiveness
        is_allowed, scope_error = validate_scope_and_destructiveness(name, args)
        if not is_allowed:
            return {
                "rc": -1,
                "summary": f"Operation not allowed: {scope_error}",
                "error": "SCOPE_VIOLATION"
            }
        
        # Execute tool
        executor = tool["executor"]
        result = executor(server_id, args)
        
        # Convert to dictionary and add metadata
        result_dict = result.to_dict()
        result_dict["tool_name"] = name
        result_dict["executed_at"] = datetime.now(timezone.utc).isoformat()
        result_dict["server_id"] = server_id
        
        logger.info(f"Tool {name} executed successfully for server {server_id}")
        return result_dict
        
    except Exception as e:
        logger.error(f"Error executing tool {name}: {e}")
        return {
            "rc": -1,
            "summary": f"Tool execution failed: {str(e)}",
            "error": "EXECUTION_FAILED"
        }