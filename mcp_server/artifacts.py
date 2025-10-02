"""
Artifacts module for MCP Kali Server.
Handles artifact storage, auto-parsing, and summarization.
"""

import json
import logging
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List, Optional, Union
import hashlib

from .util import safe_json_save, safe_json_load, sanitize_filename, get_file_size_str

logger = logging.getLogger(__name__)

# Artifact storage configuration
ARTIFACTS_BASE_DIR = Path("/var/lib/mcp/artifacts")

class ArtifactManager:
    """Manages artifact storage and retrieval."""
    
    def __init__(self, base_dir: Path = ARTIFACTS_BASE_DIR):
        self.base_dir = base_dir
        self.base_dir.mkdir(parents=True, exist_ok=True)
    
    def get_artifact_dir(self, server_id: str, run_id: str) -> Path:
        """Get directory path for a specific artifact."""
        return self.base_dir / server_id / run_id
    
    def create_artifact_uri(self, server_id: str, run_id: str, filename: str) -> str:
        """Create artifact URI for referencing stored artifacts."""
        return f"artifact://{server_id}/{run_id}/{filename}"
    
    def parse_artifact_uri(self, uri: str) -> Optional[tuple[str, str, str]]:
        """Parse artifact URI into components."""
        try:
            if not uri.startswith("artifact://"):
                return None
            
            path = uri[11:]  # Remove "artifact://" prefix
            parts = path.split("/", 2)
            
            if len(parts) != 3:
                return None
                
            return parts[0], parts[1], parts[2]  # server_id, run_id, filename
            
        except Exception as e:
            logger.error(f"Error parsing artifact URI {uri}: {e}")
            return None
    
    def save_artifact(self, server_id: str, run_id: str, kind: str, content: Union[str, Dict[str, Any]]) -> Optional[str]:
        """
        Save artifact data and create associated metadata.
        
        Args:
            server_id: Server ID
            run_id: Unique run ID
            kind: Type of artifact (e.g., 'nmap_scan', 'web_scan')
            content: Artifact content (string or structured data)
            
        Returns:
            Artifact URI if successful, None otherwise
        """
        try:
            artifact_dir = self.get_artifact_dir(server_id, run_id)
            artifact_dir.mkdir(parents=True, exist_ok=True)
            
            # Determine content type and save raw data
            if isinstance(content, dict):
                # Structured data - save as JSON
                raw_file = artifact_dir / "raw.json"
                if not safe_json_save(raw_file, content):
                    return None
                raw_content = json.dumps(content, indent=2)
            else:
                # String content - save as text or XML
                if content.strip().startswith("<?xml") or "<nmaprun" in content:
                    raw_file = artifact_dir / "raw.xml"
                else:
                    raw_file = artifact_dir / "raw.txt"
                
                with open(raw_file, 'w', encoding='utf-8') as f:
                    f.write(content)
                raw_content = content
            
            # Generate summary
            summary = self._generate_summary(kind, content)
            summary_file = artifact_dir / "summary.txt"
            with open(summary_file, 'w', encoding='utf-8') as f:
                f.write(summary)
            
            # Parse structured data if applicable
            parsed_data = self._parse_content(kind, content)
            if parsed_data:
                parsed_file = artifact_dir / "parsed.json"
                safe_json_save(parsed_file, parsed_data)
            
            # Create metadata
            metadata = {
                "server_id": server_id,
                "run_id": run_id,
                "kind": kind,
                "created": datetime.now(timezone.utc).isoformat(),
                "files": {
                    "raw": raw_file.name,
                    "summary": summary_file.name,
                    "parsed": "parsed.json" if parsed_data else None
                },
                "size": get_file_size_str(raw_file),
                "summary": summary[:200] + "..." if len(summary) > 200 else summary
            }
            
            metadata_file = artifact_dir / "metadata.json"
            if not safe_json_save(metadata_file, metadata):
                return None
            
            # Return URI to raw file
            artifact_uri = self.create_artifact_uri(server_id, run_id, raw_file.name)
            logger.info(f"Saved artifact: {artifact_uri}")
            
            return artifact_uri
            
        except Exception as e:
            logger.error(f"Error saving artifact for {server_id}/{run_id}: {e}")
            return None
    
    def list_artifacts(self, server_id: str, limit: int = 50, offset: int = 0) -> Dict[str, Any]:
        """
        List artifacts for a server.
        
        Args:
            server_id: Server ID
            limit: Maximum number of artifacts to return
            offset: Offset for pagination
            
        Returns:
            Dictionary with artifact list and pagination info
        """
        try:
            server_dir = self.base_dir / server_id
            if not server_dir.exists():
                return {"items": [], "total": 0, "nextOffset": None}
            
            # Get all run directories
            run_dirs = sorted([d for d in server_dir.iterdir() if d.is_dir()], 
                            key=lambda x: x.stat().st_mtime, reverse=True)
            
            total = len(run_dirs)
            
            # Apply pagination
            paginated_dirs = run_dirs[offset:offset + limit]
            
            items = []
            for run_dir in paginated_dirs:
                metadata_file = run_dir / "metadata.json"
                metadata = safe_json_load(metadata_file, {})
                
                if metadata:
                    # Create artifact URI for the raw file
                    raw_filename = metadata.get("files", {}).get("raw", "raw.txt")
                    artifact_uri = self.create_artifact_uri(server_id, run_dir.name, raw_filename)
                    
                    item = {
                        "artifact_uri": artifact_uri,
                        "run_id": run_dir.name,
                        "kind": metadata.get("kind", "unknown"),
                        "summary": metadata.get("summary", ""),
                        "created": metadata.get("created", ""),
                        "size": metadata.get("size", "unknown")
                    }
                    items.append(item)
            
            # Calculate next offset
            next_offset = offset + limit if offset + limit < total else None
            
            return {
                "items": items,
                "total": total,
                "limit": limit,
                "offset": offset,
                "nextOffset": next_offset
            }
            
        except Exception as e:
            logger.error(f"Error listing artifacts for {server_id}: {e}")
            return {"items": [], "total": 0, "error": str(e)}
    
    def read_artifact(self, uri: str) -> Optional[Dict[str, Any]]:
        """
        Read artifact by URI.
        
        Args:
            uri: Artifact URI
            
        Returns:
            Dictionary with artifact content and metadata
        """
        try:
            parsed = self.parse_artifact_uri(uri)
            if not parsed:
                return None
            
            server_id, run_id, filename = parsed
            artifact_file = self.get_artifact_dir(server_id, run_id) / filename
            
            if not artifact_file.exists():
                logger.warning(f"Artifact file not found: {artifact_file}")
                return None
            
            # Load metadata
            metadata_file = artifact_file.parent / "metadata.json"
            metadata = safe_json_load(metadata_file, {})
            
            # Read content based on file type
            if filename.endswith('.json'):
                content = safe_json_load(artifact_file)
                content_type = "application/json"
            else:
                with open(artifact_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                content_type = "text/xml" if filename.endswith('.xml') else "text/plain"
            
            return {
                "uri": uri,
                "content": content,
                "content_type": content_type,
                "metadata": metadata,
                "size": get_file_size_str(artifact_file)
            }
            
        except Exception as e:
            logger.error(f"Error reading artifact {uri}: {e}")
            return None
    
    def _generate_summary(self, kind: str, content: Union[str, Dict[str, Any]]) -> str:
        """Generate human-readable summary of artifact content."""
        try:
            if kind == "nmap_scan":
                return self._summarize_nmap(content)
            elif isinstance(content, dict):
                return self._summarize_structured_data(content)
            else:
                return self._summarize_text(content)
                
        except Exception as e:
            logger.error(f"Error generating summary for {kind}: {e}")
            return f"Summary generation failed: {str(e)}"
    
    def _summarize_nmap(self, content: Union[str, Dict[str, Any]]) -> str:
        """Generate summary for nmap scan results."""
        try:
            if isinstance(content, dict):
                # Extract from structured data
                xml_output = content.get("xml_output", "")
                target = content.get("target", "unknown")
            else:
                xml_output = content
                target = "unknown"
            
            if not xml_output.strip():
                return f"Nmap scan of {target} - no output generated"
            
            # Parse XML to extract key information
            try:
                root = ET.fromstring(xml_output)
                
                # Extract scan info
                scan_args = root.get("args", "")
                start_time = root.get("startstr", "")
                
                # Count hosts and ports
                hosts = root.findall("host")
                total_hosts = len(hosts)
                up_hosts = 0
                total_ports = 0
                open_ports = 0
                
                for host in hosts:
                    status = host.find("status")
                    if status is not None and status.get("state") == "up":
                        up_hosts += 1
                        
                        ports = host.findall(".//port")
                        total_ports += len(ports)
                        
                        for port in ports:
                            state = port.find("state")
                            if state is not None and state.get("state") in ["open", "open|filtered"]:
                                open_ports += 1
                
                summary = f"Nmap scan of {target} completed on {start_time}. "
                summary += f"Scanned {total_hosts} hosts ({up_hosts} up), found {open_ports} open ports out of {total_ports} total."
                
                if open_ports > 0:
                    # Add some detail about open services
                    services = set()
                    for host in hosts:
                        for port in host.findall(".//port"):
                            state = port.find("state")
                            if state is not None and state.get("state") in ["open", "open|filtered"]:
                                service = port.find("service")
                                if service is not None:
                                    service_name = service.get("name", "unknown")
                                    services.add(service_name)
                    
                    if services:
                        services_list = sorted(list(services))[:5]  # Top 5 services
                        summary += f" Common services: {', '.join(services_list)}"
                        if len(services) > 5:
                            summary += f" and {len(services) - 5} others"
                
                return summary
                
            except ET.ParseError:
                # Fallback for invalid XML
                lines = xml_output.split('\n')
                non_empty_lines = [line for line in lines if line.strip()]
                summary = f"Nmap scan of {target} - {len(non_empty_lines)} lines of output"
                
                # Look for indication of results
                if any("open" in line.lower() for line in lines):
                    open_count = sum(1 for line in lines if "open" in line.lower())
                    summary += f", approximately {open_count} open ports found"
                
                return summary
                
        except Exception as e:
            return f"Nmap scan summary failed: {str(e)}"
    
    def _summarize_structured_data(self, data: Dict[str, Any]) -> str:
        """Generate summary for structured data."""
        try:
            summary_parts = []
            
            # Count different types of data
            for key, value in data.items():
                if isinstance(value, list):
                    summary_parts.append(f"{len(value)} {key}")
                elif isinstance(value, dict):
                    summary_parts.append(f"{key} data available")
                elif isinstance(value, str) and len(value) > 100:
                    summary_parts.append(f"{key} ({len(value)} chars)")
            
            if summary_parts:
                return f"Structured data with: {', '.join(summary_parts)}"
            else:
                return "Structured data artifact"
                
        except Exception:
            return "Structured data artifact (summary unavailable)"
    
    def _summarize_text(self, text: str) -> str:
        """Generate summary for text content."""
        try:
            lines = text.split('\n')
            non_empty_lines = [line for line in lines if line.strip()]
            
            summary = f"Text content with {len(non_empty_lines)} lines"
            
            # Look for common patterns
            if any("error" in line.lower() for line in lines[:10]):
                summary += " (contains errors)"
            elif any("warning" in line.lower() for line in lines[:10]):
                summary += " (contains warnings)"
            elif any("found" in line.lower() for line in lines[:10]):
                summary += " (contains findings)"
            
            return summary
            
        except Exception:
            return "Text content (summary unavailable)"
    
    def _parse_content(self, kind: str, content: Union[str, Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """Parse content into structured format if applicable."""
        try:
            if kind == "nmap_scan":
                return self._parse_nmap_xml_content(content)
            return None
            
        except Exception as e:
            logger.error(f"Error parsing content for {kind}: {e}")
            return None
    
    def _parse_nmap_xml_content(self, content: Union[str, Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """Parse nmap XML content into structured format."""
        try:
            if isinstance(content, dict):
                xml_content = content.get("xml_output", "")
            else:
                xml_content = content
            
            if not xml_content.strip():
                return None
            
            # Import from tools module to avoid circular import
            from .tools import ToolRegistry
            registry = ToolRegistry()
            findings = registry._parse_nmap_xml(xml_content)
            
            if findings:
                return {
                    "hosts": findings,
                    "total_hosts": len(findings),
                    "total_ports": sum(len(host.get("ports", [])) for host in findings),
                    "parsed_at": datetime.now(timezone.utc).isoformat()
                }
            
            return None
            
        except Exception as e:
            logger.error(f"Error parsing nmap XML: {e}")
            return None

# Global artifact manager instance
artifact_manager = ArtifactManager()

def save_artifact(server_id: str, run_id: str, kind: str, content: Union[str, Dict[str, Any]]) -> Optional[str]:
    """Save artifact using global manager."""
    return artifact_manager.save_artifact(server_id, run_id, kind, content)

def list_artifacts(server_id: str, limit: int = 50, offset: int = 0) -> Dict[str, Any]:
    """List artifacts using global manager."""
    return artifact_manager.list_artifacts(server_id, limit, offset)

def read_artifact(uri: str) -> Optional[Dict[str, Any]]:
    """Read artifact using global manager."""
    return artifact_manager.read_artifact(uri)

def parse_nmap_xml(xml_str: str) -> List[Dict[str, Any]]:
    """Parse nmap XML output into structured findings."""
    # Import to avoid circular dependency
    from .tools import ToolRegistry
    registry = ToolRegistry()
    return registry._parse_nmap_xml(xml_str)

def summarize(text: str) -> str:
    """Generate summary of text content."""
    return artifact_manager._summarize_text(text)