"""
Output parsers for various pentesting tools.
Converts tool outputs into structured data for analysis and reporting.
"""

import json
import xml.etree.ElementTree as ET
import re
import logging
from typing import Dict, Any, List, Optional, Union
from pathlib import Path

logger = logging.getLogger(__name__)

class OutputParser:
    """Base class for tool output parsers."""
    
    @staticmethod
    def parse_nmap_xml(output: str) -> Dict[str, Any]:
        """Parse Nmap XML output into structured data."""
        try:
            root = ET.fromstring(output)
            results = {
                "scan_info": {},
                "hosts": []
            }
            
            # Parse scan info
            scaninfo = root.find("scaninfo")
            if scaninfo is not None:
                results["scan_info"] = {
                    "type": scaninfo.get("type"),
                    "protocol": scaninfo.get("protocol"),
                    "numservices": scaninfo.get("numservices"),
                    "services": scaninfo.get("services")
                }
            
            # Parse hosts
            for host in root.findall("host"):
                host_data = {"addresses": [], "ports": [], "hostnames": []}
                
                # Get addresses
                for address in host.findall("address"):
                    host_data["addresses"].append({
                        "addr": address.get("addr"),
                        "addrtype": address.get("addrtype")
                    })
                
                # Get hostnames
                for hostname in host.findall(".//hostname"):
                    host_data["hostnames"].append({
                        "name": hostname.get("name"),
                        "type": hostname.get("type")
                    })
                
                # Get ports
                ports_elem = host.find("ports")
                if ports_elem is not None:
                    for port in ports_elem.findall("port"):
                        port_data = {
                            "portid": port.get("portid"),
                            "protocol": port.get("protocol"),
                            "state": port.find("state").get("state") if port.find("state") is not None else "unknown"
                        }
                        
                        # Get service info
                        service = port.find("service")
                        if service is not None:
                            port_data["service"] = {
                                "name": service.get("name"),
                                "product": service.get("product"),
                                "version": service.get("version"),
                                "extrainfo": service.get("extrainfo")
                            }
                        
                        host_data["ports"].append(port_data)
                
                results["hosts"].append(host_data)
            
            return results
            
        except ET.ParseError as e:
            logger.error(f"Error parsing Nmap XML: {e}")
            return {"error": f"XML parse error: {e}", "raw_output": output}
        except Exception as e:
            logger.error(f"Error processing Nmap output: {e}")
            return {"error": f"Processing error: {e}", "raw_output": output}
    
    @staticmethod
    def parse_nikto_json(output: str) -> Dict[str, Any]:
        """Parse Nikto JSON output."""
        try:
            data = json.loads(output)
            return {
                "vulnerabilities": data.get("vulnerabilities", []),
                "scan_details": data.get("scan_details", {}),
                "host_info": data.get("host", {})
            }
        except json.JSONDecodeError as e:
            logger.error(f"Error parsing Nikto JSON: {e}")
            return {"error": f"JSON parse error: {e}", "raw_output": output}
    
    @staticmethod
    def parse_dirb_text(output: str) -> Dict[str, Any]:
        """Parse DIRB text output."""
        results = {
            "directories_found": [],
            "files_found": [],
            "errors": []
        }
        
        lines = output.split('\n')
        for line in lines:
            line = line.strip()
            
            # Match directory/file findings
            if line.startswith('+ '):
                match = re.match(r'\+ (http[s]?://[^\s]+)\s+\(CODE:(\d+)\|SIZE:(\d+)\)', line)
                if match:
                    url, code, size = match.groups()
                    item = {
                        "url": url,
                        "status_code": int(code),
                        "size": int(size)
                    }
                    
                    if url.endswith('/'):
                        results["directories_found"].append(item)
                    else:
                        results["files_found"].append(item)
            
            # Match errors
            elif 'ERROR' in line or 'FATAL' in line:
                results["errors"].append(line)
        
        return results
    
    @staticmethod
    def parse_gobuster_text(output: str) -> Dict[str, Any]:
        """Parse Gobuster text output."""
        results = {
            "found_paths": [],
            "scan_info": {}
        }
        
        lines = output.split('\n')
        for line in lines:
            line = line.strip()
            
            # Match found paths
            if line.startswith('/'):
                parts = line.split()
                if len(parts) >= 3:
                    results["found_paths"].append({
                        "path": parts[0],
                        "status_code": parts[1] if parts[1].isdigit() else None,
                        "size": parts[2] if len(parts) > 2 and parts[2].isdigit() else None
                    })
        
        return results
    
    @staticmethod
    def parse_masscan_json(output: str) -> Dict[str, Any]:
        """Parse Masscan JSON output."""
        try:
            # Masscan outputs each result as a separate JSON object
            results = {"hosts": []}
            
            for line in output.split('\n'):
                line = line.strip()
                if line.startswith('{'):
                    try:
                        item = json.loads(line)
                        results["hosts"].append(item)
                    except json.JSONDecodeError:
                        continue
            
            return results
        except Exception as e:
            logger.error(f"Error parsing Masscan output: {e}")
            return {"error": str(e), "raw_output": output}
    
    @staticmethod
    def parse_harvester_text(output: str) -> Dict[str, Any]:
        """Parse theHarvester text output."""
        results = {
            "emails": [],
            "hosts": [],
            "ips": [],
            "urls": []
        }
        
        current_section = None
        lines = output.split('\n')
        
        for line in lines:
            line = line.strip()
            
            if 'emails found:' in line.lower():
                current_section = 'emails'
            elif 'hosts found:' in line.lower():
                current_section = 'hosts'
            elif 'ip addresses found:' in line.lower():
                current_section = 'ips'
            elif 'urls found:' in line.lower():
                current_section = 'urls'
            elif line and current_section and not line.startswith('-'):
                if current_section in results:
                    results[current_section].append(line)
        
        return results
    
    @staticmethod
    def parse_msf_console(output: str) -> Dict[str, Any]:
        """Parse Metasploit console output."""
        results = {
            "sessions": [],
            "vulnerabilities": [],
            "exploits_attempted": [],
            "errors": []
        }
        
        lines = output.split('\n')
        for line in lines:
            line = line.strip()
            
            if '[+]' in line:
                if 'session' in line.lower():
                    results["sessions"].append(line.replace('[+]', '').strip())
                elif 'vulnerable' in line.lower():
                    results["vulnerabilities"].append(line.replace('[+]', '').strip())
                else:
                    results["exploits_attempted"].append(line.replace('[+]', '').strip())
            elif '[-]' in line or '[!]' in line:
                results["errors"].append(line)
        
        return results
    
    @staticmethod
    def parse_hashcat_text(output: str) -> Dict[str, Any]:
        """Parse Hashcat output."""
        results = {
            "cracked_hashes": [],
            "session_info": {},
            "progress": {}
        }
        
        lines = output.split('\n')
        for line in lines:
            line = line.strip()
            
            # Look for cracked hashes (usually hash:password format)
            if ':' in line and len(line.split(':')) >= 2:
                parts = line.split(':', 1)
                if len(parts[0]) > 10:  # Likely a hash
                    results["cracked_hashes"].append({
                        "hash": parts[0],
                        "password": parts[1]
                    })
            
            # Parse progress information
            elif 'Progress' in line:
                results["progress"]["status"] = line
            elif 'Session' in line:
                results["session_info"]["session"] = line
        
        return results
    
    @staticmethod
    def parse_hydra_text(output: str) -> Dict[str, Any]:
        """Parse Hydra brute force output."""
        results = {
            "successful_logins": [],
            "scan_info": {},
            "errors": []
        }
        
        lines = output.split('\n')
        for line in lines:
            line = line.strip()
            
            # Look for successful login attempts
            if '[DATA]' in line:
                results["scan_info"]["data"] = line.replace('[DATA]', '').strip()
            elif line.startswith('[') and 'login:' in line and 'password:' in line:
                # Extract login credentials
                match = re.search(r'login:\s*(\S+)\s+password:\s*(\S+)', line)
                if match:
                    results["successful_logins"].append({
                        "username": match.group(1),
                        "password": match.group(2),
                        "service": line.split(']')[0].replace('[', '')
                    })
            elif 'ERROR' in line:
                results["errors"].append(line)
        
        return results
    
    @staticmethod
    def parse_wpscan_json(output: str) -> Dict[str, Any]:
        """Parse WPScan JSON output."""
        try:
            return json.loads(output)
        except json.JSONDecodeError as e:
            logger.error(f"Error parsing WPScan JSON: {e}")
            return {"error": f"JSON parse error: {e}", "raw_output": output}
    
    @staticmethod
    def parse_nuclei_json(output: str) -> Dict[str, Any]:
        """Parse Nuclei JSON output."""
        results = {"findings": []}
        
        for line in output.split('\n'):
            line = line.strip()
            if line.startswith('{'):
                try:
                    finding = json.loads(line)
                    results["findings"].append(finding)
                except json.JSONDecodeError:
                    continue
        
        return results
    
    @staticmethod
    def parse_generic_json(output: str) -> Dict[str, Any]:
        """Generic JSON parser for tools that output valid JSON."""
        try:
            return json.loads(output)
        except json.JSONDecodeError as e:
            logger.error(f"Error parsing JSON output: {e}")
            return {"error": f"JSON parse error: {e}", "raw_output": output}
    
    @staticmethod
    def parse_generic_text(output: str) -> Dict[str, Any]:
        """Generic text parser that preserves the original output."""
        return {
            "raw_output": output,
            "line_count": len(output.split('\n')),
            "char_count": len(output)
        }

# Parser mapping for easy lookup
PARSERS = {
    "parse_nmap_xml": OutputParser.parse_nmap_xml,
    "parse_nikto_json": OutputParser.parse_nikto_json,
    "parse_dirb_text": OutputParser.parse_dirb_text,
    "parse_gobuster_text": OutputParser.parse_gobuster_text,
    "parse_masscan_json": OutputParser.parse_masscan_json,
    "parse_harvester_text": OutputParser.parse_harvester_text,
    "parse_msf_console": OutputParser.parse_msf_console,
    "parse_hashcat_text": OutputParser.parse_hashcat_text,
    "parse_hydra_text": OutputParser.parse_hydra_text,
    "parse_wpscan_json": OutputParser.parse_wpscan_json,
    "parse_nuclei_json": OutputParser.parse_nuclei_json,
    "parse_generic_json": OutputParser.parse_generic_json,
    "parse_generic_text": OutputParser.parse_generic_text
}