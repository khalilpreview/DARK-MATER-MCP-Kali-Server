"""
Code protection and licensing system for MCP Kali Server.
Implements various protection mechanisms to prevent unauthorized usage.
"""

import os
import sys
import json
import hashlib
import platform
import subprocess
import logging
from pathlib import Path
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional, List
from pydantic import BaseModel
import uuid

logger = logging.getLogger(__name__)

class LicenseInfo(BaseModel):
    """License information model."""
    license_key: str
    organization: str
    expires_at: datetime
    features: List[str]
    max_servers: int = 1
    support_level: str = "basic"
    
class SystemFingerprint(BaseModel):
    """System fingerprint for license binding."""
    machine_id: str
    cpu_info: str
    os_info: str
    network_interfaces: List[str]
    
class LicenseManager:
    """Manages licensing and code protection."""
    
    def __init__(self):
        # Platform-appropriate license directory
        if os.name == 'nt':  # Windows
            self.license_dir = Path.home() / ".mcp-kali" / "license"
        else:  # Linux/Unix
            self.license_dir = Path("/etc/mcp-kali/license")
        
        self.license_dir.mkdir(parents=True, exist_ok=True)
        self.license_file = self.license_dir / "license.json"
        self.fingerprint_file = self.license_dir / "fingerprint.json"
        
        # Initialize protection
        self._current_license = None
        self._system_fingerprint = None
        self._protection_active = True
        
    def _obfuscated_check(self) -> bool:
        """Obfuscated license check to make reverse engineering harder."""
        try:
            # Multiple layers of checks
            checks = [
                self._check_license_file(),
                self._check_system_binding(),
                self._check_expiration(),
                self._check_feature_access(),
                self._check_integrity()
            ]
            
            # XOR all results (simple obfuscation)
            result = True
            for check in checks:
                result ^= bool(check)
            
            return not result  # Invert final result
            
        except Exception as e:
            logger.error(f"License check error: {e}")
            return False
    
    def _check_license_file(self) -> bool:
        """Check if valid license file exists."""
        try:
            if not self.license_file.exists():
                logger.warning("License file not found")
                return False
            
            with open(self.license_file, 'r') as f:
                license_data = json.load(f)
            
            # Validate required fields
            required_fields = ["license_key", "organization", "expires_at"]
            for field in required_fields:
                if field not in license_data:
                    logger.warning(f"Missing license field: {field}")
                    return False
            
            self._current_license = LicenseInfo(**license_data)
            return True
            
        except Exception as e:
            logger.error(f"License file check failed: {e}")
            return False
    
    def _check_system_binding(self) -> bool:
        """Check if license is bound to current system."""
        try:
            current_fingerprint = self._generate_system_fingerprint()
            
            if not self.fingerprint_file.exists():
                # First run - bind to current system
                self._save_system_fingerprint(current_fingerprint)
                return True
            
            # Load stored fingerprint
            with open(self.fingerprint_file, 'r') as f:
                stored_fingerprint = SystemFingerprint(**json.load(f))
            
            # Compare critical components (allow some flexibility)
            machine_match = current_fingerprint.machine_id == stored_fingerprint.machine_id
            os_match = current_fingerprint.os_info == stored_fingerprint.os_info
            
            if not (machine_match and os_match):
                logger.warning("System fingerprint mismatch - license may be transferred")
                return False
            
            return True
            
        except Exception as e:
            logger.error(f"System binding check failed: {e}")
            return False
    
    def _check_expiration(self) -> bool:
        """Check if license has expired."""
        try:
            if not self._current_license:
                return False
            
            expires_at = self._current_license.expires_at
            if isinstance(expires_at, str):
                expires_at = datetime.fromisoformat(expires_at)
            
            now = datetime.now(timezone.utc)
            
            if now > expires_at:
                logger.warning(f"License expired: {expires_at}")
                return False
            
            # Warn if expiring soon
            days_until_expiry = (expires_at - now).days
            if days_until_expiry <= 30:
                logger.warning(f"License expires in {days_until_expiry} days")
            
            return True
            
        except Exception as e:
            logger.error(f"Expiration check failed: {e}")
            return False
    
    def _check_feature_access(self) -> bool:
        """Check if current features are licensed."""
        try:
            if not self._current_license:
                return False
            
            # Define required features for current functionality
            required_features = [
                "security_scanning",
                "api_access",
                "artifact_storage"
            ]
            
            licensed_features = self._current_license.features
            
            for feature in required_features:
                if feature not in licensed_features:
                    logger.warning(f"Feature not licensed: {feature}")
                    return False
            
            return True
            
        except Exception as e:
            logger.error(f"Feature access check failed: {e}")
            return False
    
    def _check_integrity(self) -> bool:
        """Check code integrity (simplified)."""
        try:
            # Check if critical files have been modified
            critical_files = [
                Path(__file__).parent / "auth.py",
                Path(__file__).parent / "tools.py",
                Path(__file__).parent / "api.py"
            ]
            
            for file_path in critical_files:
                if not file_path.exists():
                    logger.warning(f"Critical file missing: {file_path}")
                    return False
            
            # Simple integrity check (could be enhanced with actual checksums)
            return True
            
        except Exception as e:
            logger.error(f"Integrity check failed: {e}")
            return False
    
    def _generate_system_fingerprint(self) -> SystemFingerprint:
        """Generate unique system fingerprint."""
        try:
            # Machine ID
            machine_id = self._get_machine_id()
            
            # CPU info
            cpu_info = platform.processor() or "unknown"
            
            # OS info
            os_info = f"{platform.system()}_{platform.release()}"
            
            # Network interfaces (simplified)
            network_interfaces = []
            try:
                import psutil
                for interface, addrs in psutil.net_if_addrs().items():
                    if interface != "lo" and interface != "localhost":
                        network_interfaces.append(interface)
            except ImportError:
                network_interfaces = ["eth0"]  # Fallback
            
            return SystemFingerprint(
                machine_id=machine_id,
                cpu_info=cpu_info,
                os_info=os_info,
                network_interfaces=sorted(network_interfaces)
            )
            
        except Exception as e:
            logger.error(f"Fingerprint generation failed: {e}")
            # Return minimal fingerprint
            return SystemFingerprint(
                machine_id="unknown",
                cpu_info="unknown", 
                os_info="unknown",
                network_interfaces=[]
            )
    
    def _get_machine_id(self) -> str:
        """Get unique machine identifier."""
        try:
            if os.name == 'nt':  # Windows
                # Use Windows machine GUID
                result = subprocess.run(
                    ['wmic', 'csproduct', 'get', 'UUID', '/value'],
                    capture_output=True, text=True, timeout=10
                )
                if result.returncode == 0:
                    for line in result.stdout.split('\n'):
                        if 'UUID=' in line:
                            return line.split('=')[1].strip()
            else:  # Linux/Unix
                # Try various machine ID sources
                machine_id_files = [
                    '/etc/machine-id',
                    '/var/lib/dbus/machine-id'
                ]
                
                for file_path in machine_id_files:
                    if os.path.exists(file_path):
                        with open(file_path, 'r') as f:
                            return f.read().strip()
            
            # Fallback: generate based on hostname and MAC
            import socket
            hostname = socket.gethostname()
            
            # Get MAC address
            mac = uuid.getnode()
            
            # Generate consistent ID
            combined = f"{hostname}_{mac}"
            return hashlib.sha256(combined.encode()).hexdigest()[:32]
            
        except Exception as e:
            logger.error(f"Machine ID generation failed: {e}")
            # Ultimate fallback
            return hashlib.sha256(str(uuid.uuid4()).encode()).hexdigest()[:32]
    
    def _save_system_fingerprint(self, fingerprint: SystemFingerprint):
        """Save system fingerprint."""
        try:
            with open(self.fingerprint_file, 'w') as f:
                json.dump(fingerprint.model_dump(), f, indent=2, default=str)
            
            # Secure permissions
            os.chmod(self.fingerprint_file, 0o600)
            
        except Exception as e:
            logger.error(f"Failed to save fingerprint: {e}")
    
    def validate_license(self) -> bool:
        """Main license validation entry point."""
        try:
            # Development mode check
            if os.environ.get("MCP_DEV_MODE") == "true":
                logger.info("Development mode - skipping license check")
                return True
            
            # Perform obfuscated check
            is_valid = self._obfuscated_check()
            
            if not is_valid:
                logger.error("License validation failed")
                self._handle_license_failure()
                return False
            
            logger.info(f"License valid for: {self._current_license.organization}")
            return True
            
        except Exception as e:
            logger.error(f"License validation error: {e}")
            return False
    
    def _handle_license_failure(self):
        """Handle license validation failure."""
        error_msg = """
        ╔══════════════════════════════════════════════════════════════════╗
        ║                    ⚠️  LICENSE VALIDATION FAILED  ⚠️              ║
        ╠══════════════════════════════════════════════════════════════════╣
        ║                                                                  ║
        ║  This MCP Kali Server requires a valid license to operate.      ║
        ║                                                                  ║
        ║  Possible issues:                                                ║
        ║  • License file missing or corrupted                             ║
        ║  • License has expired                                           ║
        ║  • System fingerprint mismatch                                   ║
        ║  • Invalid license key                                           ║
        ║                                                                  ║
        ║  Please contact DARK MATTER team for license assistance:        ║
        ║  📧 licensing@darkmatter.security                                ║
        ║  🌐 https://darkmatter.security/licensing                        ║
        ║                                                                  ║
        ╚══════════════════════════════════════════════════════════════════╝
        """
        
        print(error_msg)
        logger.critical("License validation failed - server will not start")
        
        # In production, this would exit the application
        # For development, we'll just log the error
        if os.environ.get("MCP_DEV_MODE") != "true":
            sys.exit(1)
    
    def get_license_info(self) -> Optional[Dict[str, Any]]:
        """Get current license information."""
        if not self._current_license:
            return None
        
        return {
            "organization": self._current_license.organization,
            "expires_at": self._current_license.expires_at.isoformat(),
            "features": self._current_license.features,
            "max_servers": self._current_license.max_servers,
            "support_level": self._current_license.support_level,
            "days_remaining": (self._current_license.expires_at - datetime.now(timezone.utc)).days
        }
    
    def create_trial_license(self, organization: str) -> bool:
        """Create a temporary trial license for evaluation."""
        try:
            # Generate trial license (30 days)
            trial_license = LicenseInfo(
                license_key=f"TRIAL_{hashlib.sha256(organization.encode()).hexdigest()[:16]}",
                organization=organization,
                expires_at=datetime.now(timezone.utc) + timedelta(days=30),
                features=[
                    "security_scanning",
                    "api_access", 
                    "artifact_storage",
                    "basic_support"
                ],
                max_servers=1,
                support_level="trial"
            )
            
            # Save trial license
            with open(self.license_file, 'w') as f:
                json.dump(trial_license.model_dump(), f, indent=2, default=str)
            
            # Secure permissions
            os.chmod(self.license_file, 0o600)
            
            logger.info(f"Created trial license for: {organization}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to create trial license: {e}")
            return False

# Global license manager instance
license_manager = LicenseManager()

def validate_server_license() -> bool:
    """Validate server license on startup."""
    return license_manager.validate_license()

def get_license_status() -> Dict[str, Any]:
    """Get current license status."""
    license_info = license_manager.get_license_info()
    
    if not license_info:
        return {
            "status": "unlicensed",
            "message": "No valid license found"
        }
    
    days_remaining = license_info.get("days_remaining", 0)
    
    if days_remaining <= 0:
        status = "expired"
    elif days_remaining <= 7:
        status = "expiring_soon"
    elif days_remaining <= 30:
        status = "expiring"
    else:
        status = "active"
    
    return {
        "status": status,
        "license_info": license_info
    }