"""
Authentication module for MCP Kali Server.
Handles enrollment tokens, API key generation, and credential management.
"""

import json
import secrets
import string
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, Optional, Tuple
import logging

from fastapi import HTTPException, status, Request, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel

logger = logging.getLogger(__name__)

# Configuration paths - handle both Windows and Linux
import os
if os.name == 'nt':  # Windows
    CONFIG_DIR = Path.home() / ".mcp-kali"
else:  # Linux/Unix
    CONFIG_DIR = Path("/etc/mcp-kali")

ENROLL_FILE = CONFIG_DIR / "enroll.json"
CREDENTIALS_FILE = CONFIG_DIR / "credentials.json"

class EnrollmentData(BaseModel):
    """Enrollment token data model."""
    id: str
    token: str
    created: datetime
    
class ServerCredentials(BaseModel):
    """Server API credentials model."""
    server_id: str
    api_key: str
    label: str
    created: datetime

class EnrollmentRequest(BaseModel):
    """Enrollment request model."""
    id: str
    token: str
    label: Optional[str] = None

class EnrollmentResponse(BaseModel):
    """Enrollment response model."""
    server_id: str
    api_key: str
    label: str

def generate_strong_key(length: int = 64) -> str:
    """
    Generate a cryptographically strong random key.
    
    Args:
        length: Length of the key to generate
        
    Returns:
        Random hex string of specified length
    """
    return secrets.token_hex(length // 2)

def generate_api_key() -> str:
    """
    Generate a strong API key.
    
    Returns:
        64-character hex API key
    """
    return generate_strong_key(64)

def generate_enrollment_token() -> str:
    """
    Generate a strong enrollment token.
    
    Returns:
        32-character hex enrollment token
    """
    return generate_strong_key(32)

def load_enroll() -> Optional[EnrollmentData]:
    """
    Load enrollment data from disk.
    
    Returns:
        EnrollmentData if file exists and is valid, None otherwise
    """
    try:
        if not ENROLL_FILE.exists():
            logger.debug(f"Enrollment file {ENROLL_FILE} does not exist")
            return None
            
        with open(ENROLL_FILE, 'r') as f:
            data = json.load(f)
            
        # Convert string timestamp back to datetime
        if 'created' in data and isinstance(data['created'], str):
            data['created'] = datetime.fromisoformat(data['created'])
            
        return EnrollmentData(**data)
        
    except Exception as e:
        logger.error(f"Error loading enrollment data: {e}")
        return None

def save_enroll(enroll_data: EnrollmentData) -> bool:
    """
    Save enrollment data to disk.
    
    Args:
        enroll_data: Enrollment data to save
        
    Returns:
        True if successful, False otherwise
    """
    try:
        # Ensure directory exists
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        
        # Convert datetime to ISO string for JSON serialization
        data = enroll_data.model_dump()
        if isinstance(data['created'], datetime):
            data['created'] = data['created'].isoformat()
        
        with open(ENROLL_FILE, 'w') as f:
            json.dump(data, f, indent=2)
            
        # Secure the file permissions (readable only by owner)
        ENROLL_FILE.chmod(0o600)
        
        logger.info(f"Enrollment data saved to {ENROLL_FILE}")
        return True
        
    except Exception as e:
        logger.error(f"Error saving enrollment data: {e}")
        return False

def load_api_credentials() -> Dict[str, ServerCredentials]:
    """
    Load API credentials from disk.
    
    Returns:
        Dictionary mapping server_id to credentials
    """
    try:
        if not CREDENTIALS_FILE.exists():
            logger.debug(f"Credentials file {CREDENTIALS_FILE} does not exist")
            return {}
            
        with open(CREDENTIALS_FILE, 'r') as f:
            data = json.load(f)
            
        credentials = {}
        
        # Handle both formats: single credential object or dictionary of credentials
        if 'server_id' in data and 'api_key' in data:
            # Single credential format (from smart_start.py)
            server_id = data['server_id']
            cred_data = data.copy()
            
            # Convert string timestamp back to datetime
            if 'created' in cred_data and isinstance(cred_data['created'], str):
                cred_data['created'] = datetime.fromisoformat(cred_data['created'])
                
            credentials[server_id] = ServerCredentials(**cred_data)
            
        else:
            # Multiple credentials format (dictionary)
            for server_id, cred_data in data.items():
                # Convert string timestamp back to datetime
                if 'created' in cred_data and isinstance(cred_data['created'], str):
                    cred_data['created'] = datetime.fromisoformat(cred_data['created'])
                    
                credentials[server_id] = ServerCredentials(**cred_data)
            
        return credentials
        
    except Exception as e:
        logger.error(f"Error loading API credentials: {e}")
        return {}

def save_api_credentials(credentials: Dict[str, ServerCredentials]) -> bool:
    """
    Save API credentials to disk.
    
    Args:
        credentials: Dictionary of server credentials to save
        
    Returns:
        True if successful, False otherwise
    """
    try:
        # Ensure directory exists
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        
        # Convert to serializable format
        data = {}
        for server_id, creds in credentials.items():
            cred_data = creds.model_dump()
            if isinstance(cred_data['created'], datetime):
                cred_data['created'] = cred_data['created'].isoformat()
            data[server_id] = cred_data
        
        with open(CREDENTIALS_FILE, 'w') as f:
            json.dump(data, f, indent=2)
            
        # Secure the file permissions (readable only by owner)
        CREDENTIALS_FILE.chmod(0o600)
        
        logger.info(f"API credentials saved to {CREDENTIALS_FILE}")
        return True
        
    except Exception as e:
        logger.error(f"Error saving API credentials: {e}")
        return False

def validate_enrollment(request: EnrollmentRequest) -> Tuple[bool, str]:
    """
    Validate enrollment request against stored enrollment token.
    
    Args:
        request: Enrollment request to validate
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    try:
        enroll_data = load_enroll()
        if not enroll_data:
            return False, "No enrollment token available"
            
        if enroll_data.id != request.id:
            return False, "Invalid enrollment ID"
            
        if enroll_data.token != request.token:
            return False, "Invalid enrollment token"
            
        return True, ""
        
    except Exception as e:
        logger.error(f"Error validating enrollment: {e}")
        return False, f"Validation error: {e}"

def create_server_credentials(request: EnrollmentRequest) -> ServerCredentials:
    """
    Create new server credentials from enrollment request.
    
    Args:
        request: Validated enrollment request
        
    Returns:
        New server credentials
    """
    return ServerCredentials(
        server_id=request.id,
        api_key=generate_api_key(),
        label=request.label or f"Server-{request.id}",
        created=datetime.now(timezone.utc)
    )

def get_api_key_from_credentials(api_key: str) -> Optional[ServerCredentials]:
    """
    Find server credentials by API key.
    
    Args:
        api_key: API key to search for
        
    Returns:
        ServerCredentials if found, None otherwise
    """
    credentials = load_api_credentials()
    
    for server_id, creds in credentials.items():
        if creds.api_key == api_key:
            return creds
            
    return None

# FastAPI Security
security = HTTPBearer()

async def require_api_key(request: Request, credentials: HTTPAuthorizationCredentials = Depends(security)) -> ServerCredentials:
    """
    FastAPI dependency that requires valid API key authentication.
    
    Args:
        request: FastAPI request object
        credentials: HTTP Bearer credentials
        
    Returns:
        ServerCredentials for the authenticated server
        
    Raises:
        HTTPException: If authentication fails
    """
    if not credentials or not credentials.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing API key",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    server_creds = get_api_key_from_credentials(credentials.credentials)
    if not server_creds:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Log successful authentication (without the actual key)
    logger.debug(f"Authenticated server: {server_creds.server_id} ({server_creds.label})")
    
    return server_creds

def enroll_server(request: EnrollmentRequest) -> EnrollmentResponse:
    """
    Enroll a new server and generate API credentials.
    
    Args:
        request: Enrollment request
        
    Returns:
        Enrollment response with new credentials
        
    Raises:
        HTTPException: If enrollment fails
    """
    # Validate enrollment token
    is_valid, error_msg = validate_enrollment(request)
    if not is_valid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Enrollment failed: {error_msg}"
        )
    
    # Load existing credentials
    existing_credentials = load_api_credentials()
    
    # Check if server is already enrolled
    if request.id in existing_credentials:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Server already enrolled"
        )
    
    # Create new credentials
    server_creds = create_server_credentials(request)
    
    # Save credentials
    existing_credentials[server_creds.server_id] = server_creds
    if not save_api_credentials(existing_credentials):
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to save credentials"
        )
    
    logger.info(f"Successfully enrolled server: {server_creds.server_id} ({server_creds.label})")
    
    return EnrollmentResponse(
        server_id=server_creds.server_id,
        api_key=server_creds.api_key,
        label=server_creds.label
    )

def create_enrollment_token(server_id: str) -> EnrollmentData:
    """
    Create a new enrollment token for server installation.
    
    Args:
        server_id: Unique server identifier
        
    Returns:
        New enrollment data
    """
    enrollment = EnrollmentData(
        id=server_id,
        token=generate_enrollment_token(),
        created=datetime.now(timezone.utc)
    )
    
    if not save_enroll(enrollment):
        raise RuntimeError("Failed to save enrollment token")
    
    return enrollment