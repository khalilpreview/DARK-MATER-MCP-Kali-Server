"""
FastAPI application for MCP Kali Server.
Provides HTTP endpoints for enrollment, health checks, tools, and artifacts.
"""

import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, Optional

from fastapi import FastAPI, HTTPException, Depends, Query, status
from fastapi.responses import JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from .auth import (
    require_api_key, enroll_server, EnrollmentRequest, EnrollmentResponse, 
    ServerCredentials
)
from .tools import list_tools, call_tool
from .artifacts import list_artifacts, read_artifact
from .memory import search_memory, get_observation_stats
from .scope import get_scope_info
from .ngrok_manager import get_ngrok_info, get_ngrok_metrics

logger = logging.getLogger(__name__)

# Request/Response Models
class ToolCallRequest(BaseModel):
    """Request model for tool execution."""
    name: str
    arguments: Dict[str, Any]

class HealthResponse(BaseModel):
    """Health check response model."""
    ok: bool
    server_id: str
    caps: Dict[str, bool]
    time: str
    version: str = "2.0.0"

class ErrorResponse(BaseModel):
    """Error response model."""
    error: str
    detail: Optional[str] = None

# Create FastAPI application
app = FastAPI(
    title="MCP Kali Server",
    description="Production-ready security testing server with enrollment and artifact storage",
    version="2.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# Add CORS middleware for dashboard integration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global exception handler
@app.exception_handler(Exception)
async def global_exception_handler(request, exc):
    """Handle unexpected exceptions gracefully."""
    logger.error(f"Unhandled exception in {request.url}: {exc}", exc_info=True)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "error": "Internal server error",
            "detail": "An unexpected error occurred"
        }
    )

# Mount static files for schemas
schema_dir = Path(__file__).parent / "schemas"
if schema_dir.exists():
    app.mount("/schemas", StaticFiles(directory=str(schema_dir)), name="schemas")

# Enrollment endpoint (public - no authentication required)
@app.post("/enroll", response_model=EnrollmentResponse)
async def enroll_endpoint(request: EnrollmentRequest):
    """
    Enroll a new server and generate API credentials.
    
    This endpoint is public and uses the enrollment token for authentication.
    """
    try:
        logger.info(f"Enrollment request from server: {request.id}")
        response = enroll_server(request)
        logger.info(f"Successfully enrolled server: {response.server_id}")
        return response
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Enrollment error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Enrollment failed due to server error"
        )

# Health check endpoint (requires authentication)
@app.get("/health", response_model=HealthResponse)
async def health_check(server_creds: ServerCredentials = Depends(require_api_key)):
    """
    Health check endpoint with server capabilities.
    
    Returns server status and available capabilities.
    """
    try:
        return HealthResponse(
            ok=True,
            server_id=server_creds.server_id,
            caps={
                "tools": True,
                "artifacts": True,
                "memory": True,
                "scope_validation": True,
                "schema_validation": True
            },
            time=datetime.now(timezone.utc).isoformat()
        )
        
    except Exception as e:
        logger.error(f"Health check error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Health check failed"
        )

# Tools endpoints
@app.get("/tools/list")
async def tools_list_endpoint(server_creds: ServerCredentials = Depends(require_api_key)):
    """
    Get list of available tools with metadata.
    
    Returns tool names, descriptions, and schema references.
    """
    try:
        tools = list_tools()
        return {"tools": tools}
        
    except Exception as e:
        logger.error(f"Tools list error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve tools list"
        )

@app.post("/tools/call")
async def tools_call_endpoint(
    request: ToolCallRequest,
    server_creds: ServerCredentials = Depends(require_api_key)
):
    """
    Execute a tool with the provided arguments.
    
    Validates arguments against schema and checks scope/destructiveness.
    """
    try:
        logger.info(f"Tool call request: {request.name} from server {server_creds.server_id}")
        
        result = call_tool(server_creds.server_id, request.name, request.arguments)
        
        # Log the result (without sensitive data)
        if result.get("rc") == 0:
            logger.info(f"Tool {request.name} executed successfully")
        else:
            logger.warning(f"Tool {request.name} failed: {result.get('summary', 'Unknown error')}")
        
        return result
        
    except Exception as e:
        logger.error(f"Tool call error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Tool execution failed due to server error"
        )

# Artifacts endpoints
@app.get("/artifacts/list")
async def artifacts_list_endpoint(
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    server_creds: ServerCredentials = Depends(require_api_key)
):
    """
    List artifacts for the authenticated server.
    
    Supports pagination with limit and offset parameters.
    """
    try:
        result = list_artifacts(server_creds.server_id, limit, offset)
        return result
        
    except Exception as e:
        logger.error(f"Artifacts list error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve artifacts list"
        )

@app.get("/artifacts/read")
async def artifacts_read_endpoint(
    uri: str = Query(..., description="Artifact URI to read"),
    server_creds: ServerCredentials = Depends(require_api_key)
):
    """
    Read artifact content by URI.
    
    Validates that the artifact belongs to the authenticated server.
    """
    try:
        # Validate that the URI belongs to this server
        if not uri.startswith(f"artifact://{server_creds.server_id}/"):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied: artifact does not belong to this server"
            )
        
        artifact = read_artifact(uri)
        if not artifact:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Artifact not found"
            )
        
        # Return appropriate response based on content type
        content_type = artifact.get("content_type", "text/plain")
        
        if content_type == "application/json":
            return artifact["content"]
        else:
            return PlainTextResponse(
                content=artifact["content"],
                media_type=content_type
            )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Artifact read error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to read artifact"
        )

# Memory endpoints
@app.get("/memory/search")
async def memory_search_endpoint(
    query: Optional[str] = Query(None, description="Search query"),
    kind: Optional[str] = Query(None, description="Observation kind filter"),
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    server_creds: ServerCredentials = Depends(require_api_key)
):
    """
    Search memory observations for the authenticated server.
    
    Supports text search and filtering by observation kind.
    """
    try:
        result = search_memory(server_creds.server_id, query, kind, limit, offset)
        return result
        
    except Exception as e:
        logger.error(f"Memory search error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to search memory"
        )

@app.get("/memory/stats")
async def memory_stats_endpoint(server_creds: ServerCredentials = Depends(require_api_key)):
    """
    Get memory statistics for the authenticated server.
    
    Returns counts and breakdowns of stored observations.
    """
    try:
        stats = get_observation_stats(server_creds.server_id)
        return stats
        
    except Exception as e:
        logger.error(f"Memory stats error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve memory statistics"
        )

# Configuration endpoints
@app.get("/config/scope")
async def scope_config_endpoint(server_creds: ServerCredentials = Depends(require_api_key)):
    """
    Get current scope configuration.
    
    Returns allowed CIDRs and destructive operation settings.
    """
    try:
        scope_info = get_scope_info()
        return scope_info
        
    except Exception as e:
        logger.error(f"Scope config error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve scope configuration"
        )

# Ngrok endpoints
@app.get("/ngrok/info")
async def ngrok_info_endpoint(server_creds: ServerCredentials = Depends(require_api_key)):
    """
    Get ngrok tunnel information.
    
    Returns current tunnel status and public URL.
    """
    try:
        ngrok_info = get_ngrok_info()
        return ngrok_info
        
    except Exception as e:
        logger.error(f"Ngrok info error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve ngrok information"
        )

@app.get("/ngrok/metrics")
async def ngrok_metrics_endpoint(server_creds: ServerCredentials = Depends(require_api_key)):
    """
    Get ngrok tunnel metrics.
    
    Returns connection and traffic statistics if available.
    """
    try:
        metrics = get_ngrok_metrics()
        if metrics:
            return metrics
        else:
            return {"message": "Metrics not available"}
        
    except Exception as e:
        logger.error(f"Ngrok metrics error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve ngrok metrics"
        )

# Server information endpoint
@app.get("/info")
async def server_info_endpoint(server_creds: ServerCredentials = Depends(require_api_key)):
    """
    Get server information and statistics.
    
    Returns comprehensive server status and usage statistics.
    """
    try:
        # Get memory stats
        memory_stats = get_observation_stats(server_creds.server_id)
        
        # Get artifacts count
        artifacts_info = list_artifacts(server_creds.server_id, limit=1)
        
        # Get scope info
        scope_info = get_scope_info()
        
        # Get ngrok info
        ngrok_info = get_ngrok_info()
        
        return {
            "server_id": server_creds.server_id,
            "label": server_creds.label,
            "enrolled_at": server_creds.created.isoformat(),
            "memory_stats": memory_stats,
            "artifacts_count": artifacts_info.get("total", 0),
            "scope_config": scope_info,
            "available_tools": len(list_tools()),
            "ngrok_tunnel": ngrok_info,
            "server_time": datetime.now(timezone.utc).isoformat()
        }
        
    except Exception as e:
        logger.error(f"Server info error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve server information"
        )

# Root endpoint
@app.get("/")
async def root():
    """Root endpoint with basic server information."""
    return {
        "name": "MCP Kali Server",
        "version": "2.0.0",
        "description": "Production-ready security testing server",
        "endpoints": {
            "enrollment": "/enroll",
            "health": "/health",
            "tools": "/tools/list",
            "artifacts": "/artifacts/list",
            "memory": "/memory/search",
            "documentation": "/docs"
        }
    }

# Additional utility endpoints for dashboard integration
@app.get("/status")
async def status_endpoint():
    """
    Public status endpoint for basic health monitoring.
    
    Does not require authentication - suitable for load balancers.
    """
    try:
        return {
            "status": "healthy",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "version": "2.0.0"
        }
    except Exception as e:
        logger.error(f"Status check error: {e}")
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"status": "unhealthy", "error": str(e)}
        )

# Startup event handler
@app.on_event("startup")
async def startup_event():
    """Initialize server on startup."""
    logger.info("MCP Kali Server starting up...")
    
    # Ensure scope configuration exists
    try:
        from .scope import ensure_scope_config
        ensure_scope_config()
    except Exception as e:
        logger.error(f"Error initializing scope config: {e}")
    
    logger.info("MCP Kali Server startup complete")

# Shutdown event handler
@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on server shutdown."""
    logger.info("MCP Kali Server shutting down...")
    
    # Perform any necessary cleanup
    try:
        # Clean up old memory observations (keep last 30 days)
        from .memory import memory_manager
        cleaned = memory_manager.cleanup_old_observations(30)
        if cleaned > 0:
            logger.info(f"Cleaned up {cleaned} old observations during shutdown")
    except Exception as e:
        logger.error(f"Error during shutdown cleanup: {e}")
    
    logger.info("MCP Kali Server shutdown complete")

# Export the app for uvicorn
__all__ = ["app"]