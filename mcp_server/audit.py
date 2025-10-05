"""
Enhanced audit logging system for MCP Kali Server.
Provides comprehensive audit trail for compliance and security monitoring.
"""

import json
import logging
import sqlite3
import hashlib
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List
from pydantic import BaseModel
from enum import Enum

logger = logging.getLogger(__name__)

class AuditEventType(str, Enum):
    """Types of audit events."""
    AUTHENTICATION = "authentication"
    TOOL_EXECUTION = "tool_execution" 
    API_ACCESS = "api_access"
    CONFIGURATION_CHANGE = "configuration_change"
    SECURITY_VIOLATION = "security_violation"
    SYSTEM_EVENT = "system_event"

class AuditSeverity(str, Enum):
    """Audit event severity levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class AuditEvent(BaseModel):
    """Audit event model."""
    timestamp: datetime
    event_type: AuditEventType
    severity: AuditSeverity
    user_id: Optional[str] = None
    client_ip: Optional[str] = None
    action: str
    resource: Optional[str] = None
    details: Dict[str, Any] = {}
    success: bool = True
    error_message: Optional[str] = None

class AuditLogger:
    """Enhanced audit logging system."""
    
    def __init__(self, db_path: Path = None):
        if db_path is None:
            # Use platform-appropriate path
            import os
            if os.name == 'nt':  # Windows
                db_dir = Path.home() / ".mcp-kali" / "audit"
            else:  # Linux/Unix
                db_dir = Path("/var/lib/mcp/audit")
            
            db_dir.mkdir(parents=True, exist_ok=True)
            self.db_path = db_dir / "audit.db"
        else:
            self.db_path = db_path
            
        self._init_database()
    
    def _init_database(self):
        """Initialize audit database."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS audit_events (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp TEXT NOT NULL,
                        event_type TEXT NOT NULL,
                        severity TEXT NOT NULL,
                        user_id TEXT,
                        client_ip TEXT,
                        action TEXT NOT NULL,
                        resource TEXT,
                        details TEXT,
                        success BOOLEAN NOT NULL,
                        error_message TEXT,
                        hash TEXT NOT NULL,
                        created_at TEXT DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                
                # Create indices for performance
                conn.execute("CREATE INDEX IF NOT EXISTS idx_timestamp ON audit_events(timestamp)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_event_type ON audit_events(event_type)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_user_id ON audit_events(user_id)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_severity ON audit_events(severity)")
                
                conn.commit()
                logger.info(f"Audit database initialized at {self.db_path}")
                
        except Exception as e:
            logger.error(f"Failed to initialize audit database: {e}")
            raise
    
    def _calculate_hash(self, event: AuditEvent) -> str:
        """Calculate hash for audit event integrity."""
        data = f"{event.timestamp.isoformat()}{event.event_type}{event.action}{event.user_id or ''}{event.success}"
        return hashlib.sha256(data.encode()).hexdigest()[:16]
    
    async def log_event(self, event: AuditEvent) -> bool:
        """
        Log an audit event.
        
        Args:
            event: Audit event to log
            
        Returns:
            True if successfully logged, False otherwise
        """
        try:
            event_hash = self._calculate_hash(event)
            details_json = json.dumps(event.details) if event.details else "{}"
            
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    INSERT INTO audit_events (
                        timestamp, event_type, severity, user_id, client_ip,
                        action, resource, details, success, error_message, hash
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    event.timestamp.isoformat(),
                    event.event_type.value,
                    event.severity.value,
                    event.user_id,
                    event.client_ip,
                    event.action,
                    event.resource,
                    details_json,
                    event.success,
                    event.error_message,
                    event_hash
                ))
                conn.commit()
            
            # Also log to application logger for immediate visibility
            log_level = {
                AuditSeverity.LOW: logging.INFO,
                AuditSeverity.MEDIUM: logging.WARNING,
                AuditSeverity.HIGH: logging.ERROR,
                AuditSeverity.CRITICAL: logging.CRITICAL
            }.get(event.severity, logging.INFO)
            
            logger.log(log_level, f"AUDIT: {event.action} - {event.event_type.value} - Success: {event.success}")
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to log audit event: {e}")
            return False
    
    async def log_authentication(self, user_id: str, success: bool, client_ip: str, details: Dict[str, Any] = None):
        """Log authentication event."""
        event = AuditEvent(
            timestamp=datetime.now(timezone.utc),
            event_type=AuditEventType.AUTHENTICATION,
            severity=AuditSeverity.MEDIUM if success else AuditSeverity.HIGH,
            user_id=user_id,
            client_ip=client_ip,
            action="login_attempt",
            success=success,
            details=details or {}
        )
        await self.log_event(event)
    
    async def log_tool_execution(self, user_id: str, tool_name: str, target: str, success: bool, 
                               duration: float, client_ip: str, error_message: str = None):
        """Log tool execution event."""
        severity = AuditSeverity.LOW if success else AuditSeverity.MEDIUM
        
        event = AuditEvent(
            timestamp=datetime.now(timezone.utc),
            event_type=AuditEventType.TOOL_EXECUTION,
            severity=severity,
            user_id=user_id,
            client_ip=client_ip,
            action=f"execute_{tool_name}",
            resource=target,
            success=success,
            error_message=error_message,
            details={
                "tool_name": tool_name,
                "target": target,
                "duration_seconds": duration
            }
        )
        await self.log_event(event)
    
    async def log_api_access(self, user_id: str, endpoint: str, method: str, status_code: int, 
                           client_ip: str, duration: float):
        """Log API access event."""
        success = 200 <= status_code < 400
        severity = AuditSeverity.LOW if success else AuditSeverity.MEDIUM
        
        event = AuditEvent(
            timestamp=datetime.now(timezone.utc),
            event_type=AuditEventType.API_ACCESS,
            severity=severity,
            user_id=user_id,
            client_ip=client_ip,
            action=f"{method}_{endpoint}",
            resource=endpoint,
            success=success,
            details={
                "method": method,
                "endpoint": endpoint,
                "status_code": status_code,
                "duration_seconds": duration
            }
        )
        await self.log_event(event)
    
    async def log_security_violation(self, user_id: str, violation_type: str, target: str, 
                                   client_ip: str, details: Dict[str, Any]):
        """Log security violation."""
        event = AuditEvent(
            timestamp=datetime.now(timezone.utc),
            event_type=AuditEventType.SECURITY_VIOLATION,
            severity=AuditSeverity.HIGH,
            user_id=user_id,
            client_ip=client_ip,
            action=f"security_violation_{violation_type}",
            resource=target,
            success=False,
            details=details
        )
        await self.log_event(event)
    
    async def log_configuration_change(self, user_id: str, config_type: str, changes: Dict[str, Any], 
                                     client_ip: str):
        """Log configuration change."""
        event = AuditEvent(
            timestamp=datetime.now(timezone.utc),
            event_type=AuditEventType.CONFIGURATION_CHANGE,
            severity=AuditSeverity.MEDIUM,
            user_id=user_id,
            client_ip=client_ip,
            action=f"config_change_{config_type}",
            resource=config_type,
            success=True,
            details=changes
        )
        await self.log_event(event)
    
    async def search_events(self, 
                          event_type: Optional[AuditEventType] = None,
                          user_id: Optional[str] = None,
                          severity: Optional[AuditSeverity] = None,
                          start_time: Optional[datetime] = None,
                          end_time: Optional[datetime] = None,
                          limit: int = 100,
                          offset: int = 0) -> List[Dict[str, Any]]:
        """
        Search audit events with filters.
        
        Returns:
            List of matching audit events
        """
        try:
            query = "SELECT * FROM audit_events WHERE 1=1"
            params = []
            
            if event_type:
                query += " AND event_type = ?"
                params.append(event_type.value)
                
            if user_id:
                query += " AND user_id = ?"
                params.append(user_id)
                
            if severity:
                query += " AND severity = ?"
                params.append(severity.value)
                
            if start_time:
                query += " AND timestamp >= ?"
                params.append(start_time.isoformat())
                
            if end_time:
                query += " AND timestamp <= ?"
                params.append(end_time.isoformat())
            
            query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
            params.extend([limit, offset])
            
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.execute(query, params)
                rows = cursor.fetchall()
                
                events = []
                for row in rows:
                    event_dict = dict(row)
                    # Parse JSON details
                    if event_dict['details']:
                        try:
                            event_dict['details'] = json.loads(event_dict['details'])
                        except json.JSONDecodeError:
                            event_dict['details'] = {}
                    events.append(event_dict)
                
                return events
                
        except Exception as e:
            logger.error(f"Error searching audit events: {e}")
            return []
    
    async def get_event_statistics(self, days: int = 7) -> Dict[str, Any]:
        """Get audit event statistics for the last N days."""
        try:
            start_time = datetime.now(timezone.utc) - timedelta(days=days)
            
            with sqlite3.connect(self.db_path) as conn:
                # Total events
                total_query = "SELECT COUNT(*) FROM audit_events WHERE timestamp >= ?"
                total_events = conn.execute(total_query, (start_time.isoformat(),)).fetchone()[0]
                
                # Events by type
                type_query = """
                    SELECT event_type, COUNT(*) as count 
                    FROM audit_events 
                    WHERE timestamp >= ? 
                    GROUP BY event_type
                """
                type_results = conn.execute(type_query, (start_time.isoformat(),)).fetchall()
                
                # Events by severity
                severity_query = """
                    SELECT severity, COUNT(*) as count 
                    FROM audit_events 
                    WHERE timestamp >= ? 
                    GROUP BY severity
                """
                severity_results = conn.execute(severity_query, (start_time.isoformat(),)).fetchall()
                
                # Failed events
                failed_query = """
                    SELECT COUNT(*) FROM audit_events 
                    WHERE timestamp >= ? AND success = 0
                """
                failed_events = conn.execute(failed_query, (start_time.isoformat(),)).fetchone()[0]
                
                return {
                    "total_events": total_events,
                    "failed_events": failed_events,
                    "success_rate": (total_events - failed_events) / total_events if total_events > 0 else 1.0,
                    "events_by_type": {row[0]: row[1] for row in type_results},
                    "events_by_severity": {row[0]: row[1] for row in severity_results},
                    "period_days": days
                }
                
        except Exception as e:
            logger.error(f"Error getting audit statistics: {e}")
            return {"error": str(e)}

# Global audit logger instance
audit_logger = AuditLogger()