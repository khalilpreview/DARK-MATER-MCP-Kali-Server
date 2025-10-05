"""
Webhook system for MCP Kali Server.
Provides real-time notifications and integrations with external systems.
"""

import json
import asyncio
import logging
import httpx
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from pathlib import Path
from pydantic import BaseModel, HttpUrl
from enum import Enum

from .util import safe_json_load, safe_json_save

logger = logging.getLogger(__name__)

class WebhookEventType(str, Enum):
    """Types of webhook events."""
    SCAN_STARTED = "scan_started"
    SCAN_COMPLETED = "scan_completed"
    SCAN_FAILED = "scan_failed"
    SECURITY_ALERT = "security_alert"
    HIGH_SEVERITY_FINDING = "high_severity_finding"
    SYSTEM_ERROR = "system_error"
    LICENSE_EXPIRING = "license_expiring"

class WebhookConfig(BaseModel):
    """Webhook configuration model."""
    id: str
    name: str
    url: HttpUrl
    secret: Optional[str] = None
    events: List[WebhookEventType]
    enabled: bool = True
    retry_attempts: int = 3
    timeout_seconds: int = 10

class WebhookEvent(BaseModel):
    """Webhook event payload."""
    event_type: WebhookEventType
    timestamp: datetime
    server_id: str
    data: Dict[str, Any]
    event_id: str

class WebhookManager:
    """Manages webhook configurations and delivery."""
    
    def __init__(self):
        # Platform-appropriate config directory
        import os
        if os.name == 'nt':  # Windows
            self.config_dir = Path.home() / ".mcp-kali" / "webhooks"
        else:  # Linux/Unix
            self.config_dir = Path("/etc/mcp-kali/webhooks")
        
        self.config_dir.mkdir(parents=True, exist_ok=True)
        self.webhooks_file = self.config_dir / "webhooks.json"
        self.delivery_log = self.config_dir / "delivery.log"
        
        # Load existing webhooks
        self.webhooks: Dict[str, WebhookConfig] = {}
        self._load_webhooks()
    
    def _load_webhooks(self):
        """Load webhook configurations from disk."""
        try:
            if self.webhooks_file.exists():
                data = safe_json_load(self.webhooks_file) or {}
                for webhook_id, webhook_data in data.items():
                    self.webhooks[webhook_id] = WebhookConfig(**webhook_data)
                
                logger.info(f"Loaded {len(self.webhooks)} webhook configurations")
            
        except Exception as e:
            logger.error(f"Error loading webhooks: {e}")
    
    def _save_webhooks(self):
        """Save webhook configurations to disk."""
        try:
            data = {}
            for webhook_id, webhook in self.webhooks.items():
                data[webhook_id] = webhook.model_dump()
            
            safe_json_save(self.webhooks_file, data)
            
        except Exception as e:
            logger.error(f"Error saving webhooks: {e}")
    
    def add_webhook(self, webhook: WebhookConfig) -> bool:
        """Add a new webhook configuration."""
        try:
            self.webhooks[webhook.id] = webhook
            self._save_webhooks()
            logger.info(f"Added webhook: {webhook.name} ({webhook.id})")
            return True
            
        except Exception as e:
            logger.error(f"Error adding webhook: {e}")
            return False
    
    def remove_webhook(self, webhook_id: str) -> bool:
        """Remove a webhook configuration."""
        try:
            if webhook_id in self.webhooks:
                webhook_name = self.webhooks[webhook_id].name
                del self.webhooks[webhook_id]
                self._save_webhooks()
                logger.info(f"Removed webhook: {webhook_name} ({webhook_id})")
                return True
            return False
            
        except Exception as e:
            logger.error(f"Error removing webhook: {e}")
            return False
    
    def update_webhook(self, webhook_id: str, updates: Dict[str, Any]) -> bool:
        """Update webhook configuration."""
        try:
            if webhook_id not in self.webhooks:
                return False
            
            webhook = self.webhooks[webhook_id]
            
            # Update fields
            for field, value in updates.items():
                if hasattr(webhook, field):
                    setattr(webhook, field, value)
            
            self._save_webhooks()
            logger.info(f"Updated webhook: {webhook.name} ({webhook_id})")
            return True
            
        except Exception as e:
            logger.error(f"Error updating webhook: {e}")
            return False
    
    def list_webhooks(self) -> List[Dict[str, Any]]:
        """List all webhook configurations."""
        return [
            {
                "id": webhook_id,
                **webhook.model_dump()
            }
            for webhook_id, webhook in self.webhooks.items()
        ]
    
    async def send_event(self, event: WebhookEvent) -> Dict[str, Any]:
        """
        Send webhook event to all matching webhooks.
        
        Returns:
            Dictionary with delivery results
        """
        results = {}
        
        # Find matching webhooks
        matching_webhooks = [
            (webhook_id, webhook)
            for webhook_id, webhook in self.webhooks.items()
            if webhook.enabled and event.event_type in webhook.events
        ]
        
        if not matching_webhooks:
            logger.debug(f"No webhooks configured for event: {event.event_type}")
            return {"delivered": 0, "failed": 0}
        
        # Send to matching webhooks
        delivery_tasks = []
        for webhook_id, webhook in matching_webhooks:
            task = asyncio.create_task(
                self._deliver_webhook(webhook_id, webhook, event)
            )
            delivery_tasks.append(task)
        
        # Wait for all deliveries
        delivery_results = await asyncio.gather(*delivery_tasks, return_exceptions=True)
        
        # Count results
        delivered = 0
        failed = 0
        
        for i, result in enumerate(delivery_results):
            webhook_id = matching_webhooks[i][0]
            if isinstance(result, Exception):
                logger.error(f"Webhook delivery failed: {webhook_id} - {result}")
                failed += 1
                results[webhook_id] = {"success": False, "error": str(result)}
            elif result:
                delivered += 1
                results[webhook_id] = {"success": True}
            else:
                failed += 1
                results[webhook_id] = {"success": False, "error": "Delivery failed"}
        
        logger.info(f"Webhook event {event.event_type} delivered to {delivered}/{len(matching_webhooks)} webhooks")
        
        return {
            "delivered": delivered,
            "failed": failed,
            "total": len(matching_webhooks),
            "results": results
        }
    
    async def _deliver_webhook(self, webhook_id: str, webhook: WebhookConfig, event: WebhookEvent) -> bool:
        """Deliver webhook event to a single webhook endpoint."""
        try:
            # Prepare payload
            payload = {
                "event_type": event.event_type.value,
                "timestamp": event.timestamp.isoformat(),
                "server_id": event.server_id,
                "event_id": event.event_id,
                "data": event.data
            }
            
            # Add signature if secret is configured
            headers = {"Content-Type": "application/json"}
            if webhook.secret:
                import hmac
                import hashlib
                
                payload_json = json.dumps(payload, sort_keys=True)
                signature = hmac.new(
                    webhook.secret.encode(),
                    payload_json.encode(),
                    hashlib.sha256
                ).hexdigest()
                headers["X-Webhook-Signature"] = f"sha256={signature}"
            
            # Deliver webhook with retries
            for attempt in range(webhook.retry_attempts):
                try:
                    async with httpx.AsyncClient(timeout=webhook.timeout_seconds) as client:
                        response = await client.post(
                            str(webhook.url),
                            json=payload,
                            headers=headers
                        )
                        
                        if response.status_code < 400:
                            self._log_delivery(webhook_id, event, True, response.status_code)
                            return True
                        else:
                            logger.warning(f"Webhook {webhook_id} returned {response.status_code}")
                            
                except httpx.TimeoutException:
                    logger.warning(f"Webhook {webhook_id} timed out (attempt {attempt + 1})")
                except httpx.RequestError as e:
                    logger.warning(f"Webhook {webhook_id} request failed: {e} (attempt {attempt + 1})")
                
                # Wait before retry (exponential backoff)
                if attempt < webhook.retry_attempts - 1:
                    await asyncio.sleep(2 ** attempt)
            
            # All attempts failed
            self._log_delivery(webhook_id, event, False, 0)
            return False
            
        except Exception as e:
            logger.error(f"Error delivering webhook {webhook_id}: {e}")
            self._log_delivery(webhook_id, event, False, 0, str(e))
            return False
    
    def _log_delivery(self, webhook_id: str, event: WebhookEvent, success: bool, 
                     status_code: int = 0, error: str = None):
        """Log webhook delivery attempt."""
        try:
            log_entry = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "webhook_id": webhook_id,
                "event_type": event.event_type.value,
                "event_id": event.event_id,
                "success": success,
                "status_code": status_code,
                "error": error
            }
            
            with open(self.delivery_log, 'a') as f:
                f.write(json.dumps(log_entry) + '\n')
                
        except Exception as e:
            logger.error(f"Error logging webhook delivery: {e}")
    
    async def send_scan_completed(self, server_id: str, tool_name: str, target: str, 
                                findings: List[Dict[str, Any]], artifact_uri: str = None):
        """Send scan completed webhook event."""
        import uuid
        
        event = WebhookEvent(
            event_type=WebhookEventType.SCAN_COMPLETED,
            timestamp=datetime.now(timezone.utc),
            server_id=server_id,
            event_id=str(uuid.uuid4()),
            data={
                "tool_name": tool_name,
                "target": target,
                "findings_count": len(findings),
                "high_severity_count": len([f for f in findings if f.get("severity") in ["high", "critical"]]),
                "artifact_uri": artifact_uri,
                "findings": findings[:10]  # Send first 10 findings
            }
        )
        
        return await self.send_event(event)
    
    async def send_security_alert(self, server_id: str, alert_type: str, details: Dict[str, Any]):
        """Send security alert webhook event."""
        import uuid
        
        event = WebhookEvent(
            event_type=WebhookEventType.SECURITY_ALERT,
            timestamp=datetime.now(timezone.utc),
            server_id=server_id,
            event_id=str(uuid.uuid4()),
            data={
                "alert_type": alert_type,
                "severity": details.get("severity", "medium"),
                "details": details
            }
        )
        
        return await self.send_event(event)
    
    async def send_high_severity_finding(self, server_id: str, tool_name: str, 
                                       finding: Dict[str, Any]):
        """Send high severity finding webhook event."""
        import uuid
        
        event = WebhookEvent(
            event_type=WebhookEventType.HIGH_SEVERITY_FINDING,
            timestamp=datetime.now(timezone.utc),
            server_id=server_id,
            event_id=str(uuid.uuid4()),
            data={
                "tool_name": tool_name,
                "finding": finding,
                "severity": finding.get("severity", "unknown")
            }
        )
        
        return await self.send_event(event)

# Global webhook manager instance
webhook_manager = WebhookManager()

# Convenience functions for common webhook events
async def notify_scan_completed(server_id: str, tool_name: str, target: str, 
                              findings: List[Dict[str, Any]], artifact_uri: str = None):
    """Notify external systems that a scan has completed."""
    return await webhook_manager.send_scan_completed(
        server_id, tool_name, target, findings, artifact_uri
    )

async def notify_security_alert(server_id: str, alert_type: str, details: Dict[str, Any]):
    """Send security alert notification."""
    return await webhook_manager.send_security_alert(server_id, alert_type, details)

async def notify_high_severity_finding(server_id: str, tool_name: str, finding: Dict[str, Any]):
    """Notify about high severity security findings."""
    return await webhook_manager.send_high_severity_finding(server_id, tool_name, finding)