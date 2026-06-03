"""
Audit Logging Module
Implements comprehensive audit logging for HIPAA compliance.
"""

import os
import logging
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Dict, Any
from enum import Enum


class AuditEventType(str, Enum):
    """HIPAA-relevant audit event types"""
    ACCESS = "access"
    CREATE = "create"
    UPDATE = "update"
    DELETE = "delete"
    EXPORT = "export"
    LOGIN = "login"
    LOGOUT = "logout"
    FAILED_LOGIN = "failed_login"
    PERMISSION_DENIED = "permission_denied"
    CONSENT_GIVEN = "consent_given"
    CONSENT_REVOKED = "consent_revoked"


class AuditLogger:
    """
    HIPAA-compliant audit logging.
    
    Implements requirements from:
    - 164.312(b) Audit Controls
    - 164.308(a)(1)(ii)(D) Information System Activity Review
    
    Logs:
    - Who (user/system)
    - What (action)
    - When (timestamp)
    - Where (resource/PHI)
    - Result (success/failure)
    - Context (metadata)
    """
    
    def __init__(self, log_file: Optional[Path] = None):
        """
        Initialize audit logger.
        
        Args:
            log_file: Path to audit log file
        """
        self.log_file = log_file or Path(os.getenv("AUDIT_LOG_PATH", "./logs/audit.log"))
        self.log_file.parent.mkdir(parents=True, exist_ok=True)
        
        # Setup file handler for audit log
        self.logger = logging.getLogger("audit")
        self.logger.setLevel(logging.INFO)

        # Keep audit records out of the root logger / console. Without this,
        # logging.basicConfig() elsewhere causes every audit event (including
        # PHI-bearing resource names) to leak to stderr and be duplicated.
        self.logger.propagate = False

        # Avoid attaching duplicate handlers if the logger is reconfigured.
        if not any(isinstance(h, logging.FileHandler) for h in self.logger.handlers):
            # Create file handler
            handler = logging.FileHandler(self.log_file)
            handler.setLevel(logging.INFO)

            # Format: JSON for structured logging
            formatter = logging.Formatter('%(message)s')
            handler.setFormatter(formatter)

            self.logger.addHandler(handler)
    
    def log_event(
        self,
        event_type: AuditEventType,
        user_id: str,
        resource: str,
        action: str,
        result: str = "success",
        metadata: Optional[Dict[str, Any]] = None
    ):
        """
        Log an audit event.
        
        Args:
            event_type: Type of event
            user_id: User or system identifier
            resource: Resource accessed (PHI record, claim, etc.)
            action: Specific action performed
            result: success|failure|denied
            metadata: Additional context
        """
        event = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": event_type.value,
            "user_id": user_id,
            "resource": resource,
            "action": action,
            "result": result,
            "metadata": metadata or {}
        }
        
        # Log as JSON
        self.logger.info(json.dumps(event))
    
    def log_access(
        self,
        user_id: str,
        resource: str,
        access_type: str = "read",
        **metadata
    ):
        """Log PHI access event"""
        self.log_event(
            event_type=AuditEventType.ACCESS,
            user_id=user_id,
            resource=resource,
            action=f"access_{access_type}",
            metadata=metadata
        )
    
    def log_phi_operation(
        self,
        user_id: str,
        operation: str,
        record_id: str,
        success: bool = True,
        **metadata
    ):
        """Log PHI create/update/delete operation"""
        result = "success" if success else "failure"
        
        event_map = {
            "create": AuditEventType.CREATE,
            "update": AuditEventType.UPDATE,
            "delete": AuditEventType.DELETE,
            "export": AuditEventType.EXPORT
        }
        
        self.log_event(
            event_type=event_map.get(operation, AuditEventType.ACCESS),
            user_id=user_id,
            resource=f"phi_record:{record_id}",
            action=operation,
            result=result,
            metadata=metadata
        )
    
    def log_consent(
        self,
        user_id: str,
        consent_type: str,
        granted: bool,
        **metadata
    ):
        """Log consent given or revoked"""
        event_type = AuditEventType.CONSENT_GIVEN if granted else AuditEventType.CONSENT_REVOKED
        
        self.log_event(
            event_type=event_type,
            user_id=user_id,
            resource="consent",
            action=consent_type,
            metadata=metadata
        )
    
    def log_authentication(
        self,
        user_id: str,
        success: bool,
        method: str = "password",
        **metadata
    ):
        """Log authentication attempt"""
        event_type = AuditEventType.LOGIN if success else AuditEventType.FAILED_LOGIN
        result = "success" if success else "failure"
        
        self.log_event(
            event_type=event_type,
            user_id=user_id,
            resource="authentication",
            action=f"login_{method}",
            result=result,
            metadata=metadata
        )


# Global audit logger instance
_audit_logger = None


def get_audit_logger() -> AuditLogger:
    """Get or create global audit logger"""
    global _audit_logger
    if _audit_logger is None:
        _audit_logger = AuditLogger()
    return _audit_logger
