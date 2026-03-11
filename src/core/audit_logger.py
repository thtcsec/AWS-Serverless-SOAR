"""
AWS SOAR — Audit Logger
Logs all SOAR actions to a structured, immutable audit trail.
Every containment, investigation, and decision action is recorded
with timestamp, actor, action type, target resource, and result.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from enum import Enum

logger = logging.getLogger("aws-soar.audit")


class AuditAction(str, Enum):
    """Enumeration of auditable SOAR actions."""
    ISOLATE_NETWORK = "ISOLATE_NETWORK"
    KILL_PROCESS = "KILL_PROCESS"
    QUARANTINE_FILE = "QUARANTINE_FILE"
    REVOKE_CREDENTIALS = "REVOKE_CREDENTIALS"
    DISABLE_ACCESS_KEY = "DISABLE_ACCESS_KEY"
    ATTACH_DENY_POLICY = "ATTACH_DENY_POLICY"
    SNAPSHOT_VOLUME = "SNAPSHOT_VOLUME"
    STOP_INSTANCE = "STOP_INSTANCE"
    THREAT_INTEL_LOOKUP = "THREAT_INTEL_LOOKUP"
    SCORING_DECISION = "SCORING_DECISION"
    APPROVAL_REQUESTED = "APPROVAL_REQUESTED"
    APPROVAL_GRANTED = "APPROVAL_GRANTED"
    APPROVAL_DENIED = "APPROVAL_DENIED"
    PLAYBOOK_STARTED = "PLAYBOOK_STARTED"
    PLAYBOOK_COMPLETED = "PLAYBOOK_COMPLETED"
    PLAYBOOK_FAILED = "PLAYBOOK_FAILED"


class AuditEntry:
    """A single audit log entry."""

    def __init__(
        self,
        action: AuditAction,
        resource_id: str,
        actor: str = "SOAR_SYSTEM",
        details: Optional[Dict[str, Any]] = None,
        success: bool = True,
    ) -> None:
        self.timestamp = datetime.now(timezone.utc).isoformat()
        self.action = action
        self.resource_id = resource_id
        self.actor = actor
        self.details = details or {}
        self.success = success

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "action": self.action.value,
            "resource_id": self.resource_id,
            "actor": self.actor,
            "success": self.success,
            "details": self.details,
        }


class AuditLogger:
    """
    Structured audit logger for all SOAR operations.
    Supports local in-memory log, CloudWatch Logs, and S3 archival.
    """

    def __init__(self, cloudwatch_client: Any = None, s3_client: Any = None) -> None:
        self._entries: List[AuditEntry] = []
        self._cw = cloudwatch_client
        self._s3 = s3_client
        self._log_group = "/soar/audit-trail"

    def log(
        self,
        action: AuditAction,
        resource_id: str,
        actor: str = "SOAR_SYSTEM",
        details: Optional[Dict[str, Any]] = None,
        success: bool = True,
    ) -> AuditEntry:
        """Record a SOAR action to the audit trail."""
        entry = AuditEntry(
            action=action,
            resource_id=resource_id,
            actor=actor,
            details=details,
            success=success,
        )
        self._entries.append(entry)
        logger.info(
            f"AUDIT | {entry.action.value} | {resource_id} | "
            f"{'OK' if success else 'FAIL'} | {actor}"
        )

        if self._cw:
            self._write_to_cloudwatch(entry)

        return entry

    def get_entries(
        self,
        resource_id: Optional[str] = None,
        action: Optional[AuditAction] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """Retrieve audit entries with optional filtering."""
        filtered = self._entries
        if resource_id:
            filtered = [e for e in filtered if e.resource_id == resource_id]
        if action:
            filtered = [e for e in filtered if e.action == action]
        return [e.to_dict() for e in filtered[-limit:]]

    def get_summary(self) -> Dict[str, Any]:
        """Get a summary of all audit activity."""
        total = len(self._entries)
        success_count = sum(1 for e in self._entries if e.success)
        actions: Dict[str, int] = {}
        for entry in self._entries:
            key = entry.action.value
            actions[key] = actions.get(key, 0) + 1

        return {
            "total_entries": total,
            "success_count": success_count,
            "failure_count": total - success_count,
            "actions_breakdown": actions,
        }

    def export_to_s3(self, bucket: str, prefix: str = "audit/") -> bool:
        """Archive audit entries to S3 for long-term retention."""
        if not self._s3 or not self._entries:
            return False

        try:
            ts = datetime.now(timezone.utc).strftime("%Y/%m/%d/%H%M%S")
            key = f"{prefix}{ts}-audit.json"
            body = json.dumps(
                [e.to_dict() for e in self._entries], indent=2
            )
            self._s3.put_object(Bucket=bucket, Key=key, Body=body)
            logger.info(f"Exported {len(self._entries)} audit entries to s3://{bucket}/{key}")
            return True
        except Exception as e:
            logger.error(f"Failed to export audit to S3: {e}")
            return False

    def _write_to_cloudwatch(self, entry: AuditEntry) -> None:
        """Write a single audit entry to CloudWatch Logs."""
        try:
            self._cw.put_log_events(
                logGroupName=self._log_group,
                logStreamName="soar-actions",
                logEvents=[{
                    "timestamp": int(
                        datetime.fromisoformat(entry.timestamp).timestamp() * 1000
                    ),
                    "message": json.dumps(entry.to_dict()),
                }],
            )
        except Exception as e:
            logger.warning(f"CloudWatch write failed (non-fatal): {e}")
