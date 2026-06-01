"""
AWS SOAR — Unified Incident Pipeline
Single processing spine for all security events.

Event → Normalize → Correlate → Score → Decision → Playbook → Execute → Audit
"""

from __future__ import annotations

import logging
from typing import Any

from src.core.audit_logger import AuditAction, AuditLogger, get_audit_logger
from src.core.correlator import IncidentCorrelator
from src.core.event_normalizer import EventNormalizer, UnifiedIncident
from src.core.policy import PolicyEngine
from src.integrations.slack_notifier import SlackNotifier
from src.playbooks.registry import PlaybookRegistry

logger = logging.getLogger("aws-soar.pipeline")

_correlator = IncidentCorrelator()


class IncidentPipeline:
    """Orchestrates the full incident lifecycle. Handlers delegate here."""

    def __init__(
        self,
        registry: PlaybookRegistry,
        policy: PolicyEngine | None = None,
        audit: AuditLogger | None = None,
        correlator: IncidentCorrelator | None = None,
    ) -> None:
        self._registry = registry
        self._policy = policy or PolicyEngine()
        self._audit = audit or get_audit_logger()
        self._correlator = correlator or _correlator

    def process(self, event_data: dict[str, Any]) -> dict[str, Any]:
        detail = event_data.get("detail", {})
        resource_hint = str(detail.get("id") or event_data.get("id") or "unknown")

        self._audit.log(
            AuditAction.PLAYBOOK_STARTED,
            resource_id=resource_hint,
            details={"phase": "input", "event_keys": list(event_data.keys())},
        )

        incident = EventNormalizer.normalize(event_data)
        if incident is None:
            self._audit.log(
                AuditAction.PLAYBOOK_FAILED,
                resource_id=resource_hint,
                details={"reason": "normalization_failed"},
                success=False,
            )
            return {"statusCode": 422, "body": {"error": "Unable to normalize event"}}

        incident.raw_event = event_data
        incident.pipeline_options = {
            k: event_data[k] for k in ("dry_run", "preview_only", "execution_mode") if k in event_data
        }

        self._correlator.ingest(incident)
        related = self._correlator.find_related(incident.incident_id)
        incident.related_incidents = [r.incident_id for r in related]

        self._audit.log(
            AuditAction.COLLECT_EVIDENCE,
            resource_id=incident.incident_id,
            details={
                "phase": "correlate",
                "related_count": len(related),
                "related_ids": incident.related_incidents,
            },
        )

        score_result = self._policy.evaluate(incident)
        self._audit.log(
            AuditAction.SCORING_DECISION,
            resource_id=incident.incident_id,
            details={
                "risk_score": incident.risk_score,
                "decision": incident.decision,
                "score_result": score_result,
            },
        )

        if incident.decision == "IGNORE":
            return self._finalize(
                incident,
                {
                    "status": "ignored",
                    "incident_id": incident.incident_id,
                    "decision": incident.decision,
                    "risk_score": incident.risk_score,
                },
            )

        if incident.decision == "REQUIRE_APPROVAL":
            self._request_approval(incident, score_result)
            return self._finalize(
                incident,
                {
                    "status": "pending_approval",
                    "incident_id": incident.incident_id,
                    "decision": incident.decision,
                    "risk_score": incident.risk_score,
                },
            )

        if not PolicyEngine.should_execute_playbook(incident.decision):
            return self._finalize(
                incident,
                {
                    "status": "no_action",
                    "incident_id": incident.incident_id,
                    "decision": incident.decision,
                },
            )

        result = self._registry.dispatch(incident)

        if result is None:
            self._audit.log(
                AuditAction.PLAYBOOK_FAILED,
                resource_id=incident.incident_id,
                details={"reason": "no_matching_playbook"},
                success=False,
            )
            return {"statusCode": 200, "body": {"status": "no_playbook", "incident_id": incident.incident_id}}

        success = result is not False and not (isinstance(result, dict) and result.get("status") == "failed")
        self._audit.log(
            AuditAction.PLAYBOOK_COMPLETED if success else AuditAction.PLAYBOOK_FAILED,
            resource_id=incident.incident_id,
            details={"phase": "execute", "result": result if isinstance(result, dict) else {"success": success}},
            success=success,
        )

        if isinstance(result, dict):
            return {"statusCode": 200, "body": result}

        if result:
            return {"statusCode": 200, "body": {"status": "executed", "incident_id": incident.incident_id}}

        return {"statusCode": 500, "body": {"status": "failed", "incident_id": incident.incident_id}}

    def _request_approval(self, incident: UnifiedIncident, score_result: dict[str, Any]) -> None:
        self._audit.log(
            AuditAction.APPROVAL_REQUESTED,
            resource_id=incident.incident_id,
            details={"risk_score": incident.risk_score, "score_result": score_result},
        )
        try:
            notifier = SlackNotifier()
            notifier.send_incident_alert(
                {
                    "id": incident.incident_id,
                    "severity": incident.severity,
                    "title": f"Approval Required: {incident.action or incident.raw_event_type}",
                    "description": score_result.get("summary", "Manual approval required before remediation."),
                    "decision": incident.decision,
                    "intel_summary": incident.intel_summary,
                    "resource": incident.resource,
                    "risk_score": incident.risk_score,
                }
            )
        except Exception as exc:
            logger.warning(f"Approval notification failed (non-fatal): {exc}")

    def _finalize(self, incident: UnifiedIncident, body: dict[str, Any]) -> dict[str, Any]:
        self._audit.log(
            AuditAction.PLAYBOOK_COMPLETED,
            resource_id=incident.incident_id,
            details={"phase": "complete", **body},
        )
        return {"statusCode": 200, "body": body}
