"""
AWS SOAR — RDS Compromise Playbook
Handles RDS database compromise events from CloudTrail.
"""

from __future__ import annotations

import contextlib
import os
from typing import Any

from pydantic import ValidationError

from src.clients.aws import AWSClientFacade
from src.core.audit_logger import AuditAction, AuditLogger
from src.core.event_normalizer import UnifiedIncident
from src.core.logger import logger
from src.core.metrics import PlaybookTimer, emit_metric
from src.models.events import RDSCloudTrailEvent
from src.playbooks._helpers import coerce_incident, is_dry_run
from src.playbooks.base import Playbook


class RDSCompromisePlaybook(Playbook):
    """Playbook to respond to RDS compromise events detected via CloudTrail."""

    def __init__(self) -> None:
        self.rds = AWSClientFacade.rds()
        self.ec2 = AWSClientFacade.ec2()
        self.isolation_sg_id = os.environ.get("ISOLATION_SG_ID")
        self.audit = AuditLogger()

    def can_handle(self, incident: UnifiedIncident | dict[str, Any]) -> bool:
        incident = coerce_incident(incident)
        try:
            source = incident.raw_event.get("source")
            if source != "aws.rds":
                return False
            event = RDSCloudTrailEvent.model_validate(incident.raw_event)
            return event.detail.is_risky
        except ValidationError:
            return False
        except Exception:
            return False

    def execute(self, incident: UnifiedIncident | dict[str, Any]) -> bool | dict[str, Any]:
        incident = coerce_incident(incident)
        with PlaybookTimer("RDSCompromise"):
            try:
                event = RDSCloudTrailEvent.model_validate(incident.raw_event)
                db_id = event.detail.dbInstanceIdentifier
                source_ip = str(event.detail.sourceIPAddress or "")
                event_name = event.detail.eventName

                if not db_id:
                    logger.error("No dbInstanceIdentifier found in RDS CloudTrail event")
                    return False

                if is_dry_run(incident):
                    return self._build_preview(db_id, event_name, source_ip)

                logger.info(f"Executing RDS Compromise playbook for {db_id} (action={event_name})")
                self.audit.log(AuditAction.PLAYBOOK_STARTED, db_id, details={"event": event_name})
                emit_metric("FindingsProcessed", 1.0, "Count", {"Playbook": "RDSCompromise"})

                # Step 1: Threat intel + scoring
                intel_report: dict[str, Any] = {}
                risk_data: dict[str, Any] = {"decision": "IGNORE", "risk_score": 0.0}

                is_external_ip = (
                    source_ip
                    and not source_ip.endswith(".amazonaws.com")
                    and not source_ip.startswith("10.")
                    and not source_ip.startswith("172.")
                    and not source_ip.startswith("192.168.")
                )

                if is_external_ip:
                    try:
                        from src.integrations.intel import ThreatIntelService
                        from src.integrations.scoring import ScoringEngine

                        intel_service = ThreatIntelService()
                        intel_report = intel_service.get_ip_report(source_ip)
                        self.audit.log(AuditAction.THREAT_INTEL_LOOKUP, source_ip, details=intel_report)
                        risk_data = ScoringEngine.calculate_risk_score(intel_report, initial_severity=7.0)
                    except Exception as e:
                        logger.warning(f"Threat intel / scoring failed (non-fatal): {e}")
                        risk_data = {"decision": "REQUIRE_APPROVAL", "risk_score": 50.0}

                decision = str(risk_data.get("decision", "IGNORE"))
                score = float(str(risk_data.get("risk_score", 0.0)))
                self.audit.log(AuditAction.SCORING_DECISION, db_id, details={"decision": decision, "score": score})

                if decision == "IGNORE":
                    logger.info(f"RDS event for {db_id} scored low ({score}). Ignoring.")
                    self.audit.log(AuditAction.PLAYBOOK_COMPLETED, db_id)
                    return True

                elif decision == "REQUIRE_APPROVAL":
                    logger.info(f"RDS event for {db_id} requires approval. Score={score}")
                    self._notify_slack(db_id, event_name, source_ip, score, decision, intel_report)
                    self.audit.log(AuditAction.APPROVAL_REQUESTED, db_id, details={"score": score})
                    self.audit.log(AuditAction.PLAYBOOK_COMPLETED, db_id)
                    return True

                elif decision == "AUTO_ISOLATE":
                    logger.critical(f"AUTO_ISOLATE triggered for RDS instance {db_id} (score={score})")

                    # Step 2: Create DB snapshot
                    self._create_db_snapshot(db_id, event_name)

                    # Step 3: Modify security groups to isolation SG
                    if self.isolation_sg_id:
                        self._isolate_db_security_group(db_id)

                    # Step 4: Notify Slack
                    self._notify_slack(db_id, event_name, source_ip, score, decision, intel_report)

                    self.audit.log(AuditAction.PLAYBOOK_COMPLETED, db_id)
                    return True

            except Exception as e:
                logger.error(f"RDS Compromise playbook failed: {e}", exc_info=True)
                with contextlib.suppress(Exception):
                    db_id_fallback = incident.raw_event.get("detail", {}).get("dbInstanceIdentifier", "unknown")
                    self.audit.log(AuditAction.PLAYBOOK_FAILED, db_id_fallback, success=False)
                return False

        return False

    def _create_db_snapshot(self, db_id: str, event_name: str) -> None:
        """Create a forensic DB snapshot before isolation."""
        try:
            from datetime import UTC, datetime

            ts = datetime.now(UTC).strftime("%Y%m%d%H%M%S")
            snapshot_id = f"soar-forensic-{db_id}-{ts}"
            self.rds.create_db_snapshot(
                DBSnapshotIdentifier=snapshot_id,
                DBInstanceIdentifier=db_id,
                Tags=[
                    {"Key": "Purpose", "Value": "soar-forensic"},
                    {"Key": "TriggeringEvent", "Value": event_name},
                ],
            )
            logger.info(f"Created forensic DB snapshot {snapshot_id} for {db_id}")
            self.audit.log(AuditAction.SNAPSHOT_DB, db_id, details={"snapshot_id": snapshot_id})
        except Exception as e:
            logger.warning(f"Failed to create DB snapshot for {db_id}: {e}")

    def _isolate_db_security_group(self, db_id: str) -> None:
        """Replace DB security groups with isolation SG."""
        try:
            self.rds.modify_db_instance(
                DBInstanceIdentifier=db_id,
                VpcSecurityGroupIds=[self.isolation_sg_id],
                ApplyImmediately=True,
            )
            logger.info(f"Applied isolation SG {self.isolation_sg_id} to DB {db_id}")
            self.audit.log(AuditAction.ISOLATE_DB, db_id, details={"isolation_sg": self.isolation_sg_id})
        except Exception as e:
            logger.warning(f"Failed to isolate DB security group for {db_id}: {e}")

    def _notify_slack(
        self,
        db_id: str,
        event_name: str,
        source_ip: str,
        score: float,
        decision: str,
        intel_report: dict[str, Any],
    ) -> None:
        try:
            from src.integrations.slack_notifier import SlackNotifier

            notifier = SlackNotifier()
            incident_data = {
                "id": f"RDS-{db_id}-{event_name}",
                "severity": "CRITICAL" if decision == "AUTO_ISOLATE" else "HIGH",
                "title": f"RDS Compromise Detected: {event_name}",
                "description": (
                    f"Suspicious RDS action: {event_name}\n"
                    f"DB Instance: {db_id}\n"
                    f"Source IP: {source_ip}\n"
                    f"Risk Score: {score}\n"
                    f"Decision: {decision}"
                ),
                "decision": decision,
                "intel_summary": intel_report,
            }
            notifier.send_incident_alert(incident_data)
        except Exception as e:
            logger.warning(f"Failed to send Slack notification: {e}")

    def _build_preview(self, db_id: str, event_name: str, source_ip: str) -> dict[str, Any]:
        return {
            "mode": "dry_run",
            "playbook": "RDSCompromise",
            "target_resource": db_id,
            "summary": "Preview only. No RDS snapshots or security groups were modified.",
            "planned_actions": [
                {
                    "step": 1,
                    "action": "risk_assessment",
                    "target": db_id,
                    "details": f"Evaluate risky RDS action '{event_name}' from source IP '{source_ip or 'unknown'}'.",
                },
                {
                    "step": 2,
                    "action": "create_db_snapshot",
                    "target": db_id,
                    "details": "Create forensic DB snapshot before isolation if decision reaches AUTO_ISOLATE.",
                },
                {
                    "step": 3,
                    "action": "modify_db_instance",
                    "target": db_id,
                    "details": f"Apply isolation security group {self.isolation_sg_id or 'UNCONFIGURED'}.",
                },
                {
                    "step": 4,
                    "action": "notify_slack",
                    "target": db_id,
                    "details": "Notify operators with risk score and decision path.",
                },
            ],
        }
