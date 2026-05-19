"""
AWS SOAR — CI/CD Supply Chain Attack Detection Playbook
Handles CodePipeline and CodeBuild events for supply chain compromise detection.
"""

from __future__ import annotations

import contextlib
from typing import Any

from pydantic import ValidationError

from src.clients.aws import AWSClientFacade
from src.core.audit_logger import AuditAction, AuditLogger
from src.core.logger import logger
from src.core.metrics import PlaybookTimer, emit_metric
from src.models.events import CodePipelineEvent
from src.playbooks.base import Playbook


class CICDSupplyChainPlaybook(Playbook):
    """Playbook to detect and respond to CI/CD supply chain attacks."""

    VALID_SOURCES = {"aws.codepipeline", "aws.codebuild"}

    def __init__(self) -> None:
        self.codepipeline = AWSClientFacade.codepipeline()
        self.codebuild = AWSClientFacade.codebuild()
        self.s3 = AWSClientFacade.s3()
        self.audit = AuditLogger()

    def can_handle(self, event_data: dict[str, Any]) -> bool:
        try:
            source = event_data.get("source", "")
            if source not in self.VALID_SOURCES:
                return False
            event = CodePipelineEvent.model_validate(event_data)
            return event.detail.is_supply_chain_risk
        except (ValidationError, Exception):
            return False

    def execute(self, event_data: dict[str, Any]) -> bool | dict[str, Any]:
        with PlaybookTimer("CICDSupplyChain"):
            try:
                event = CodePipelineEvent.model_validate(event_data)
                source = event.source
                event_name = event.detail.eventName
                source_ip = str(event.detail.sourceIPAddress or "")
                identity = event.detail.userIdentity
                actor = identity.get("arn", identity.get("userName", "unknown"))
                params = event.detail.requestParameters or {}

                # Extract pipeline/build name
                pipeline_name = params.get("name", params.get("pipeline", {}).get("name", ""))
                build_id = params.get("id", "")
                resource_id = pipeline_name or build_id or "unknown"

                if self._is_dry_run(event_data):
                    return self._build_preview(
                        source, resource_id, event_name, source_ip, actor, pipeline_name, build_id
                    )

                logger.info(f"Executing CI/CD Supply Chain playbook: source={source}, event={event_name}")
                self.audit.log(
                    AuditAction.PLAYBOOK_STARTED,
                    resource_id,
                    details={"event": event_name, "actor": actor},
                )
                emit_metric("FindingsProcessed", 1.0, "Count", {"Playbook": "CICDSupplyChain"})

                # Behavior-based scoring
                risk_score = self._behavior_score(source_ip, actor, event_name)
                decision = "AUTO_ISOLATE" if risk_score >= 70 else "REQUIRE_APPROVAL" if risk_score >= 40 else "IGNORE"
                self.audit.log(
                    AuditAction.SCORING_DECISION,
                    resource_id,
                    details={"decision": decision, "risk_score": risk_score},
                )

                if decision == "IGNORE":
                    logger.info(f"CI/CD event {event_name} scored low ({risk_score}). Ignoring.")
                    self.audit.log(AuditAction.PLAYBOOK_COMPLETED, resource_id)
                    return True

                elif decision == "REQUIRE_APPROVAL":
                    logger.info(f"CI/CD event {event_name} requires approval. Score={risk_score}")
                    self._notify_slack(resource_id, event_name, source_ip, actor, risk_score, decision)
                    self.audit.log(AuditAction.APPROVAL_REQUESTED, resource_id)
                    self.audit.log(AuditAction.PLAYBOOK_COMPLETED, resource_id)
                    return True

                elif decision == "AUTO_ISOLATE":
                    logger.critical(f"AUTO_ISOLATE for CI/CD resource {resource_id} (score={risk_score})")

                    if source == "aws.codepipeline" and pipeline_name:
                        self._disable_pipeline(pipeline_name)

                    if source == "aws.codebuild" and build_id:
                        self._stop_build(build_id)

                    # Quarantine artifact S3 paths
                    artifact_bucket = params.get("artifactStore", {}).get("location", "")
                    if artifact_bucket:
                        self._quarantine_artifact_bucket(artifact_bucket, resource_id)

                    self._notify_slack(resource_id, event_name, source_ip, actor, risk_score, decision)
                    self.audit.log(AuditAction.PLAYBOOK_COMPLETED, resource_id)
                    return True

            except Exception as e:
                logger.error(f"CI/CD Supply Chain playbook failed: {e}", exc_info=True)
                with contextlib.suppress(Exception):
                    self.audit.log(AuditAction.PLAYBOOK_FAILED, "cicd_resource", success=False)
                return False

        return False

    @staticmethod
    def _is_dry_run(event_data: dict[str, Any]) -> bool:
        return bool(
            event_data.get("dry_run") or event_data.get("preview_only") or event_data.get("execution_mode") == "dry_run"
        )

    @staticmethod
    def _build_preview(
        source: str,
        resource_id: str,
        event_name: str,
        source_ip: str,
        actor: str,
        pipeline_name: str,
        build_id: str,
    ) -> dict[str, Any]:
        risk_score = CICDSupplyChainPlaybook._behavior_score(source_ip, actor, event_name)
        decision = "AUTO_ISOLATE" if risk_score >= 70 else "REQUIRE_APPROVAL" if risk_score >= 40 else "IGNORE"
        planned_actions = [
            {
                "step": 1,
                "action": "behavior_score",
                "target": resource_id,
                "details": (
                    f"Score CI/CD event '{event_name}' from actor '{actor}' (score={risk_score}, decision={decision})."
                ),
            },
        ]
        if decision != "IGNORE":
            if source == "aws.codepipeline" and pipeline_name:
                planned_actions.append(
                    {
                        "step": 2,
                        "action": "disable_stage_transition",
                        "target": pipeline_name,
                        "details": "Disable pipeline stage transitions if AUTO_ISOLATE is reached.",
                    }
                )
            if source == "aws.codebuild" and build_id:
                planned_actions.append(
                    {
                        "step": len(planned_actions) + 1,
                        "action": "stop_build",
                        "target": build_id,
                        "details": "Stop the active build if AUTO_ISOLATE is reached.",
                    }
                )
            planned_actions.append(
                {
                    "step": len(planned_actions) + 1,
                    "action": "notify_slack",
                    "target": resource_id,
                    "details": "Notify operators with risk score and decision path.",
                }
            )

        return {
            "mode": "dry_run",
            "playbook": "CICDSupplyChain",
            "target_resource": resource_id,
            "decision": decision,
            "risk_score": risk_score,
            "planned_actions": planned_actions,
            "summary": "Preview only. No CodePipeline, CodeBuild, or S3 remediation was executed.",
        }

    @staticmethod
    def _behavior_score(source_ip: str, actor: str, event_name: str) -> float:
        """Behavior-based risk scoring (external caller, off-hours, sensitive action)."""
        score = 0.0
        # External IP (non-AWS)
        if source_ip and not source_ip.endswith(".amazonaws.com"):
            is_internal = (
                source_ip.startswith("10.") or source_ip.startswith("172.") or source_ip.startswith("192.168.")
            )
            if not is_internal:
                score += 35.0

        # Highly sensitive CI/CD actions
        if event_name in ("UpdatePipeline", "PutJobSuccessResult"):
            score += 30.0
        elif event_name in ("StartBuild", "BatchGetProjects"):
            score += 15.0

        # Unknown / service actor
        if "assumed-role" not in actor.lower() and "service" not in actor.lower():
            score += 10.0

        return min(score, 100.0)

    def _disable_pipeline(self, pipeline_name: str) -> None:
        try:
            self.codepipeline.disable_stage_transition(
                pipelineName=pipeline_name,
                stageName="Source",
                transitionType="Inbound",
                reason="SOAR Auto-Isolation: Supply chain compromise detected",
            )
            logger.info(f"Disabled pipeline transitions for {pipeline_name}")
            self.audit.log(AuditAction.DISABLE_PIPELINE, pipeline_name)
        except Exception as e:
            logger.warning(f"Failed to disable pipeline {pipeline_name}: {e}")

    def _stop_build(self, build_id: str) -> None:
        try:
            self.codebuild.stop_build(id=build_id)
            logger.info(f"Stopped build {build_id}")
            self.audit.log(AuditAction.STOP_BUILD, build_id)
        except Exception as e:
            logger.warning(f"Failed to stop build {build_id}: {e}")

    def _quarantine_artifact_bucket(self, bucket_name: str, resource_id: str) -> None:
        """Add a deny-all bucket policy to quarantine artifacts."""
        import json

        try:
            deny_policy = {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "SOARQuarantine",
                        "Effect": "Deny",
                        "Principal": "*",
                        "Action": "s3:*",
                        "Resource": [
                            f"arn:aws:s3:::{bucket_name}",
                            f"arn:aws:s3:::{bucket_name}/*",
                        ],
                    }
                ],
            }
            self.s3.put_bucket_policy(Bucket=bucket_name, Policy=json.dumps(deny_policy))
            logger.info(f"Applied quarantine policy to artifact bucket {bucket_name}")
            self.audit.log(
                AuditAction.QUARANTINE_ARTIFACT,
                bucket_name,
                details={"pipeline_resource": resource_id},
            )
        except Exception as e:
            logger.warning(f"Failed to quarantine artifact bucket {bucket_name}: {e}")

    def _notify_slack(
        self,
        resource_id: str,
        event_name: str,
        source_ip: str,
        actor: str,
        score: float,
        decision: str,
    ) -> None:
        try:
            from src.integrations.slack_notifier import SlackNotifier

            notifier = SlackNotifier()
            incident_data = {
                "id": f"CICD-{resource_id}-{event_name}",
                "severity": "CRITICAL" if decision == "AUTO_ISOLATE" else "HIGH",
                "title": f"CI/CD Supply Chain Attack Detected: {event_name}",
                "description": (
                    f"Suspicious CI/CD action: {event_name}\n"
                    f"Resource: {resource_id}\n"
                    f"Actor: {actor}\n"
                    f"Source IP: {source_ip}\n"
                    f"Risk Score: {score}\n"
                    f"Decision: {decision}"
                ),
                "decision": decision,
                "intel_summary": {},
            }
            notifier.send_incident_alert(incident_data)
        except Exception as e:
            logger.warning(f"Failed to send Slack notification: {e}")
