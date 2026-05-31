"""
AWS SOAR — EKS Pod Isolation Playbook
Handles EKS runtime threat findings from GuardDuty.
"""

from __future__ import annotations

import contextlib
import os
from typing import Any

from src.clients.aws import AWSClientFacade
from src.core.audit_logger import AuditAction, AuditLogger
from src.core.event_normalizer import UnifiedIncident
from src.core.logger import logger
from src.core.metrics import PlaybookTimer, emit_metric
from src.models.events import EKSGuardDutyEvent
from src.playbooks._helpers import coerce_incident, is_dry_run
from src.playbooks.base import Playbook


class EKSPodIsolationPlaybook(Playbook):
    """Playbook to isolate compromised pods in EKS clusters."""

    def __init__(self) -> None:
        self.eks = AWSClientFacade.eks()
        self.s3 = AWSClientFacade.s3()
        self.audit = AuditLogger()
        self.evidence_bucket = os.environ.get("EVIDENCE_BUCKET", "")

    def can_handle(self, incident: UnifiedIncident | dict[str, Any]) -> bool:
        incident = coerce_incident(incident)
        try:
            source = incident.raw_event.get("source")
            if source != "aws.guardduty":
                return False
            event = EKSGuardDutyEvent.model_validate(incident.raw_event)
            return event.is_eks_runtime_threat
        except Exception:
            return False

    def execute(self, incident: UnifiedIncident | dict[str, Any]) -> bool | dict[str, Any]:
        incident = coerce_incident(incident)
        with PlaybookTimer("EKSPodIsolation"):
            try:
                event = EKSGuardDutyEvent.model_validate(incident.raw_event)
                finding_type = event.detail.type
                severity = event.detail.severity

                # Extract EKS resource details from finding
                resource = event.detail.resource or {}
                eks_details = resource.get("eksClusterDetails", {})
                k8s_details = resource.get("kubernetesDetails", {})

                cluster_name = eks_details.get("name", "")
                namespace = k8s_details.get("kubernetesWorkloadDetails", {}).get("namespace", "default")
                pod_name = k8s_details.get("kubernetesWorkloadDetails", {}).get("name", "")

                if not cluster_name:
                    logger.error("No EKS cluster name found in GuardDuty finding")
                    return False

                if is_dry_run(incident):
                    return self._build_preview(cluster_name, namespace, pod_name, finding_type, severity)

                logger.info(f"Executing EKS Pod Isolation for cluster={cluster_name}, pod={pod_name}")
                self.audit.log(
                    AuditAction.PLAYBOOK_STARTED,
                    f"{cluster_name}/{namespace}/{pod_name}",
                    details={"finding_type": finding_type, "severity": severity},
                )
                emit_metric("FindingsProcessed", 1.0, "Count", {"Playbook": "EKSPodIsolation"})

                # Severity-based scoring for runtime threats
                decision = self._severity_decision(severity)
                self.audit.log(
                    AuditAction.SCORING_DECISION,
                    cluster_name,
                    details={"decision": decision, "severity": severity},
                )

                if decision == "IGNORE":
                    logger.info(f"EKS finding for {cluster_name} severity too low. Ignoring.")
                    self.audit.log(AuditAction.PLAYBOOK_COMPLETED, cluster_name)
                    return True

                # Collect pod logs to evidence bucket
                if self.evidence_bucket and pod_name:
                    self._collect_pod_logs(cluster_name, namespace, pod_name, event.detail.id)

                if decision in ("AUTO_ISOLATE", "REQUIRE_APPROVAL") and pod_name:
                    self._apply_quarantine_label(cluster_name, namespace, pod_name)

                self.audit.log(AuditAction.PLAYBOOK_COMPLETED, cluster_name)
                return True

            except Exception as e:
                logger.error(f"EKS Pod Isolation playbook failed: {e}", exc_info=True)
                with contextlib.suppress(Exception):
                    self.audit.log(AuditAction.PLAYBOOK_FAILED, "eks_pod", success=False)
                return False

        return False

    @staticmethod
    def _severity_decision(severity: float) -> str:
        """Map GuardDuty severity to SOAR decision for runtime threats."""
        if severity >= 7.0:
            return "AUTO_ISOLATE"
        elif severity >= 4.0:
            return "REQUIRE_APPROVAL"
        return "IGNORE"

    @staticmethod
    def _build_preview(
        cluster_name: str,
        namespace: str,
        pod_name: str,
        finding_type: str,
        severity: float,
    ) -> dict[str, Any]:
        decision = EKSPodIsolationPlaybook._severity_decision(severity)
        planned_actions = [
            {
                "step": 1,
                "action": "severity_decision",
                "target": cluster_name,
                "details": f"Map severity {severity} to decision '{decision}' for finding '{finding_type}'.",
            },
        ]
        if pod_name:
            planned_actions.append(
                {
                    "step": 2,
                    "action": "collect_pod_logs",
                    "target": f"{cluster_name}/{namespace}/{pod_name}",
                    "details": "Upload pod evidence metadata to the configured S3 evidence bucket.",
                }
            )
            if decision in ("AUTO_ISOLATE", "REQUIRE_APPROVAL"):
                planned_actions.append(
                    {
                        "step": 3,
                        "action": "kubectl_label",
                        "target": f"{cluster_name}/{namespace}/{pod_name}",
                        "details": "Apply soar-quarantine=true label to isolate the pod.",
                    }
                )

        return {
            "mode": "dry_run",
            "playbook": "EKSPodIsolation",
            "target_resource": f"{cluster_name}/{namespace}/{pod_name or 'unknown'}",
            "decision": decision,
            "planned_actions": planned_actions,
            "summary": "Preview only. No EKS or kubectl remediation was executed.",
        }

    def _apply_quarantine_label(self, cluster_name: str, namespace: str, pod_name: str) -> None:
        """Label pod for quarantine via EKS API (kubectl-equivalent via boto3)."""
        try:
            import subprocess

            # Get cluster endpoint and CA data
            cluster_info = self.eks.describe_cluster(name=cluster_name)
            cluster_data = cluster_info.get("cluster", {})
            endpoint = cluster_data.get("endpoint", "")

            if not endpoint:
                logger.warning(f"Could not retrieve cluster endpoint for {cluster_name}")
                return

            # Use kubectl via subprocess (assumes kubeconfig is available in Lambda)
            label_cmd = [
                "kubectl",
                "--server",
                endpoint,
                "--namespace",
                namespace,
                "label",
                "pod",
                pod_name,
                "soar-quarantine=true",
                "--overwrite",
            ]
            result = subprocess.run(label_cmd, capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                logger.info(f"Applied soar-quarantine label to pod {pod_name} in {cluster_name}/{namespace}")
                self.audit.log(
                    AuditAction.APPLY_NETWORK_POLICY,
                    f"{cluster_name}/{namespace}/{pod_name}",
                    details={"label": "soar-quarantine=true"},
                )
            else:
                logger.warning(f"kubectl label failed: {result.stderr}")
                # Fallback: log audit with failure
                self.audit.log(
                    AuditAction.APPLY_NETWORK_POLICY,
                    f"{cluster_name}/{namespace}/{pod_name}",
                    success=False,
                    details={"error": result.stderr},
                )
        except Exception as e:
            logger.warning(f"Failed to apply quarantine label to {pod_name}: {e}")

    def _collect_pod_logs(self, cluster_name: str, namespace: str, pod_name: str, finding_id: str) -> None:
        """Collect pod logs with kubectl and upload evidence to S3."""
        try:
            import json
            import subprocess
            from datetime import UTC, datetime

            from src.core.config import config

            log_tail = int(os.environ.get("EKS_POD_LOG_TAIL", "2000"))
            log_since = os.environ.get("EKS_POD_LOG_SINCE", "1h")
            log_timeout = int(os.environ.get("EKS_POD_LOG_TIMEOUT", "60"))
            include_previous = os.environ.get("EKS_POD_LOG_PREVIOUS", "false").lower() in ("1", "true", "yes")
            include_describe = os.environ.get("EKS_POD_DESCRIBE", "true").lower() not in ("0", "false", "no")
            include_events = os.environ.get("EKS_POD_EVENTS", "true").lower() not in ("0", "false", "no")

            def run_kubectl(args: list[str]) -> tuple[str, str]:
                try:
                    result = subprocess.run(args, capture_output=True, text=True, timeout=log_timeout)
                    if result.returncode == 0:
                        return result.stdout, ""
                    return "", result.stderr or f"kubectl exited with code {result.returncode}"
                except Exception as exc:
                    return "", str(exc)

            logs_output = ""
            log_error = ""
            log_cmd = ["kubectl", "--namespace", namespace, "logs", pod_name, "--tail", str(log_tail)]
            if log_since:
                log_cmd.extend(["--since", log_since])
            logs_output, log_error = run_kubectl(log_cmd)

            prev_output = ""
            prev_error = ""
            if include_previous:
                prev_cmd = log_cmd + ["--previous"]
                prev_output, prev_error = run_kubectl(prev_cmd)

            describe_output = ""
            describe_error = ""
            if include_describe:
                describe_cmd = ["kubectl", "--namespace", namespace, "describe", "pod", pod_name]
                describe_output, describe_error = run_kubectl(describe_cmd)

            events_output = ""
            events_error = ""
            if include_events:
                events_cmd = [
                    "kubectl",
                    "--namespace",
                    namespace,
                    "get",
                    "events",
                    "--field-selector",
                    f"involvedObject.name={pod_name},involvedObject.kind=Pod",
                    "--sort-by=.metadata.creationTimestamp",
                ]
                events_output, events_error = run_kubectl(events_cmd)

            artifacts: dict[str, str] = {}
            errors: dict[str, str] = {}
            evidence: dict[str, Any] = {
                "cluster_name": cluster_name,
                "namespace": namespace,
                "pod_name": pod_name,
                "finding_id": finding_id,
                "collected_at": datetime.now(UTC).isoformat(),
                "log_collected": bool(logs_output),
                "log_tail": log_tail,
                "log_since": log_since,
                "include_previous": include_previous,
                "include_describe": include_describe,
                "include_events": include_events,
                "artifacts": artifacts,
                "errors": errors,
            }
            key_prefix = f"evidence/eks/{cluster_name}/{namespace}/{pod_name}/{finding_id}"
            meta_key = f"{key_prefix}.json"
            log_key = f"{key_prefix}.log"
            prev_key = f"{key_prefix}.previous.log"
            describe_key = f"{key_prefix}.describe.txt"
            events_key = f"{key_prefix}.events.txt"
            bucket = self.evidence_bucket or config.evidence_bucket
            if bucket:
                if logs_output:
                    self.s3.put_object(Bucket=bucket, Key=log_key, Body=logs_output.encode("utf-8"))
                    artifacts["logs"] = log_key
                elif log_error:
                    errors["logs"] = log_error
                if prev_output:
                    self.s3.put_object(Bucket=bucket, Key=prev_key, Body=prev_output.encode("utf-8"))
                    artifacts["previous_logs"] = prev_key
                elif prev_error:
                    errors["previous_logs"] = prev_error
                if describe_output:
                    self.s3.put_object(Bucket=bucket, Key=describe_key, Body=describe_output.encode("utf-8"))
                    artifacts["describe"] = describe_key
                elif describe_error:
                    errors["describe"] = describe_error
                if events_output:
                    self.s3.put_object(Bucket=bucket, Key=events_key, Body=events_output.encode("utf-8"))
                    artifacts["events"] = events_key
                elif events_error:
                    errors["events"] = events_error
                self.s3.put_object(Bucket=bucket, Key=meta_key, Body=json.dumps(evidence))
                logger.info(f"Uploaded EKS pod evidence to s3://{bucket}/{meta_key}")
            self.audit.log(
                AuditAction.COLLECT_POD_LOGS,
                f"{cluster_name}/{namespace}/{pod_name}",
                details={"s3_key": meta_key, "artifacts": evidence.get("artifacts", {})},
            )
        except Exception as e:
            logger.warning(f"Failed to collect pod logs for {pod_name}: {e}")
