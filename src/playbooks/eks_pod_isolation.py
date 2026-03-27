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
from src.core.logger import logger
from src.core.metrics import PlaybookTimer, emit_metric
from src.models.events import EKSGuardDutyEvent
from src.playbooks.base import Playbook


class EKSPodIsolationPlaybook(Playbook):
    """Playbook to isolate compromised pods in EKS clusters."""

    def __init__(self) -> None:
        self.eks = AWSClientFacade.eks()
        self.s3 = AWSClientFacade.s3()
        self.audit = AuditLogger()
        self.evidence_bucket = os.environ.get("EVIDENCE_BUCKET", "")

    def can_handle(self, event_data: dict[str, Any]) -> bool:
        try:
            source = event_data.get("source")
            if source != "aws.guardduty":
                return False
            event = EKSGuardDutyEvent.model_validate(event_data)
            return event.is_eks_runtime_threat
        except Exception:
            return False

    def execute(self, event_data: dict[str, Any]) -> bool:
        with PlaybookTimer("EKSPodIsolation"):
            try:
                event = EKSGuardDutyEvent.model_validate(event_data)
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
        """Upload pod log placeholder to S3 evidence bucket."""
        try:
            import json
            from datetime import UTC, datetime

            from src.core.config import config

            evidence = {
                "cluster_name": cluster_name,
                "namespace": namespace,
                "pod_name": pod_name,
                "finding_id": finding_id,
                "collected_at": datetime.now(UTC).isoformat(),
                "note": "Pod log collection placeholder — attach kubectl logs output",
            }
            key = f"evidence/eks/{cluster_name}/{namespace}/{pod_name}/{finding_id}.json"
            bucket = self.evidence_bucket or config.evidence_bucket
            if bucket:
                self.s3.put_object(Bucket=bucket, Key=key, Body=json.dumps(evidence))
                logger.info(f"Uploaded EKS pod evidence to s3://{bucket}/{key}")
            self.audit.log(
                AuditAction.COLLECT_POD_LOGS,
                f"{cluster_name}/{namespace}/{pod_name}",
                details={"s3_key": key},
            )
        except Exception as e:
            logger.warning(f"Failed to collect pod logs for {pod_name}: {e}")
