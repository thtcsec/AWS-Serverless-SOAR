"""
AWS SOAR — Ransomware Response Playbook
Handles ransomware / crypto-locker events detected by GuardDuty.

Actions:
1. Snapshot all EBS volumes attached to the affected EC2 instance.
2. Isolate the instance by swapping its Security Groups.
3. Enable S3 bucket versioning (if an S3 resource is involved).
4. Apply a DenyAll bucket policy to freeze writes / deletes.
5. Stop the instance to halt lateral movement.
"""

from __future__ import annotations

import contextlib
import json
import os
from datetime import UTC, datetime
from typing import Any

from pydantic import ValidationError

from src.clients.aws import AWSClientFacade
from src.core.audit_logger import AuditAction, AuditLogger
from src.core.logger import logger
from src.core.metrics import PlaybookTimer, emit_metric
from src.models.events import GuardDutyEvent
from src.playbooks.base import Playbook

# GuardDuty finding-type keywords that indicate ransomware behaviour
_RANSOMWARE_KEYWORDS: list[str] = [
    "Ransomware",
    "CryptoCurrency",
    "Impact:S3",
    "Impact:EC2",
    "Trojan:EC2",
    "UnauthorizedAccess:S3",
    "Exfiltration",
]


class RansomwareResponsePlaybook(Playbook):
    """Auto-contain ransomware threats across EC2 and S3 resources."""

    def __init__(self) -> None:
        self.audit = AuditLogger()

    def can_handle(self, event_data: dict[str, Any]) -> bool:
        try:
            if event_data.get("source") != "aws.guardduty":
                return False
            event = GuardDutyEvent.model_validate(event_data)
            return any(kw in event.detail.type for kw in _RANSOMWARE_KEYWORDS)
        except (ValidationError, Exception):
            return False

    def execute(self, event_data: dict[str, Any]) -> bool | dict[str, Any]:
        with PlaybookTimer("RansomwareResponse"):
            try:
                event = GuardDutyEvent.model_validate(event_data)

                if self._is_dry_run(event_data):
                    return self._build_preview(event)

                logger.info(
                    "Executing Ransomware Response Playbook",
                    extra={"json_fields": {"finding_type": event.detail.type}},
                )
                emit_metric("FindingsProcessed", 1.0, "Count", {"Playbook": "RansomwareResponse"})
                self.audit.log(AuditAction.PLAYBOOK_STARTED, event.detail.id, actor="SOAR_ENGINE")

                # --- EC2 branch -------------------------------------------------
                instance_id = self._extract_instance_id(event)
                if instance_id:
                    self._snapshot_volumes(instance_id, event.detail.id)
                    self._isolate_instance(instance_id)
                    self._stop_instance(instance_id)

                # --- S3 branch --------------------------------------------------
                bucket_name = self._extract_bucket_name(event)
                if bucket_name:
                    self._enable_versioning(bucket_name)
                    self._freeze_bucket(bucket_name)

                if not instance_id and not bucket_name:
                    logger.warning("No actionable resource found in the finding")

                self.audit.log(AuditAction.PLAYBOOK_COMPLETED, event.detail.id, actor="SOAR_ENGINE")
                return True

            except Exception as exc:
                logger.error(f"Ransomware Response failed: {exc}", exc_info=True)
                with contextlib.suppress(Exception):
                    self.audit.log(
                        AuditAction.PLAYBOOK_FAILED,
                        "ransomware_response",
                        actor="SOAR_ENGINE",
                        success=False,
                    )
                return False

    # ------------------------------------------------------------------ #
    # Dry-run helpers
    # ------------------------------------------------------------------ #

    @staticmethod
    def _is_dry_run(event_data: dict[str, Any]) -> bool:
        return bool(
            event_data.get("dry_run") or event_data.get("preview_only") or event_data.get("execution_mode") == "dry_run"
        )

    def _build_preview(self, event: GuardDutyEvent) -> dict[str, Any]:
        instance_id = self._extract_instance_id(event)
        bucket_name = self._extract_bucket_name(event)
        planned_actions: list[dict[str, Any]] = []
        step = 1

        if instance_id:
            planned_actions.extend(
                [
                    {
                        "step": step,
                        "action": "create_snapshot",
                        "target": instance_id,
                        "details": "Snapshot all EBS volumes attached to the instance.",
                    },
                    {
                        "step": step + 1,
                        "action": "modify_instance_attribute",
                        "target": instance_id,
                        "details": (
                            f"Swap security groups to isolation SG {os.environ.get('ISOLATION_SG_ID', 'UNCONFIGURED')}."
                        ),
                    },
                    {
                        "step": step + 2,
                        "action": "stop_instances",
                        "target": instance_id,
                        "details": "Stop the instance to halt lateral movement.",
                    },
                ]
            )
            step += 3
        if bucket_name:
            planned_actions.extend(
                [
                    {
                        "step": step,
                        "action": "put_bucket_versioning",
                        "target": bucket_name,
                        "details": "Enable S3 bucket versioning.",
                    },
                    {
                        "step": step + 1,
                        "action": "put_bucket_policy",
                        "target": bucket_name,
                        "details": "Apply DenyAll freeze policy to block writes and deletes.",
                    },
                ]
            )

        target = instance_id or bucket_name or event.detail.id
        return {
            "mode": "dry_run",
            "playbook": "RansomwareResponse",
            "target_resource": target,
            "finding_id": event.detail.id,
            "finding_type": event.detail.type,
            "planned_actions": planned_actions,
            "summary": "Preview only. No EC2 or S3 remediation APIs were executed.",
        }

    # ------------------------------------------------------------------ #
    # Resource extraction helpers
    # ------------------------------------------------------------------ #

    @staticmethod
    def _extract_instance_id(event: GuardDutyEvent) -> str | None:
        if event.detail.resource:
            iid = event.detail.resource.get("instanceDetails", {}).get("instanceId")
            if iid:
                return str(iid)
        if event.detail.resources:
            for res in event.detail.resources:
                iid = res.get("instanceDetails", {}).get("instanceId")
                if iid:
                    return str(iid)
        return None

    @staticmethod
    def _extract_bucket_name(event: GuardDutyEvent) -> str | None:
        if event.detail.resource:
            s3_details = event.detail.resource.get("s3BucketDetails")
            if s3_details and isinstance(s3_details, list) and len(s3_details) > 0:
                return str(s3_details[0].get("name", ""))
        return None

    # ------------------------------------------------------------------ #
    # EC2 actions
    # ------------------------------------------------------------------ #

    @staticmethod
    def _snapshot_volumes(instance_id: str, finding_id: str) -> None:
        ec2 = AWSClientFacade.ec2()
        reservations = ec2.describe_instances(InstanceIds=[instance_id]).get("Reservations", [])
        if not reservations:
            logger.warning(f"Instance {instance_id} not found")
            return

        instance = reservations[0]["Instances"][0]
        for mapping in instance.get("BlockDeviceMappings", []):
            vol_id = mapping["Ebs"]["VolumeId"]
            ts = datetime.now(UTC).strftime("%Y%m%dT%H%M%S")
            snap = ec2.create_snapshot(
                VolumeId=vol_id,
                Description=f"Ransomware quarantine snapshot for {finding_id}",
                TagSpecifications=[
                    {
                        "ResourceType": "snapshot",
                        "Tags": [
                            {"Key": "Purpose", "Value": "ransomware-quarantine"},
                            {"Key": "FindingId", "Value": finding_id},
                            {"Key": "InstanceId", "Value": instance_id},
                            {"Key": "Timestamp", "Value": ts},
                        ],
                    }
                ],
            )
            logger.info(f"Created quarantine snapshot {snap.get('SnapshotId')} for volume {vol_id}")

    @staticmethod
    def _isolate_instance(instance_id: str) -> None:
        isolation_sg = os.environ.get("ISOLATION_SG_ID")
        if not isolation_sg:
            logger.warning("ISOLATION_SG_ID not set — skipping network isolation")
            return
        ec2 = AWSClientFacade.ec2()
        ec2.modify_instance_attribute(InstanceId=instance_id, Groups=[isolation_sg])
        logger.info(f"Isolated instance {instance_id} into SG {isolation_sg}")

    @staticmethod
    def _stop_instance(instance_id: str) -> None:
        ec2 = AWSClientFacade.ec2()
        ec2.stop_instances(InstanceIds=[instance_id])
        logger.info(f"Stopped instance {instance_id}")

    # ------------------------------------------------------------------ #
    # S3 actions
    # ------------------------------------------------------------------ #

    @staticmethod
    def _enable_versioning(bucket_name: str) -> None:
        s3 = AWSClientFacade.s3()
        s3.put_bucket_versioning(
            Bucket=bucket_name,
            VersioningConfiguration={"Status": "Enabled"},
        )
        logger.info(f"Enabled versioning on bucket {bucket_name}")

    @staticmethod
    def _freeze_bucket(bucket_name: str) -> None:
        """Apply a DenyAll policy to freeze the bucket."""
        deny_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "SOARRansomwareFreeze",
                    "Effect": "Deny",
                    "Principal": "*",
                    "Action": ["s3:PutObject", "s3:DeleteObject", "s3:PutObjectAcl"],
                    "Resource": [f"arn:aws:s3:::{bucket_name}/*"],
                    "Condition": {
                        "StringNotEquals": {
                            "aws:PrincipalArn": os.environ.get(
                                "SOAR_ROLE_ARN",
                                "arn:aws:iam::123456789012:role/soar-engine",
                            )
                        }
                    },
                }
            ],
        }
        s3 = AWSClientFacade.s3()
        s3.put_bucket_policy(Bucket=bucket_name, Policy=json.dumps(deny_policy))
        logger.info(f"Applied DenyAll freeze policy to bucket {bucket_name}")
