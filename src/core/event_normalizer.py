"""
AWS SOAR — Unified Event Normalizer
Converts native AWS security events into a standardized UnifiedIncident schema
for cross-platform analysis and incident correlation.
"""

from __future__ import annotations

import hashlib
import logging
import uuid
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, Field

logger = logging.getLogger("aws-soar.normalizer")


# ---------------------------------------------------------------------------
# Unified Incident Schema
# ---------------------------------------------------------------------------


class UnifiedIncident(BaseModel):
    """Platform-agnostic incident representation — canonical schema for the SOAR pipeline."""

    incident_id: str = ""
    platform: str = "aws"
    timestamp: str = ""
    severity: str = "MEDIUM"
    source_ip: str = ""
    actor: str = ""
    action: str = ""
    resource: str = ""
    resource_type: str = ""
    risk_score: float = 0.0
    decision: str = "IGNORE"
    intel_summary: dict[str, Any] = Field(default_factory=dict)
    tags: list[str] = Field(default_factory=list)
    raw_event_type: str = ""
    correlation_keys: list[str] = Field(default_factory=list)
    trace_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    raw_event: dict[str, Any] = Field(default_factory=dict)
    related_incidents: list[str] = Field(default_factory=list)
    pipeline_options: dict[str, Any] = Field(default_factory=dict)

    def to_playbook_payload(self) -> dict[str, Any]:
        payload = dict(self.raw_event)
        payload.update(self.pipeline_options)
        payload["_incident"] = self.model_dump(exclude={"raw_event"})
        return payload


# ---------------------------------------------------------------------------
# Normalizer
# ---------------------------------------------------------------------------


class EventNormalizer:
    """Normalize native AWS security events into UnifiedIncident objects."""

    @staticmethod
    def _generate_id(event_type: str, resource: str, timestamp: str) -> str:
        raw = f"{event_type}:{resource}:{timestamp}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    @classmethod
    def from_guardduty(cls, event_data: dict[str, Any]) -> UnifiedIncident:
        """Normalize a GuardDuty finding into a UnifiedIncident."""
        detail = event_data.get("detail", {})
        service = detail.get("service", {})
        action_info = service.get("action", {})

        source_ip = ""
        if "networkConnectionAction" in action_info:
            source_ip = action_info["networkConnectionAction"].get("remoteIpDetails", {}).get("ipAddressV4", "")

        resource_info = detail.get("resource", {})
        instance_details = resource_info.get("instanceDetails", {})
        resource_id = instance_details.get("instanceId", "")
        resource_type = detail.get("type", "").split("/")[0] if "/" in detail.get("type", "") else "unknown"

        actor = resource_info.get("accessKeyDetails", {}).get("userName", "") or service.get("additionalInfo", {}).get(
            "calledBy", "unknown"
        )

        ts = event_data.get("time", datetime.now(UTC).isoformat())
        incident_id = cls._generate_id("guardduty", resource_id, ts)

        severity_val = detail.get("severity", 0)
        if severity_val >= 7:
            severity = "CRITICAL"
        elif severity_val >= 4:
            severity = "HIGH"
        elif severity_val >= 2:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        correlation_keys = [k for k in [source_ip, actor, resource_id] if k]

        return UnifiedIncident(
            incident_id=incident_id,
            platform="aws",
            timestamp=ts,
            severity=severity,
            source_ip=source_ip,
            actor=actor,
            action=detail.get("type", ""),
            resource=resource_id,
            resource_type=resource_type,
            tags=["guardduty", detail.get("type", "")],
            raw_event_type="GuardDutyFinding",
            correlation_keys=correlation_keys,
        )

    @classmethod
    def from_cloudtrail_iam(cls, event_data: dict[str, Any]) -> UnifiedIncident:
        """Normalize an IAM CloudTrail event into a UnifiedIncident."""
        detail = event_data.get("detail", {})
        user_identity = detail.get("userIdentity", {})

        actor = user_identity.get("userName", user_identity.get("arn", "unknown"))
        source_ip = detail.get("sourceIPAddress", "")
        action = detail.get("eventName", "")
        ts = datetime.now(UTC).isoformat()

        incident_id = cls._generate_id("iam", actor, ts)
        correlation_keys = [k for k in [source_ip, actor] if k]

        return UnifiedIncident(
            incident_id=incident_id,
            platform="aws",
            timestamp=ts,
            severity="HIGH",
            source_ip=source_ip,
            actor=actor,
            action=action,
            resource=actor,
            resource_type="iam_user",
            tags=["cloudtrail", "iam", action],
            raw_event_type="IAMCloudTrailEvent",
            correlation_keys=correlation_keys,
        )

    @classmethod
    def from_cloudtrail_s3(cls, event_data: dict[str, Any]) -> UnifiedIncident:
        """Normalize an S3 CloudTrail event into a UnifiedIncident."""
        detail = event_data.get("detail", {})
        user_identity = detail.get("userIdentity", {})
        request_params = detail.get("requestParameters") or {}

        actor = user_identity.get("userName", user_identity.get("arn", "unknown"))
        source_ip = detail.get("sourceIPAddress", "")
        action = detail.get("eventName", "")
        bucket = request_params.get("bucketName", "")
        ts = datetime.now(UTC).isoformat()

        incident_id = cls._generate_id("s3", bucket, ts)
        correlation_keys = [k for k in [source_ip, actor, bucket] if k]

        return UnifiedIncident(
            incident_id=incident_id,
            platform="aws",
            timestamp=ts,
            severity="HIGH",
            source_ip=source_ip,
            actor=actor,
            action=action,
            resource=bucket,
            resource_type="s3_bucket",
            tags=["cloudtrail", "s3", action],
            raw_event_type="S3CloudTrailEvent",
            correlation_keys=correlation_keys,
        )

    @classmethod
    def from_cloudtrail_rds(cls, event_data: dict[str, Any]) -> UnifiedIncident:
        """Normalize an RDS CloudTrail event into a UnifiedIncident."""
        detail = event_data.get("detail", {})
        user_identity = detail.get("userIdentity", {})
        request_params = detail.get("requestParameters") or {}

        actor = user_identity.get("userName", user_identity.get("arn", "unknown"))
        source_ip = detail.get("sourceIPAddress", "")
        action = detail.get("eventName", "")
        db_id = request_params.get("dBInstanceIdentifier", request_params.get("dbInstanceIdentifier", ""))
        ts = datetime.now(UTC).isoformat()

        incident_id = cls._generate_id("rds", db_id or actor, ts)
        correlation_keys = [k for k in [source_ip, actor, db_id] if k]

        return UnifiedIncident(
            incident_id=incident_id,
            platform="aws",
            timestamp=ts,
            severity="HIGH",
            source_ip=source_ip,
            actor=actor,
            action=action,
            resource=db_id,
            resource_type="rds_instance",
            tags=["cloudtrail", "rds", action],
            raw_event_type="RDSCloudTrailEvent",
            correlation_keys=correlation_keys,
        )

    @classmethod
    def from_cicd(cls, event_data: dict[str, Any]) -> UnifiedIncident:
        """Normalize a CodePipeline / CodeBuild CloudTrail event."""
        detail = event_data.get("detail", {})
        user_identity = detail.get("userIdentity", {})
        request_params = detail.get("requestParameters") or {}
        source = event_data.get("source", "")

        actor = user_identity.get("userName", user_identity.get("arn", "unknown"))
        source_ip = detail.get("sourceIPAddress", "")
        action = detail.get("eventName", "")
        resource = (
            request_params.get("name", "")
            or request_params.get("pipeline", {}).get("name", "")
            or request_params.get("id", "")
            or actor
        )
        ts = datetime.now(UTC).isoformat()

        incident_id = cls._generate_id("cicd", resource, ts)
        correlation_keys = [k for k in [source_ip, actor, resource] if k]

        return UnifiedIncident(
            incident_id=incident_id,
            platform="aws",
            timestamp=ts,
            severity="HIGH",
            source_ip=source_ip,
            actor=actor,
            action=action,
            resource=resource,
            resource_type="cicd_pipeline" if source == "aws.codepipeline" else "codebuild",
            tags=["cloudtrail", source.replace("aws.", ""), action],
            raw_event_type="CICDCloudTrailEvent",
            correlation_keys=correlation_keys,
        )

    @classmethod
    def normalize(cls, event_data: dict[str, Any]) -> UnifiedIncident | None:
        """Auto-detect event type and normalize accordingly."""
        source = event_data.get("source", "")
        detail_type = event_data.get("detail-type", "")

        if source == "aws.guardduty" or detail_type == "GuardDuty Finding":
            return cls.from_guardduty(event_data)
        elif source == "aws.iam":
            return cls.from_cloudtrail_iam(event_data)
        elif source == "aws.s3":
            return cls.from_cloudtrail_s3(event_data)
        elif source == "aws.rds":
            return cls.from_cloudtrail_rds(event_data)
        elif source in ("aws.codepipeline", "aws.codebuild"):
            return cls.from_cicd(event_data)

        if source == "aws.waf":
            return cls.from_waf(event_data)

        logger.warning(f"Unknown event source: {source}")
        return None

    @classmethod
    def from_waf(cls, event_data: dict[str, Any]) -> UnifiedIncident:
        """Normalize a WAF / API Gateway abuse event."""
        detail = event_data.get("detail", {})
        source_ip = detail.get("sourceIPAddress", detail.get("clientIp", ""))
        ts = event_data.get("time", datetime.now(UTC).isoformat())
        incident_id = cls._generate_id("waf", source_ip or "unknown", ts)

        return UnifiedIncident(
            incident_id=incident_id,
            platform="aws",
            timestamp=ts,
            severity="HIGH",
            source_ip=source_ip,
            actor="unknown",
            action=detail.get("eventName", "WAFBlock"),
            resource=source_ip or "unknown",
            resource_type="waf_client",
            tags=["waf", "api_gateway"],
            raw_event_type="WAFEvent",
            correlation_keys=[k for k in [source_ip] if k],
        )

    @classmethod
    def ensure(cls, event_data: dict[str, Any] | UnifiedIncident) -> UnifiedIncident:
        """Coerce raw transport payloads into UnifiedIncident objects."""
        if isinstance(event_data, UnifiedIncident):
            if not event_data.raw_event:
                event_data.raw_event = {}
            return event_data

        incident = cls.normalize(event_data)
        if incident is None:
            incident = UnifiedIncident(raw_event_type="unknown")
        incident.raw_event = event_data
        incident.pipeline_options = {
            key: event_data[key] for key in ("dry_run", "preview_only", "execution_mode") if key in event_data
        }
        return incident
