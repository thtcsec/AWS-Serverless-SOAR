"""
AWS SOAR — API Gateway Abuse Playbook
Handles DDoS or application layer abuse detected by AWS WAF for API Gateway.
"""

from __future__ import annotations

import contextlib
import json
import os
from collections import Counter
from datetime import UTC, datetime
from typing import Any

from src.clients.aws import AWSClientFacade
from src.core.audit_logger import AuditAction, AuditLogger
from src.core.config import config
from src.core.event_normalizer import UnifiedIncident
from src.core.logger import logger
from src.core.metrics import PlaybookTimer, emit_metric
from src.models.events import WAFEvent
from src.playbooks._helpers import coerce_incident, is_dry_run
from src.playbooks.base import Playbook


class APIGatewayAbusePlaybook(Playbook):
    """Playbook to block malicious IPs abusing API Gateway."""

    def __init__(self) -> None:
        self.wafv2 = AWSClientFacade.wafv2()
        self.s3 = AWSClientFacade.s3()
        self.audit = AuditLogger()
        self.ip_set_id = os.environ.get("WAF_BLOCKLIST_IPSET_ID", "")
        self.ip_set_name = os.environ.get("WAF_BLOCKLIST_IPSET_NAME", "")
        self.ip_set_scope = os.environ.get("WAF_BLOCKLIST_SCOPE", "REGIONAL")
        self.evidence_bucket = os.environ.get("EVIDENCE_BUCKET", "")

    def can_handle(self, incident: UnifiedIncident | dict[str, Any]) -> bool:
        incident = coerce_incident(incident)
        try:
            source = incident.raw_event.get("source")
            if source != "aws.waf":
                return False
            event = WAFEvent.model_validate(incident.raw_event)
            return event.detail.is_ddos_abuse
        except Exception:
            return False

    def execute(self, incident: UnifiedIncident | dict[str, Any]) -> bool | dict[str, Any]:
        incident = coerce_incident(incident)
        with PlaybookTimer("APIGatewayAbuse"):
            try:
                event = WAFEvent.model_validate(incident.raw_event)
                client_ip = event.detail.client_ip

                if not client_ip:
                    logger.error("No client IP found in WAF finding")
                    return False

                if is_dry_run(incident):
                    return self._build_preview(client_ip)

                logger.info(f"Executing API Gateway Abuse Playbook for IP={client_ip}")
                self.audit.log(
                    AuditAction.PLAYBOOK_STARTED,
                    client_ip,
                    details={"source": event.source},
                )
                emit_metric("FindingsProcessed", 1.0, "Count", {"Playbook": "APIGatewayAbuse"})

                # Collect abuse evidence if configured
                self._collect_evidence(client_ip, incident.raw_event)

                # Ensure IP blocklist is configured
                if not self.ip_set_id or not self.ip_set_name:
                    logger.warning("WAF blocklist IPSet is not configured in environment variables.")
                    return False

                # Format IP as CIDR
                target_ip = f"{client_ip}/32" if ":" not in client_ip else f"{client_ip}/128"

                self._block_ip(target_ip)
                self.audit.log(AuditAction.PLAYBOOK_COMPLETED, client_ip)
                return True

            except Exception as e:
                logger.error(f"API Gateway Abuse playbook failed: {e}", exc_info=True)
                with contextlib.suppress(Exception):
                    self.audit.log(AuditAction.PLAYBOOK_FAILED, "waf_abuse", success=False)
                return False

        return False

    def _build_preview(self, client_ip: str) -> dict[str, Any]:
        target_ip = f"{client_ip}/32" if ":" not in client_ip else f"{client_ip}/128"
        return {
            "mode": "dry_run",
            "playbook": "APIGatewayAbuse",
            "target_resource": client_ip,
            "summary": "Preview only. No WAF IPSet blocklist was updated.",
            "planned_actions": [
                {
                    "step": 1,
                    "action": "collect_evidence",
                    "target": self.evidence_bucket or config.evidence_bucket or "UNCONFIGURED",
                    "details": "Store WAF event evidence to S3 if an evidence bucket is configured.",
                },
                {
                    "step": 2,
                    "action": "get_ip_set",
                    "target": self.ip_set_name or "UNCONFIGURED",
                    "details": f"Fetch current WAF IPSet {self.ip_set_id or 'UNCONFIGURED'} lock token.",
                },
                {
                    "step": 3,
                    "action": "update_ip_set",
                    "target": target_ip,
                    "details": f"Add {target_ip} to WAF blocklist scope {self.ip_set_scope}.",
                },
            ],
        }

    @staticmethod
    def _safe_key_component(value: str) -> str:
        return value.replace(":", "_").replace("/", "_")

    @staticmethod
    def _get_header_value(headers: list[dict[str, Any]] | None, name: str) -> str:
        if not headers:
            return ""
        name_lower = name.lower()
        for header in headers:
            header_name = str(header.get("name", "")).lower()
            if header_name == name_lower:
                return str(header.get("value", ""))
        return ""

    @staticmethod
    def _top_counts(values: list[str], limit: int) -> list[dict[str, Any]]:
        counter = Counter(v for v in values if v)
        return [{"value": value, "count": count} for value, count in counter.most_common(limit)]

    def _summarize_waf_samples(self, detail: dict[str, Any]) -> dict[str, Any]:
        samples = detail.get("sampledRequests", []) or []
        max_samples = int(os.environ.get("WAF_SAMPLE_MAX", "50"))
        top_n = int(os.environ.get("WAF_SUMMARY_TOP_N", "5"))
        used_samples = samples[:max_samples]

        methods: list[str] = []
        uris: list[str] = []
        user_agents: list[str] = []

        for sample in used_samples:
            request = sample.get("request", {}) or sample.get("httpRequest", {}) or {}
            methods.append(str(request.get("method", "")))
            uris.append(str(request.get("uri", "")))
            headers = request.get("headers", [])
            user_agents.append(self._get_header_value(headers, "user-agent"))

        return {
            "sample_total": len(samples),
            "sample_used": len(used_samples),
            "top_methods": self._top_counts(methods, top_n),
            "top_uris": self._top_counts(uris, top_n),
            "top_user_agents": self._top_counts(user_agents, top_n),
        }

    def _collect_evidence(self, client_ip: str, event_data: dict[str, Any]) -> None:
        bucket = self.evidence_bucket or config.evidence_bucket
        if not bucket:
            return

        try:
            safe_ip = self._safe_key_component(client_ip) or "unknown"
            ts = datetime.now(UTC).strftime("%Y%m%d%H%M%S")
            key = f"evidence/api_gateway/{safe_ip}/{ts}.json"
            detail = event_data.get("detail", {}) or {}
            payload = {
                "client_ip": client_ip,
                "collected_at": datetime.now(UTC).isoformat(),
                "source": "aws.waf",
                "event": event_data,
                "summary": self._summarize_waf_samples(detail),
            }
            self.s3.put_object(Bucket=bucket, Key=key, Body=json.dumps(payload, default=str))
            self.audit.log(
                AuditAction.COLLECT_EVIDENCE,
                client_ip,
                details={"s3_key": key},
            )
        except Exception as exc:
            logger.warning(f"Failed to store WAF evidence for {client_ip}: {exc}")

    def _block_ip(self, target_ip: str) -> None:
        """Add the offending IP to the WAF IPSet blocklist."""
        try:
            # First, fetch the lock token
            response = self.wafv2.get_ip_set(Name=self.ip_set_name, Scope=self.ip_set_scope, Id=self.ip_set_id)
            ip_set = response.get("IPSet", {})
            lock_token = response.get("LockToken", "")
            addresses = ip_set.get("Addresses", [])

            if target_ip in addresses:
                logger.info(f"IP {target_ip} is already in the blocklist.")
                return

            addresses.append(target_ip)

            # Update the IPSet
            self.wafv2.update_ip_set(
                Name=self.ip_set_name,
                Scope=self.ip_set_scope,
                Id=self.ip_set_id,
                Addresses=addresses,
                LockToken=lock_token,
                Description="Updated by SOAR API Gateway Abuse Playbook",
            )
            logger.info(f"Successfully added {target_ip} to WAF IPSet {self.ip_set_name}")

            self.audit.log(
                AuditAction.ISOLATE_NETWORK,
                target_ip,
                details={"waf_ip_set": self.ip_set_name},
            )

        except Exception as e:
            logger.warning(f"Failed to block IP {target_ip} in WAF: {e}")
            raise
