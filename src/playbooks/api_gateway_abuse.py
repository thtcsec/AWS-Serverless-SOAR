"""
AWS SOAR — API Gateway Abuse Playbook
Handles DDoS or application layer abuse detected by AWS WAF for API Gateway.
"""

from __future__ import annotations

import contextlib
import os
from typing import Any

from src.clients.aws import AWSClientFacade
from src.core.audit_logger import AuditAction, AuditLogger
from src.core.logger import logger
from src.core.metrics import PlaybookTimer, emit_metric
from src.models.events import WAFEvent
from src.playbooks.base import Playbook


class APIGatewayAbusePlaybook(Playbook):
    """Playbook to block malicious IPs abusing API Gateway."""

    def __init__(self) -> None:
        self.wafv2 = AWSClientFacade.wafv2()
        self.audit = AuditLogger()
        self.ip_set_id = os.environ.get("WAF_BLOCKLIST_IPSET_ID", "")
        self.ip_set_name = os.environ.get("WAF_BLOCKLIST_IPSET_NAME", "")
        self.ip_set_scope = os.environ.get("WAF_BLOCKLIST_SCOPE", "REGIONAL")

    def can_handle(self, event_data: dict[str, Any]) -> bool:
        try:
            source = event_data.get("source")
            if source != "aws.waf":
                return False
            event = WAFEvent.model_validate(event_data)
            return event.detail.is_ddos_abuse
        except Exception:
            return False

    def execute(self, event_data: dict[str, Any]) -> bool:
        with PlaybookTimer("APIGatewayAbuse"):
            try:
                event = WAFEvent.model_validate(event_data)
                client_ip = event.detail.client_ip

                if not client_ip:
                    logger.error("No client IP found in WAF finding")
                    return False

                logger.info(f"Executing API Gateway Abuse Playbook for IP={client_ip}")
                self.audit.log(
                    AuditAction.PLAYBOOK_STARTED,
                    client_ip,
                    details={"source": event.source},
                )
                emit_metric("FindingsProcessed", 1.0, "Count", {"Playbook": "APIGatewayAbuse"})

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
