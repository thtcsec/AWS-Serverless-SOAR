import json
from typing import Any

from pydantic import ValidationError

from src.clients.aws import AWSClientFacade
from src.core.event_normalizer import UnifiedIncident
from src.core.logger import logger
from src.core.metrics import PlaybookTimer, emit_metric
from src.core.policy import RISKY_IAM_ACTIONS
from src.models.events import IAMCloudTrailEvent
from src.playbooks._helpers import coerce_incident, is_dry_run
from src.playbooks.base import Playbook


class IAMCompromisePlaybook(Playbook):
    """Playbook to react to IAM compromise events."""

    def __init__(self) -> None:
        self.iam = AWSClientFacade.iam()

    def can_handle(self, incident: UnifiedIncident | dict[str, Any]) -> bool:
        incident = coerce_incident(incident)
        try:
            event = IAMCloudTrailEvent.model_validate(incident.raw_event)
            return event.detail.eventName in RISKY_IAM_ACTIONS
        except ValidationError:
            return False

    def execute(self, incident: UnifiedIncident | dict[str, Any]) -> bool | dict[str, Any]:
        incident = coerce_incident(incident)
        with PlaybookTimer("IAMCompromise"):
            try:
                event = IAMCloudTrailEvent.model_validate(incident.raw_event)
                username = str(event.detail.userIdentity.get("userName", ""))
                source_ip = str(event.detail.sourceIPAddress or "")
                action = str(event.detail.eventName or "")

                if not username:
                    return False

                if is_dry_run(incident):
                    return self._build_preview(username, action, source_ip)

                decision = incident.decision
                score = incident.risk_score
                intel_report = incident.intel_summary

                if decision == "IGNORE":
                    logger.info(f"Ignored IAM Compromise for {username} due to low risk score ({score}).")
                    return True

                if decision == "REQUIRE_APPROVAL":
                    logger.info(f"IAM Compromise for {username} requires human approval. Score: {score}")
                    self._notify_slack(username, action, source_ip, score, decision, intel_report)
                    return True

                if decision == "AUTO_ISOLATE":
                    logger.critical(f"IAM Auto-Isolation triggered for {username} on {action} (Score: {score})")
                    emit_metric("FindingsProcessed", 1.0, "Count", {"Playbook": "IAMCompromise"})
                    self._disable_access_keys(username)
                    self._revoke_sessions_and_deny_all(username)
                    self._notify_slack(username, action, source_ip, score, decision, intel_report)
                    return True

            except Exception as e:
                logger.error(f"IAM Compromise Response failed: {str(e)}")
                return False

            return False

    @staticmethod
    def _build_preview(username: str, action: str, source_ip: str) -> dict[str, Any]:
        return {
            "mode": "dry_run",
            "playbook": "IAMCompromise",
            "target_resource": username,
            "summary": "Preview only. No IAM credentials or policies were changed.",
            "planned_actions": [
                {
                    "step": 1,
                    "action": "risk_assessment",
                    "target": username,
                    "details": f"Evaluate risky IAM action '{action}' from source IP '{source_ip or 'unknown'}'.",
                },
                {
                    "step": 2,
                    "action": "disable_access_keys",
                    "target": username,
                    "details": "Disable all active user access keys if decision reaches AUTO_ISOLATE.",
                },
                {
                    "step": 3,
                    "action": "put_user_policy",
                    "target": username,
                    "details": "Attach explicit DenyAll policy to revoke active permissions and sessions.",
                },
                {
                    "step": 4,
                    "action": "notify_slack",
                    "target": username,
                    "details": "Notify operators with risk score, action, and decision path.",
                },
            ],
        }

    def _disable_access_keys(self, username: str) -> None:
        """Disables all active access keys for the user."""
        try:
            response = self.iam.list_access_keys(UserName=username)
            for access_key in response.get("AccessKeyMetadata", []):
                key_id = access_key.get("AccessKeyId")
                if access_key.get("Status") == "Active":
                    self.iam.update_access_key(UserName=username, AccessKeyId=key_id, Status="Inactive")
            logger.info(f"Successfully disabled access keys for {username}")
        except Exception as e:
            logger.error(f"Failed to disable keys for {username}: {str(e)}")

    def _revoke_sessions_and_deny_all(self, username: str) -> None:
        """Attaches an explicit DenyAll inline policy to revoke all active sessions."""
        try:
            deny_policy = {
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}],
            }
            self.iam.put_user_policy(
                UserName=username,
                PolicyName="SOAR_Auto_Deny_All",
                PolicyDocument=json.dumps(deny_policy),
            )
            logger.info(f"Successfully attached DenyAll policy to {username}")
        except Exception as e:
            logger.error(f"Failed to attach DenyAll policy to {username}: {str(e)}")

    def _notify_slack(
        self,
        username: str,
        action: str,
        ip: str,
        score: float,
        decision: str,
        intel_report: dict[str, Any],
    ) -> None:
        """Sends an alert to Slack."""
        try:
            from src.integrations.slack_notifier import SlackNotifier

            notifier = SlackNotifier()
            incident_data = {
                "id": f"IAM-{username}-{action}",
                "severity": "CRITICAL" if decision == "AUTO_ISOLATE" else "HIGH",
                "title": f"IAM Compromise Deteced: {action}",
                "description": f"Suspicious Action: {action}\nUser: {username}\nSource IP: {ip}\nRisk Score: {score}",
                "decision": decision,
                "intel_summary": intel_report,
            }
            notifier.send_incident_alert(incident_data)
        except Exception as e:
            logger.error(f"Failed to notify Slack: {str(e)}")
