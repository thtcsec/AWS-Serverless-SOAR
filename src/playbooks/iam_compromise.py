import os
import json
from typing import Dict, Any
from src.playbooks.base import Playbook
from src.core.logger import logger
from src.clients.aws import AWSClientFacade
from src.core.metrics import emit_metric, PlaybookTimer
from pydantic import ValidationError
from src.models.events import IAMCloudTrailEvent

class IAMCompromisePlaybook(Playbook):
    """Playbook to react to IAM compromise events."""
    
    def __init__(self):
        self.iam = AWSClientFacade.iam()
        self.risky_actions = [
            'CreateUser', 'CreateAccessKey', 'AddUserToGroup',
            'AttachUserPolicy', 'AttachRolePolicy', 'CreateRole'
        ]

    def can_handle(self, event_data: Dict[str, Any]) -> bool:
        try:
            event = IAMCloudTrailEvent.model_validate(event_data)
            return event.detail.eventName in self.risky_actions
        except ValidationError:
            return False

    def execute(self, event_data: Dict[str, Any]) -> bool:
        with PlaybookTimer("IAMCompromise"):
            try:
                event = IAMCloudTrailEvent.model_validate(event_data)
                username = str(event.detail.userIdentity.get('userName', ''))
                source_ip = str(event.detail.sourceIPAddress or '')
                action = str(event.detail.eventName or '')
                
                if not username:
                    return False

                # 1. Threat Intel & Scoring
                intel_report = {}
                risk_data = {"decision": "IGNORE", "risk_score": 0.0}
                
                if source_ip and not source_ip.endswith('.amazonaws.com'):
                    from src.integrations.intel import ThreatIntelService
                    from src.integrations.scoring import ScoringEngine
                    
                    intel_service = ThreatIntelService()
                    scoring_engine = ScoringEngine()
                    
                    intel_report = intel_service.get_ip_report(source_ip)
                    # Baseline severity for IAM actions is high (6.0)
                    risk_data = scoring_engine.calculate_risk_score(intel_report, initial_severity=6.0)

                decision = str(risk_data.get("decision", "IGNORE"))
                raw_score = risk_data.get("risk_score", 0.0)
                score = float(str(raw_score))

                # 2. Decision Routing
                if decision == "IGNORE":
                    logger.info(f"Ignored IAM Compromise for {username} due to low risk score ({score}).")
                    return True
                    
                elif decision == "REQUIRE_APPROVAL":
                    logger.info(f"IAM Compromise for {username} requires human approval. Score: {score}")
                    self._notify_slack(username, action, source_ip, score, decision, intel_report)
                    return True
                    
                elif decision == "AUTO_ISOLATE":
                    logger.critical(f"IAM Auto-Isolation triggered for {username} on {action} (Score: {score})")
                    emit_metric("FindingsProcessed", 1.0, "Count", {"Playbook": "IAMCompromise"})
                    
                    # Remediation Execution
                    self._disable_access_keys(username)
                    self._revoke_sessions_and_deny_all(username)
                    
                    # Notify
                    self._notify_slack(username, action, source_ip, score, decision, intel_report)
                    return True
                    
            except Exception as e:
                logger.error(f"IAM Compromise Response failed: {str(e)}")
                return False
            
            return False

    def _disable_access_keys(self, username: str) -> None:
        """Disables all active access keys for the user."""
        try:
            response = self.iam.list_access_keys(UserName=username)
            for access_key in response.get('AccessKeyMetadata', []):
                key_id = access_key.get('AccessKeyId')
                if access_key.get('Status') == 'Active':
                    self.iam.update_access_key(
                        UserName=username,
                        AccessKeyId=key_id,
                        Status='Inactive'
                    )
            logger.info(f"Successfully disabled access keys for {username}")
        except Exception as e:
            logger.error(f"Failed to disable keys for {username}: {str(e)}")

    def _revoke_sessions_and_deny_all(self, username: str) -> None:
        """Attaches an explicit DenyAll inline policy to revoke all active sessions."""
        try:
            deny_policy = {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Deny",
                        "Action": "*",
                        "Resource": "*"
                    }
                ]
            }
            self.iam.put_user_policy(
                UserName=username,
                PolicyName="SOAR_Auto_Deny_All",
                PolicyDocument=json.dumps(deny_policy)
            )
            logger.info(f"Successfully attached DenyAll policy to {username}")
        except Exception as e:
            logger.error(f"Failed to attach DenyAll policy to {username}: {str(e)}")

    def _notify_slack(self, username: str, action: str, ip: str, score: float, decision: str, intel_report: Dict[str, Any]) -> None:
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
                "intel_summary": intel_report
            }
            notifier.send_incident_alert(incident_data)
        except Exception as e:
            logger.error(f"Failed to notify Slack: {str(e)}")
