import os
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
                username = event.detail.userIdentity.get('userName')
                
                if not username:
                    return False

                logger.critical(f"IAM Compromise path executed for user {username} on action {event.detail.eventName}")
                emit_metric("FindingsProcessed", 1.0, "Count", {"Playbook": "IAMCompromise"})
                
                self._disable_access_keys(username)
                return True
                
            except Exception as e:
                logger.error(f"IAM Compromise Response failed: {str(e)}")
                return False

    def _disable_access_keys(self, username: str) -> None:
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
            logger.error(f"Failed to disable keys: {str(e)}")
