import os
from typing import Dict, Any
from src.playbooks.base import Playbook
from src.core.logger import logger
from src.clients.aws import AWSClientFacade
from pydantic import ValidationError
from src.models.events import S3CloudTrailEvent
from src.core.config import config

class S3ExfiltrationPlaybook(Playbook):
    """Playbook to block S3 data exfiltration detected via CloudTrail."""
    
    def __init__(self):
        self.s3 = AWSClientFacade.s3()

    def can_handle(self, event_data: Dict[str, Any]) -> bool:
        try:
            event = S3CloudTrailEvent.model_validate(event_data)
            return event.detail.eventName in ['GetObject', 'ListObjects', 'DownloadFile']
        except ValidationError:
            return False

    def execute(self, event_data: Dict[str, Any]) -> bool:
        try:
            event = S3CloudTrailEvent.model_validate(event_data)
            
            # Extract basic data
            bucket_name = event.detail.requestParameters.get('bucketName') if event.detail.requestParameters else None
            user_arn = event.detail.userIdentity.get('arn')
            
            if not bucket_name or not user_arn:
                return False

            logger.warning(f"S3 Exfiltration detected on bucket {bucket_name} by user {user_arn}")
            
            self._block_user_access(user_arn, bucket_name)
            self._enable_s3_protection(bucket_name)
            
            return True
            
        except Exception as e:
            logger.error(f"S3 Exfiltration Response failed: {str(e)}")
            return False

    def _block_user_access(self, user_arn: str, bucket_name: str) -> None:
        import json
        from datetime import datetime
        try:
            deny_statement = {
                "Sid": f"S3ExfilBlock{datetime.now().strftime('%Y%m%d%H%M%S')}",
                "Effect": "Deny",
                "Principal": {"AWS": user_arn},
                "Action": "s3:*",
                "Resource": [
                    f"arn:aws:s3:::{bucket_name}",
                    f"arn:aws:s3:::{bucket_name}/*"
                ]
            }
            
            try:
                response = self.s3.get_bucket_policy(Bucket=bucket_name)
                policy = json.loads(response['Policy'])
            except self.s3.exceptions.ClientError:
                policy = {"Version": "2012-10-17", "Statement": []}
                    
            if 'Statement' in policy:
                policy['Statement'].append(deny_statement)
            else:
                policy['Statement'] = [deny_statement]
                
            self.s3.put_bucket_policy(
                Bucket=bucket_name,
                Policy=json.dumps(policy)
            )
            logger.info("S3 Bucket Policy updated to block user.")
        except Exception as e:
            logger.error(f"Failed to apply bucket policy: {str(e)}")

    def _enable_s3_protection(self, bucket_name: str) -> None:
        try:
            self.s3.put_bucket_versioning(
                Bucket=bucket_name,
                VersioningConfiguration={'Status': 'Enabled'}
            )
            # Enable Object Lock in Governance Mode
            try:
                self.s3.put_object_lock_configuration(
                    Bucket=bucket_name,
                    ObjectLockConfiguration={
                        'ObjectLockEnabled': 'Enabled',
                        'Rule': {'DefaultRetention': {'Mode': 'GOVERNANCE', 'Days': 30}}
                    }
                )
            except self.s3.exceptions.ClientError as e:
                logger.warning(f"Could not enable object lock: {str(e)}")
        except Exception as e:
            logger.error(f"Failed to enable S3 protection: {str(e)}")
