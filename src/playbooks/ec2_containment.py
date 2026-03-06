import os
from typing import Dict, Any
from src.playbooks.base import Playbook
from src.core.logger import logger
from src.clients.aws import AWSClientFacade
from src.core.metrics import emit_metric, PlaybookTimer
from src.core.config import config
from pydantic import ValidationError
from src.models.events import GuardDutyEvent

class EC2ContainmentPlaybook(Playbook):
    """Playbook to isolate compromised EC2 instances based on GuardDuty findings."""
    
    def __init__(self):
        self.ec2 = AWSClientFacade.ec2()
        self.s3 = AWSClientFacade.s3()
        self.iam = AWSClientFacade.iam()
        self.isolation_sg_id = os.environ.get('ISOLATION_SG_ID')

    def can_handle(self, event_data: Dict[str, Any]) -> bool:
        try:
            # Quick check if it's a GuardDuty EC2 finding
            source = event_data.get("source")
            if source != "aws.guardduty":
                return False
                
            # Full validation
            event = GuardDutyEvent.model_validate(event_data)
            return "EC2" in event.detail.type or event.detail.service.get('resourceRole') == 'TARGET'
        except ValidationError:
            return False
        except Exception:
            return False

    def execute(self, event_data: Dict[str, Any]) -> bool:
        with PlaybookTimer("EC2Containment"):
            try:
                event = GuardDutyEvent.model_validate(event_data)
                instance_id = None
                if event.detail.resource:
                    instance_id = event.detail.resource.get('instanceDetails', {}).get('instanceId')
                if not instance_id and event.detail.resources:
                    instance_id = event.detail.resources[0].get('instanceDetails', {}).get('instanceId')
                
                if not instance_id:
                    logger.error("No instance ID found in GuardDuty finding")
                    return False
                    
                logger.info(f"Executing EC2 Containment for {instance_id}")
                emit_metric("FindingsProcessed", 1.0, "Count", {"Playbook": "EC2Containment"})
                
                # Step 1: Isolate Network
                if self.isolation_sg_id:
                    self.ec2.modify_instance_attribute(
                        InstanceId=instance_id,
                        Groups=[self.isolation_sg_id]
                    )
                    logger.info(f"Isolated instance {instance_id}")

                # Step 2: Enforce IMDSv2
                try:
                    self.ec2.modify_instance_metadata_options(
                        InstanceId=instance_id,
                        HttpTokens='required',
                        HttpPutResponseHopLimit=1
                    )
                except NotImplementedError:
                    logger.info("Metadata options update not supported by EC2 mock")
                
                # Step 3: Take Snapshot & upload to evidence bucket
                volumes = self.ec2.describe_instances(InstanceIds=[instance_id])['Reservations'][0]['Instances'][0].get('BlockDeviceMappings', [])
                for vol in volumes:
                    vol_id = vol['Ebs']['VolumeId']
                    snapshot = self.ec2.create_snapshot(
                        VolumeId=vol_id,
                        Description=f"Forensic snapshot for finding {event.detail.id}",
                        TagSpecifications=[{
                            'ResourceType': 'snapshot',
                            'Tags': [
                                {'Key': 'Purpose', 'Value': 'forensic-evidence'},
                                {'Key': 'FindingId', 'Value': event.detail.id},
                                {'Key': 'InstanceId', 'Value': instance_id},
                            ]
                        }]
                    )
                    snapshot_id = snapshot.get('SnapshotId', 'unknown')
                    logger.info(f"Created forensic snapshot {snapshot_id} for volume {vol_id}")

                    # Upload evidence metadata to S3 evidence bucket
                    if config.evidence_bucket:
                        self._upload_evidence_metadata(
                            instance_id, snapshot_id, vol_id, event.detail.id
                        )
                
                # Step 4: Stop Instance
                self.ec2.stop_instances(InstanceIds=[instance_id])
                logger.info(f"Stopped instance {instance_id}")
                
                return True
                
            except Exception as e:
                logger.error(f"EC2 Containment failed: {str(e)}", exc_info=True)
                return False

    def _upload_evidence_metadata(
        self, instance_id: str, snapshot_id: str, volume_id: str, finding_id: str
    ) -> None:
        """Upload forensic evidence metadata to the S3 evidence bucket."""
        import json
        from datetime import datetime, timezone
        try:
            metadata = {
                "instance_id": instance_id,
                "snapshot_id": snapshot_id,
                "volume_id": volume_id,
                "finding_id": finding_id,
                "captured_at": datetime.now(timezone.utc).isoformat(),
                "type": "ebs_snapshot_evidence",
            }
            key = f"evidence/{instance_id}/{finding_id}/{snapshot_id}.json"
            self.s3.put_object(
                Bucket=config.evidence_bucket,
                Key=key,
                Body=json.dumps(metadata),
                ServerSideEncryption="aws:kms",
            )
            logger.info(f"Uploaded evidence metadata to s3://{config.evidence_bucket}/{key}")
        except Exception as e:
            logger.warning(f"Failed to upload evidence metadata: {e}")
