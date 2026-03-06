import os
from typing import Dict, Any
from src.playbooks.base import Playbook
from src.core.logger import logger
from src.clients.aws import AWSClientFacade
from pydantic import ValidationError
from src.models.events import GuardDutyEvent

class EC2ContainmentPlaybook(Playbook):
    """Playbook to isolate compromised EC2 instances based on GuardDuty findings."""
    
    def __init__(self):
        self.ec2 = AWSClientFacade.ec2()
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
            
            # Step 3: Take Snapshot
            volumes = self.ec2.describe_instances(InstanceIds=[instance_id])['Reservations'][0]['Instances'][0].get('BlockDeviceMappings', [])
            for vol in volumes:
                vol_id = vol['Ebs']['VolumeId']
                self.ec2.create_snapshot(
                    VolumeId=vol_id,
                    Description=f"Forensic snapshot for finding {event.detail.id}"
                )
            
            # Step 4: Stop Instance
            self.ec2.stop_instances(InstanceIds=[instance_id])
            logger.info(f"Stopped instance {instance_id}")
            
            return True
            
        except Exception as e:
            logger.error(f"EC2 Containment failed: {str(e)}", exc_info=True)
            return False
