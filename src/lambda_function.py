import json
import os
import boto3
import logging

logger = logging.getLogger()
logger.setLevel(logging.INFO)

ec2 = boto3.client('ec2')
sns = boto3.client('sns')

ISOLATION_SG_ID = os.environ.get('ISOLATION_SG_ID')
SNS_TOPIC_ARN = os.environ.get('SNS_TOPIC_ARN')

def lambda_handler(event, context):
    logger.info(f"Received event: {json.dumps(event)}")
    
    try:
        detail = event.get('detail', {})
        finding_type = detail.get('type')
        severity = float(detail.get('severity', 0))
        resource = detail.get('resource', {})
        instance_details = resource.get('instanceDetails', {})
        instance_id = instance_details.get('instanceId')

        if not instance_id:
            logger.warning("No EC2 instance ID found in the GuardDuty finding.")
            return {'statusCode': 400, 'body': 'No Instance ID found'}
            
        # Only respond to Medium/High Severity threats (limit noisy false positives)
        if severity < 7.0:
            logger.info(f"Ignoring finding with severity {severity}. Configured threshold is 7.0 (High).")
            return {'statusCode': 200, 'body': 'Ignored low severity finding'}
            
        # Optional: Filter by specific threat types
        allowed_threats = ['CryptoCurrency', 'Backdoor', 'Trojan', 'Behavior']
        if not any(threat in finding_type for threat in allowed_threats):
            logger.info(f"Ignoring finding category {finding_type}. Not in critical response list.")
            return {'statusCode': 200, 'body': 'Ignored non-critical finding type'}

        logger.info(f"GuardDuty Action Triggered for Instance: {instance_id} | Severity: {severity} | Type: {finding_type}")

        # Execute SOAR playbook
        isolate_instance(instance_id)
        detach_iam_role(instance_id)
        take_snapshot(instance_id, finding_type)
        stop_instance(instance_id)
        tag_instance(instance_id)
        notify_team(instance_id, finding_type)

        return {'statusCode': 200, 'body': f'Successfully responded to threat on {instance_id}'}

    except Exception as e:
        logger.error(f"Error processing GuardDuty event: {str(e)}")
        return {'statusCode': 500, 'body': str(e)}

def isolate_instance(instance_id):
    logger.info(f"Isolating instance: {instance_id} using SG: {ISOLATION_SG_ID}")
    ec2.modify_instance_attribute(
        InstanceId=instance_id,
        Groups=[ISOLATION_SG_ID]
    )

def detach_iam_role(instance_id):
    logger.info(f"Detaching IAM roles from instance {instance_id}")
    try:
        response = ec2.describe_iam_instance_profile_associations(
            Filters=[{'Name': 'instance-id', 'Values': [instance_id]}]
        )
        associations = response.get('IamInstanceProfileAssociations', [])
        for assoc in associations:
            assoc_id = assoc.get('AssociationId')
            logger.info(f"Disassociating IAM profile assoc_id: {assoc_id}")
            ec2.disassociate_iam_instance_profile(AssociationId=assoc_id)
    except Exception as e:
        logger.error(f"Failed to detach IAM role: {str(e)}")

def take_snapshot(instance_id, finding_type):
    from datetime import datetime
    timestamp = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
    logger.info(f"Taking snapshot for volumes of {instance_id}")
    
    response = ec2.describe_instances(InstanceIds=[instance_id])
    volumes = response['Reservations'][0]['Instances'][0].get('BlockDeviceMappings', [])
    
    for volume in volumes:
        vol_id = volume['Ebs']['VolumeId']
        logger.info(f"Snapshotting volume: {vol_id}")
        ec2.create_tags(
            Resources=[
                ec2.create_snapshot(
                    VolumeId=vol_id,
                    Description=f"Forensic Snapshot - {instance_id} - {finding_type}"
                )['SnapshotId']
            ],
            Tags=[
                {'Key': 'Purpose', 'Value': 'IncidentResponse-Forensics'},
                {'Key': 'SourceInstance', 'Value': instance_id},
                {'Key': 'ThreatFinding', 'Value': finding_type},
                {'Key': 'CapturedAt', 'Value': timestamp}
            ]
        )

def stop_instance(instance_id):
    logger.info(f"Stopping instance {instance_id} to halt local execution.")
    ec2.stop_instances(InstanceIds=[instance_id])

def tag_instance(instance_id):
    logger.info(f"Tagging instance {instance_id} as Compromised")
    ec2.create_tags(
        Resources=[instance_id],
        Tags=[
            {'Key': 'SecurityStatus', 'Value': 'Compromised'},
            {'Key': 'SOAR_Action', 'Value': 'Isolated'}
        ]
    )

def notify_team(instance_id, finding_type):
    message = (
        f"🚨 SECURITY ALERT: SOAR Playbook Triggered 🚨\n\n"
        f"Instance ID: {instance_id}\n"
        f"Finding: {finding_type}\n"
        f"Action: Instance Isolated, IAM Roles Detached, Snapshot Captured, Instance STOPPED."
    )
    sns.publish(
        TopicArn=SNS_TOPIC_ARN,
        Subject="AWS Critical Threat Response",
        Message=message
    )
    logger.info("Alert notification published.")
