import json
import os
import boto3
import logging
import src.integrations as integrations

logger = logging.getLogger()
logger.setLevel(logging.INFO)

ec2 = boto3.client('ec2')
sns = boto3.client('sns')
iam = boto3.client('iam')

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

        # --- THREAT INTEL ENRICHMENT & SCORING ---
        remote_ip = detail.get('service', {}).get('action', {}).get('networkConnectionAction', {}).get('remoteIpDetails', {}).get('ipAddressV4')
        
        risk_data = {"risk_score": 0.0, "decision": "AUTO_ISOLATE"} # Default for non-network findings
        intel_report = {}

        if remote_ip:
            logger.info(f"Enriching finding with Intel for IP: {remote_ip}")
            intel_service = integrations.ThreatIntelService()
            intel_report = intel_service.get_ip_report(remote_ip)
            
            scoring_engine = integrations.ScoringEngine()
            risk_data = scoring_engine.calculate_risk_score(intel_report, severity)
            
            logger.info(f"Scoring Result: {json.dumps(risk_data)}")
            
            if risk_data['decision'] == "IGNORE":
                logger.info(f"Risk Score {risk_data['risk_score']} is too low. Skipping remediation.")
                return {'statusCode': 200, 'body': f"Ignored due to low risk score: {risk_data['risk_score']}"}
            
            if risk_data['decision'] == "REQUIRE_APPROVAL":
                logger.info(f"Risk Score {risk_data['risk_score']} requires manual approval. Notifying team.")
                notify_team(instance_id, finding_type, severity, risk_data, intel_report, approved=False)
                return {'statusCode': 200, 'body': 'Pending approval'}

        # --- REMEDIATION ---
        logger.info(f"Proceeding with AUTO_ISOLATE for Instance: {instance_id}")
        isolate_instance(instance_id)
        enforce_imdsv2(instance_id)
        detach_iam_role(instance_id)
        revoke_active_sessions(instance_id)
        tag_instance(instance_id)
        take_snapshot(instance_id, finding_type)
        stop_instance(instance_id)
        
        notify_team(instance_id, finding_type, severity, risk_data, intel_report, approved=True)

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

def enforce_imdsv2(instance_id):
    logger.info(f"Enforcing IMDSv2 on instance {instance_id} to prevent SSRF metadata theft.")
    try:
        ec2.modify_instance_metadata_options(
            InstanceId=instance_id,
            HttpTokens='required',
            HttpEndpoint='enabled'
        )
    except Exception as e:
        logger.error(f"Failed to enforce IMDSv2: {str(e)}")

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

def revoke_active_sessions(instance_id):
    logger.info(f"Attempting to revoke active IAM sessions associated with {instance_id}")
    try:
        # First, we need to find the actual IAM Role name attached to the instance
        response = ec2.describe_instances(InstanceIds=[instance_id])
        iam_profile_arn = response['Reservations'][0]['Instances'][0].get('IamInstanceProfile', {}).get('Arn')
        
        if not iam_profile_arn:
            logger.info("No IAM profile attached, skipping session revocation.")
            return
            
        # Extract role name from instance profile (often 1:1, though technically profiles can have multiple)
        # Boto3 iam get_instance_profile is needed
        profile_name = iam_profile_arn.split('/')[-1]
        profile_info = iam.get_instance_profile(InstanceProfileName=profile_name)
        
        roles = profile_info['InstanceProfile']['Roles']
        if not roles:
            return
            
        # Revoke sessions for the primary role by attaching an inline deny-all policy
        # Valid only for sessions issued before this exact moment
        from datetime import datetime, timezone
        timestamp = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
        
        for role in roles:
            role_name = role['RoleName']
            logger.info(f"Revoking active sessions for IAM Role: {role_name}")
            policy_document = {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Deny",
                        "Action": "*",
                        "Resource": "*",
                        "Condition": {
                            "DateLessThan": {
                                "aws:TokenIssueTime": timestamp
                            }
                        }
                    }
                ]
            }
            iam.put_role_policy(
                RoleName=role_name,
                PolicyName=f"SOAR-SessionRevocation-{instance_id}",
                PolicyDocument=json.dumps(policy_document)
            )
    except Exception as e:
        logger.error(f"Failed to revoke active IAM sessions: {str(e)}")

def take_snapshot(instance_id, finding_type):
    from datetime import datetime, timezone
    timestamp = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
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

def notify_team(instance_id, finding_type, severity, risk_data=None, intel_report=None, approved=True):
    action_status = "AUTOMATED RESPONSE EXECUTED" if approved else "PENDING APPROVAL"
    action_str = "Instance Isolated, IAM Revoked, Snapshot Captured, STOPPED." if approved else "Waiting for Human-in-the-Loop approval via Slack/Jira."
    
    score_info = ""
    if risk_data:
        score_info = (
            f"\nRisk Score: {risk_data['risk_score']}/100\n"
            f"Decision: {risk_data['decision']}\n"
            f"VT Malicious: {risk_data['breakdown'].get('vt_malicious')}\n"
            f"AbuseIPDB Score: {risk_data['breakdown'].get('abuse_confidence')}\n"
        )

    message = (
        f"🚨 SECURITY ALERT: SOAR Playbook ({action_status})\n\n"
        f"Instance ID: {instance_id}\n"
        f"Finding: {finding_type}\n"
        f"Severity: {severity}\n"
        f"{score_info}\n"
        f"Current Status: {action_str}"
    )
    
    sns.publish(
        TopicArn=SNS_TOPIC_ARN,
        Subject=f"AWS Security Response: {action_status}",
        Message=message
    )
    logger.info(f"Alert notification published ({action_status}).")
    
    # Update Jira Integration
    try:
        from integrations.jira import create_jira_issue
        jira_desc = f"{message}\n\nIntel Details: {json.dumps(intel_report, indent=2)}"
        create_jira_issue(instance_id, finding_type, severity, jira_desc)
    except Exception as e:
        logger.error(f"Failed to invoke Jira integration: {e}")

