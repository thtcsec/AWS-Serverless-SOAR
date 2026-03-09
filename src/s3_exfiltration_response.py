import json
import boto3
import logging
import os
from datetime import datetime, timezone, timedelta
import src.integrations as integrations

logger = logging.getLogger()
logger.setLevel(logging.INFO)

s3 = boto3.client('s3')
iam = boto3.client('iam')
sns = boto3.client('sns')

SNS_TOPIC_ARN = os.environ.get('SNS_TOPIC_ARN')
EXFILTRATION_THRESHOLD = int(os.environ.get('EXFILTRATION_THRESHOLD', '10000000000'))  # 10GB default

def lambda_handler(event, context):
    logger.info(f"Received S3 event: {json.dumps(event)}")
    
    try:
        # Parse CloudTrail event for S3 API calls
        detail = event.get('detail', {})
        event_name = detail.get('eventName')
        bucket_name = detail.get('requestParameters', {}).get('bucketName')
        user_identity = detail.get('userIdentity', {})
        source_ip = detail.get('sourceIPAddress')
        
        if not bucket_name or event_name not in ['GetObject', 'ListObjects', 'DownloadFile']:
            logger.info("Ignoring non-S3 data access event")
            return {'statusCode': 200, 'body': 'Ignored non-critical event'}
        
        # Check for potential data exfiltration patterns
        user_arn = user_identity.get('arn', 'unknown')
        
        # Get recent S3 access patterns for this user
        recent_access = get_recent_s3_access(user_arn, bucket_name)
        
        if is_exfiltration_detected(recent_access, event_name):
            logger.warning(f"Data exfiltration activity detected from user {user_arn} on bucket {bucket_name}")
            
            # --- THREAT INTEL ENRICHMENT & SCORING ---
            risk_data = {"risk_score": 0.0, "decision": "AUTO_ISOLATE"}
            intel_report = {}

            if source_ip:
                logger.info(f"Enriching S3 finding with Intel for IP: {source_ip}")
                intel_service = integrations.ThreatIntelService()
                intel_report = intel_service.get_ip_report(source_ip)
                
                scoring_engine = integrations.ScoringEngine()
                # Initial severity for S3 exfiltration is set to 8.0 (High)
                risk_data = scoring_engine.calculate_risk_score(intel_report, 8.0)
                
                logger.info(f"Scoring Result: {json.dumps(risk_data, default=str)}")
                
                if risk_data['decision'] == "IGNORE":
                    logger.info("Risk Score too low. Skipping remediation.")
                    return {'statusCode': 200, 'body': 'Ignored low risk'}
                
                if risk_data['decision'] == "REQUIRE_APPROVAL":
                    logger.info("Requires manual approval.")
                    send_exfiltration_alert(bucket_name, user_arn, source_ip, risk_data, intel_report, approved=False)
                    return {'statusCode': 200, 'body': 'Pending approval'}

            # Execute response playbook (Decision: AUTO_ISOLATE or High Initial Risk if no IP)
            block_user_access(user_arn, bucket_name)
            enable_s3_protection(bucket_name)
            send_exfiltration_alert(bucket_name, user_arn, source_ip, risk_data, intel_report, approved=True)
            
            return {
                'statusCode': 200,
                'body': f'Data exfiltration response executed for bucket {bucket_name}'
            }
        
        return {'statusCode': 200, 'body': 'No exfiltration detected'}
        
    except Exception as e:
        logger.error(f"Error processing S3 event: {str(e)}")
        return {'statusCode': 500, 'body': f'Error: {str(e)}'}

def get_recent_s3_access(user_arn, bucket_name, hours=24):
    """Get recent S3 access patterns for analysis"""
    # This would typically query CloudTrail logs or CloudWatch metrics
    # For demo purposes, we'll simulate the analysis
    try:
        # Query CloudTrail for S3 events in last 24 hours
        cloudtrail = boto3.client('cloudtrail')
        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(hours=hours)
        
        response = cloudtrail.lookup_events(
            LookupAttributes=[
                {'AttributeKey': 'ResourceName', 'AttributeValue': bucket_name}
            ],
            StartTime=start_time,
            EndTime=end_time,
            MaxResults=50
        )
        
        events = response.get('Events', [])
        access_count = len([e for e in events if user_arn in str(e.get('Username', ''))])
        
        return {
            'access_count': access_count,
            'events': events[:10],  # Return last 10 events
            'total_bytes_downloaded': estimate_download_size(events)
        }
        
    except Exception as e:
        logger.error(f"Error querying CloudTrail: {str(e)}")
        return {'access_count': 0, 'events': [], 'total_bytes_downloaded': 0}

def estimate_download_size(events):
    """Estimate total downloaded bytes from events"""
    total_bytes = 0
    for event in events:
        if event.get('EventName') == 'GetObject':
            # This would need additional logic to get actual file sizes
            total_bytes += 1024 * 1024  # Estimate 1MB per download
    return total_bytes

def is_exfiltration_detected(access_data, current_event):
    """Analyze access patterns to detect potential exfiltration"""
    total_bytes = access_data.get('total_bytes_downloaded', 0)
    access_count = access_data.get('access_count', 0)
    
    # Rule 1: Large volume downloads
    if total_bytes > EXFILTRATION_THRESHOLD:
        logger.warning(f"Large volume download detected: {total_bytes} bytes")
        return True
    
    # Rule 2: High frequency access
    if access_count > 1000:  # More than 1000 accesses in 24 hours
        logger.warning(f"High frequency access detected: {access_count} accesses")
        return True
    
    # Rule 3: Unusual time patterns (access during off-hours)
    current_hour = datetime.now().hour
    if current_hour >= 22 or current_hour <= 6:  # Late night access
        logger.warning(f"Off-hours access detected at {current_hour}:00")
        return True
    
    return False

def block_user_access(user_arn, bucket_name):
    """Block user access to the compromised bucket"""
    try:
        # Create deny statement for the user
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
        
        # Safe Append: Get existing policy first
        try:
            response = s3.get_bucket_policy(Bucket=bucket_name)
            policy = json.loads(response['Policy'])
        except s3.exceptions.ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchBucketPolicy':
                policy = {
                    "Version": "2012-10-17",
                    "Statement": []
                }
            else:
                raise e
                
        # Append the new deny statement
        if 'Statement' in policy:
            policy['Statement'].append(deny_statement)
        else:
            policy['Statement'] = [deny_statement]
            
        s3.put_bucket_policy(
            Bucket=bucket_name,
            Policy=json.dumps(policy)
        )
        
        logger.info(f"Applied deny policy for user {user_arn} on bucket {bucket_name}")
        
    except Exception as e:
        logger.error(f"Error blocking user access: {str(e)}")

def enable_s3_protection(bucket_name):
    """Enable additional S3 protection mechanisms"""
    try:
        # Enable MFA Delete if not already enabled
        s3.put_bucket_versioning(
            Bucket=bucket_name,
            VersioningConfiguration={
                'Status': 'Enabled',
                'MFADelete': 'Enabled'
            }
        )
        
        # Enable S3 Object Lock if supported
        try:
            s3.put_object_lock_configuration(
                Bucket=bucket_name,
                ObjectLockConfiguration={
                    'ObjectLockEnabled': 'Enabled',
                    'Rule': {
                        'DefaultRetention': {
                            'Mode': 'GOVERNANCE',
                            'Days': 30
                        }
                    }
                }
            )
        except s3.exceptions.ClientError as e:
            if 'ObjectLockConfigurationNotSupported' in str(e):
                logger.info("Object Lock not supported for this bucket")
            else:
                raise e
        
        logger.info(f"Enhanced S3 protection enabled for bucket {bucket_name}")
        
    except Exception as e:
        logger.error(f"Error enabling S3 protection: {str(e)}")

def send_exfiltration_alert(bucket_name, user_arn, source_ip, risk_data=None, intel_report=None, approved=True):
    action_status = "AUTOMATED RESPONSE EXECUTED" if approved else "PENDING APPROVAL"
    
    score_info = ""
    if risk_data:
        score_info = (
            f"\nRisk Score: {risk_data.get('risk_score')}/100\n"
            f"Decision: {risk_data.get('decision')}\n"
            f"VT Malicious: {risk_data.get('breakdown', {}).get('vt_malicious')}\n"
        )

    message = f"""
🚨 DATA EXFILTRATION DETECTED ({action_status})

Bucket: {bucket_name}
User: {user_arn}
Source IP: {source_ip}
{score_info}

Action Status: {"Remediation Applied" if approved else "Waiting for Approval"}
Time: {datetime.now(timezone.utc).isoformat()}
        """
        
    sns.publish(
        TopicArn=SNS_TOPIC_ARN,
        Subject=f"S3 Security Alert: {action_status}",
        Message=message.strip()
    )
    
    try:
        from src.integrations.jira import create_jira_issue
        jira_desc = f"{message}\n\nIntel Details: {json.dumps(intel_report, indent=2, default=str)}"
        # Severity 9 for S3 Exfiltration
        create_jira_issue(bucket_name, f"S3_EXFIL_{user_arn}", 9, jira_desc)
    except Exception as e:
        logger.error(f"Failed to invoke Jira integration: {e}")
