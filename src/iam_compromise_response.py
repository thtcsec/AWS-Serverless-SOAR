import json
import boto3
import logging
import os
from datetime import datetime, timezone, timedelta
import src.integrations as integrations

logger = logging.getLogger()
logger.setLevel(logging.INFO)

iam = boto3.client('iam')
cloudtrail = boto3.client('cloudtrail')
sns = boto3.client('sns')

SNS_TOPIC_ARN = os.environ.get('SNS_TOPIC_ARN')
RISKY_ACTIONS = [
    'CreateUser', 'CreateAccessKey', 'CreateLoginProfile', 'AddUserToGroup',
    'AttachUserPolicy', 'AttachRolePolicy', 'CreateRole', 'AssumeRole'
]
ADMIN_ACTIONS = [
    'DeleteUser', 'DeleteAccessKey', 'DeleteLoginProfile', 'RemoveUserFromGroup',
    'DetachUserPolicy', 'DetachRolePolicy', 'DeleteRole', 'UpdateAssumeRolePolicy'
]

def lambda_handler(event, context):
    try:
        detail = event.get('detail', {})
        event_name = detail.get('eventName')
        user_identity = detail.get('userIdentity', {})
        source_ip = detail.get('sourceIPAddress')
        error_code = detail.get('errorCode')
        
        # Only process IAM events
        if not event_name or not event_name.startswith(('Create', 'Delete', 'Update', 'Attach', 'Detach', 'Add', 'Remove')):
            return {'statusCode': 200, 'body': 'Non-IAM event ignored'}
        
        user_arn = user_identity.get('arn', 'unknown')
        username = user_identity.get('userName', 'unknown')
        
        # Analyze the IAM activity
        initial_risk = get_initial_risk_score(event_name, user_identity, source_ip, error_code)
        
        risk_data = {"risk_score": 0.0, "decision": "IGNORE", "breakdown": {}}
        intel_report = {}

        if source_ip:
            intel_service = integrations.ThreatIntelService()
            intel_report = intel_service.get_ip_report(source_ip)
            
            scoring_engine = integrations.ScoringEngine()
            # Note: IAM risk score is 0-10, we scale it to match our engine's expectations (or vice versa)
            risk_data = scoring_engine.calculate_risk_score(intel_report, initial_risk)
            
            logger.info(f"Scoring Result: {json.dumps(risk_data, default=str)}")
            
            if risk_data['decision'] == "IGNORE":
                logger.info("Risk Score too low. Skipping remediation.")
                return {'statusCode': 200, 'body': 'Ignored low risk'}
            
            if risk_data['decision'] == "REQUIRE_APPROVAL":
                logger.info("Requires manual approval.")
                send_security_alert(username, user_arn, event_name, source_ip, risk_data, intel_report, approved=False)
                return {'statusCode': 200, 'body': 'Pending approval'}

        # Execute response playbook (Decision: AUTO_ISOLATE or High Initial Risk if no IP)
        investigate_compromise(username, user_arn, event_name, source_ip)
        quarantine_if_needed(username, user_arn, risk_data, initial_risk)
        send_security_alert(username, user_arn, event_name, source_ip, risk_data, intel_report, approved=True)
        return {'statusCode': 200, 'body': 'response executed'}
        
    except Exception as e:
        logger.error(f"Error processing IAM event: {str(e)}")
        return {'statusCode': 500, 'body': f'Error: {str(e)}'}

def get_initial_risk_score(event_name, user_identity, source_ip, error_code):
    """Calculate baseline risk score for IAM activity (0-10 scale)"""
    score = 0
    
    # Base score for action type
    if event_name in ADMIN_ACTIONS:
        score += 5
    elif event_name in RISKY_ACTIONS:
        score += 3
    
    # Bonus points for suspicious patterns
    if error_code:
        score += 2  # Failed attempts are suspicious
    
    # Check for unusual source IPs
    if is_unusual_source_ip(source_ip, user_identity):
        score += 3
    
    # Check for privilege escalation patterns
    if is_privilege_escalation(event_name):
        score += 4
    
    # Check time-based patterns
    if is_suspicious_timing():
        score += 2
    
    return min(score, 10)  # Cap at 10

def is_unusual_source_ip(source_ip, user_identity):
    """Check if source IP is unusual for this user"""
    try:
        # Get recent CloudTrail events for this user
        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(days=30)
        
        response = cloudtrail.lookup_events(
            LookupAttributes=[
                {'AttributeKey': 'Username', 'AttributeValue': user_identity.get('userName', '')}
            ],
            StartTime=start_time,
            EndTime=end_time,
            MaxResults=100
        )
        
        events = response.get('Events', [])
        known_ips = set()
        
        for event in events:
            raw_event = event.get('CloudTrailEvent')
            if raw_event:
                event_data = json.loads(raw_event)
                event_source_ip = event_data.get('sourceIPAddress')
                if event_source_ip:
                    known_ips.add(event_source_ip)
        
        # If this IP hasn't been seen before, it's unusual
        return source_ip not in known_ips and len(known_ips) > 0
        
    except Exception as e:
        logger.error(f"Error checking source IP history: {str(e)}")
        return False

def is_privilege_escalation(event_name):
    """Check if action indicates privilege escalation"""
    escalation_actions = [
        'AttachUserPolicy', 'AttachRolePolicy', 'AddUserToGroup',
        'CreateRole', 'UpdateAssumeRolePolicy', 'PutUserPolicy'
    ]
    return event_name in escalation_actions

def is_suspicious_timing():
    """Check if current time is suspicious for IAM changes"""
    current_hour = datetime.now().hour
    # Late night or early morning IAM changes are suspicious
    return current_hour >= 23 or current_hour <= 5

def investigate_compromise(username, user_arn, event_name, source_ip):
    """Investigate potential IAM compromise"""
    try:
        logger.info(f"Investigating IAM compromise for user: {username}")
        
        # Get user's recent activity
        recent_activity = get_user_recent_activity(username)
        
        # Check for multiple failed login attempts
        failed_logins = count_failed_logins(username)
        
        # Check for concurrent sessions
        concurrent_sessions = check_concurrent_sessions(username)
        
        investigation_result = {
            'username': username,
            'event_name': event_name,
            'source_ip': source_ip,
            'recent_activity_count': len(recent_activity),
            'failed_login_attempts': failed_logins,
            'concurrent_sessions': concurrent_sessions,
            'investigation_time': datetime.now(timezone.utc).isoformat()
        }
        
        logger.info(f"Investigation result: {json.dumps(investigation_result)}")
        
        return investigation_result
        
    except Exception as e:
        logger.error(f"Error during investigation: {str(e)}")
        return {}

def get_user_recent_activity(username, hours=24):
    """Get user's recent IAM activity"""
    try:
        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(hours=hours)
        
        response = cloudtrail.lookup_events(
            LookupAttributes=[
                {'AttributeKey': 'Username', 'AttributeValue': username}
            ],
            StartTime=start_time,
            EndTime=end_time,
            MaxResults=50
        )
        
        return response.get('Events', [])
        
    except Exception as e:
        logger.error(f"Error getting user activity: {str(e)}")
        return []

def count_failed_logins(username, hours=24):
    """Count failed login attempts for user"""
    try:
        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(hours=hours)
        
        response = cloudtrail.lookup_events(
            LookupAttributes=[
                {'AttributeKey': 'Username', 'AttributeValue': username}
            ],
            StartTime=start_time,
            EndTime=end_time,
            MaxResults=100
        )
        
        events = response.get('Events', [])
        failed_count = 0
        
        for event in events:
            event_data = json.loads(event.get('CloudTrailEvent', '{}'))
            if event_data.get('errorCode') in ['AccessDenied', 'InvalidClientTokenId']:
                failed_count += 1
        
        return failed_count
        
    except Exception as e:
        logger.error(f"Error counting failed logins: {str(e)}")
        return 0

def check_concurrent_sessions(username):
    """Check for concurrent sessions from different IPs"""
    try:
        recent_activity = get_user_recent_activity(username, hours=1)
        unique_ips = set()
        
        for event in recent_activity:
            event_data = json.loads(event.get('CloudTrailEvent', '{}'))
            source_ip = event_data.get('sourceIPAddress')
            if source_ip:
                unique_ips.add(source_ip)
        
        return len(unique_ips)
        
    except Exception as e:
        logger.error(f"Error checking concurrent sessions: {str(e)}")
        return 0

def quarantine_if_needed(username, user_arn, risk_data, initial_score):
    """Quarantine user based on decision or very high baseline risk"""
    try:
        # Check decision from engine OR fallback to high initial score if engine was bypassed
        should_quarantine = (risk_data.get('decision') == "AUTO_ISOLATE" or initial_score >= 7)
        
        if should_quarantine:
            logger.info(f"Quarantining user {username} (Score: {risk_data.get('risk_score', initial_score)})")
            
            # Disable user's access keys
            disable_user_access_keys(username)
            # Remove user from privileged groups
            remove_from_privileged_groups(username)
            # Enable MFA
            enforce_mfa(username)
            
            logger.info(f"User {username} quarantined successfully")
        else:
            logger.info(f"Quarantine not required for {username}")
            
    except Exception as e:
        logger.error(f"Error quarantining user: {str(e)}")

def disable_user_access_keys(username):
    """Disable all access keys for the user"""
    try:
        response = iam.list_access_keys(UserName=username)
        
        for access_key in response.get('AccessKeyMetadata', []):
            access_key_id = access_key.get('AccessKeyId')
            if access_key.get('Status') == 'Active':
                iam.update_access_key(
                    UserName=username,
                    AccessKeyId=access_key_id,
                    Status='Inactive'
                )
                logger.info(f"Disabled access key {access_key_id} for user {username}")
                
    except Exception as e:
        logger.error(f"Error disabling access keys: {str(e)}")

def remove_from_privileged_groups(username):
    """Remove user from privileged IAM groups"""
    try:
        privileged_groups = ['Administrators', 'PowerUsers', 'Developers', 'DevOps']
        
        response = iam.list_groups_for_user(UserName=username)
        
        for group in response.get('Groups', []):
            group_name = group.get('GroupName')
            if group_name in privileged_groups:
                iam.remove_user_from_group(
                    GroupName=group_name,
                    UserName=username
                )
                logger.info(f"Removed user {username} from privileged group {group_name}")
                
    except Exception as e:
        logger.error(f"Error removing from groups: {str(e)}")

def enforce_mfa(username):
    """Enforce MFA for the user"""
    try:
        # Check if user has MFA device
        response = iam.list_mfa_devices(UserName=username)
        
        if not response.get('MFADevices'):
            logger.warning(f"User {username} does not have MFA enabled")
            # In a real implementation, you might want to force password reset
            # or temporarily disable the account until MFA is setup
            
    except Exception as e:
        logger.error(f"Error enforcing MFA: {str(e)}")

def send_security_alert(username, user_arn, event_name, source_ip, risk_data=None, intel_report=None, approved=True):
    action_status = "AUTOMATED RESPONSE EXECUTED" if approved else "PENDING APPROVAL"
    
    score_info = ""
    if risk_data:
        score_info = (
            f"\nRisk Score: {risk_data.get('risk_score')}/100\n"
            f"Decision: {risk_data.get('decision')}\n"
            f"VT Malicious: {risk_data.get('breakdown', {}).get('vt_malicious')}\n"
        )

    message = f"""
🚨 IAM COMPROMISE DETECTED ({action_status})

Username: {username}
User ARN: {user_arn}
Action: {event_name}
Source IP: {source_ip}
{score_info}

Next Steps:
1. Verify user identity through out-of-band channel
2. Review all recent IAM changes
3. Monitor for additional suspicious activity
        """
        
    try:
        sns.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject=f"IAM Security Alert: {action_status}",
            Message=message.strip()
        )
    except Exception as e:
        logger.error(f"Failed to send SNS alert: {e}")
    
    try:
        from src.integrations.jira import create_jira_issue
        jira_desc = f"{message}\n\nIntel Details: {json.dumps(intel_report, indent=2, default=str)}"
        create_jira_issue(username, f"IAM_{event_name}", 8, jira_desc)
    except Exception as e:
        logger.error(f"Failed to invoke Jira integration: {e}")
