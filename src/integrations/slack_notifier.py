"""
Enterprise SOAR - Slack Integration
Sends notifications to Slack channels for incident response
"""

import json
import os
import boto3
import logging
import requests
from datetime import datetime, timezone
from botocore.exceptions import ClientError

# Configure logging
logging.basicConfig(
    level=getattr(logging, os.environ.get('LOG_LEVEL', 'INFO')),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class SlackNotifier:
    """Enterprise Slack notification system for SOAR"""
    
    def __init__(self):
        self.ssm_client = boto3.client('ssm')
        self.webhook_url = self._get_slack_webhook_url()
        
    def _get_slack_webhook_url(self):
        """Retrieve Slack webhook URL from AWS Systems Manager Parameter Store"""
        try:
            response = self.ssm_client.get_parameter(
                Name='/soar/slack/webhook_url',
                WithDecryption=True
            )
            return response['Parameter']['Value']
        except ClientError as e:
            logger.error(f"Failed to retrieve Slack webhook URL: {str(e)}")
            raise
    
    def send_incident_alert(self, incident_data):
        """
        Send incident alert to Slack
        
        Args:
            incident_data (dict): Incident information
            
        Returns:
            dict: Notification result
        """
        try:
            severity = incident_data.get('severity_classification', {})
            severity_level = severity.get('severity_level', 'UNKNOWN')
            priority = severity.get('priority', 'P4')
            
            # Determine color based on severity
            color_map = {
                'CRITICAL': 'danger',
                'HIGH': 'warning',
                'MEDIUM': 'warning',
                'LOW': 'good'
            }
            color = color_map.get(severity_level, 'good')
            
            # Build Slack message
            message = {
                "username": "SOAR Bot",
                "icon_emoji": ":rotating_light:",
                "attachments": [
                    {
                        "color": color,
                        "title": f"🚨 Security Incident Detected - {severity_level}",
                        "title_link": "https://console.aws.amazon.com/guardduty/",
                        "fields": [
                            {
                                "title": "Priority",
                                "value": priority,
                                "short": True
                            },
                            {
                                "title": "Severity Score",
                                "value": str(severity.get('severity_score', 0)),
                                "short": True
                            },
                            {
                                "title": "Instance ID",
                                "value": incident_data.get('isolation_result', {}).get('instance_id', 'N/A'),
                                "short": True
                            },
                            {
                                "title": "Account",
                                "value": incident_data.get('original_finding', {}).get('account', 'N/A'),
                                "short": True
                            },
                            {
                                "title": "Finding Type",
                                "value": severity.get('finding_type', 'N/A'),
                                "short": True
                            },
                            {
                                "title": "Detection Time",
                                "value": severity.get('classification_timestamp', 'N/A'),
                                "short": True
                            }
                        ],
                        "footer": "SOAR Platform",
                        "ts": int(datetime.now(timezone.utc).timestamp())
                    }
                ]
            }
            
            # Add threat context if available
            threat_context = incident_data.get('threat_context', {})
            if any(threat_context.values()):
                threat_fields = []
                if threat_context.get('is_malware_related'):
                    threat_fields.append({"title": "🦠 Malware Detected", "value": "Yes", "short": True})
                if threat_context.get('is_data_exfiltration'):
                    threat_fields.append({"title": "📤 Data Exfiltration", "value": "Yes", "short": True})
                if threat_context.get('is_lateral_movement'):
                    threat_fields.append({"title": "🔄 Lateral Movement", "value": "Yes", "short": True})
                if threat_context.get('is_persistence_attempt'):
                    threat_fields.append({"title": "🔐 Persistence Attempt", "value": "Yes", "short": True})
                
                if threat_fields:
                    message["attachments"][0]["fields"].extend(threat_fields)
            
            response = self._send_slack_message(message)
            
            return {
                'notification_sent': True,
                'message_type': 'incident_alert',
                'severity_level': severity_level,
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'slack_response': response
            }
            
        except Exception as e:
            logger.error(f"Failed to send incident alert: {str(e)}")
            return {
                'notification_sent': False,
                'error': str(e),
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
    
    def send_isolation_notification(self, isolation_data):
        """
        Send instance isolation notification to Slack
        
        Args:
            isolation_data (dict): Isolation information
            
        Returns:
            dict: Notification result
        """
        try:
            instance_id = isolation_data.get('instance_id', 'Unknown')
            success = isolation_data.get('isolation_successful', False)
            
            color = 'good' if success else 'danger'
            emoji = '✅' if success else '❌'
            title = f"{emoji} Instance {instance_id} Isolated" if success else f"❌ Instance Isolation Failed"
            
            message = {
                "username": "SOAR Bot",
                "icon_emoji": ":shield:",
                "attachments": [
                    {
                        "color": color,
                        "title": title,
                        "fields": [
                            {
                                "title": "Instance ID",
                                "value": instance_id,
                                "short": True
                            },
                            {
                                "title": "Status",
                                "value": "Successfully Isolated" if success else "Isolation Failed",
                                "short": True
                            },
                            {
                                "title": "Isolation Security Group",
                                "value": isolation_data.get('isolation_security_group', 'N/A'),
                                "short": True
                            },
                            {
                                "title": "Timestamp",
                                "value": isolation_data.get('isolation_timestamp', 'N/A'),
                                "short": True
                            }
                        ],
                        "footer": "SOAR Platform",
                        "ts": int(datetime.now(timezone.utc).timestamp())
                    }
                ]
            }
            
            # Add original security groups if available
            original_sgs = isolation_data.get('original_security_groups', [])
            if original_sgs:
                message["attachments"][0]["fields"].append({
                    "title": "Original Security Groups",
                    "value": ", ".join(original_sgs),
                    "short": False
                })
            
            # Add error information if isolation failed
            if not success:
                error = isolation_data.get('error', 'Unknown error')
                message["attachments"][0]["fields"].append({
                    "title": "Error Details",
                    "value": error,
                    "short": False
                })
            
            response = self._send_slack_message(message)
            
            return {
                'notification_sent': True,
                'message_type': 'isolation_notification',
                'instance_id': instance_id,
                'success': success,
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'slack_response': response
            }
            
        except Exception as e:
            logger.error(f"Failed to send isolation notification: {str(e)}")
            return {
                'notification_sent': False,
                'error': str(e),
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
    
    def send_forensics_notification(self, forensics_data):
        """
        Send forensics completion notification to Slack
        
        Args:
            forensics_data (dict): Forensics information
            
        Returns:
            dict: Notification result
        """
        try:
            instance_id = forensics_data.get('instance_id', 'Unknown')
            report_summary = forensics_data.get('report_summary', {})
            total_findings = report_summary.get('total_findings', 0)
            severity_distribution = report_summary.get('severity_distribution', {})
            
            # Determine overall risk level
            critical_count = severity_distribution.get('critical', 0)
            high_count = severity_distribution.get('high', 0)
            
            if critical_count > 0:
                color = 'danger'
                emoji = '🔴'
            elif high_count > 2:
                color = 'warning'
                emoji = '🟡'
            else:
                color = 'good'
                emoji = '🟢'
            
            message = {
                "username": "SOAR Bot",
                "icon_emoji": ":mag:",
                "attachments": [
                    {
                        "color": color,
                        "title": f"{emoji} Forensic Analysis Complete - {instance_id}",
                        "fields": [
                            {
                                "title": "Instance ID",
                                "value": instance_id,
                                "short": True
                            },
                            {
                                "title": "Total Findings",
                                "value": str(total_findings),
                                "short": True
                            },
                            {
                                "title": "Critical Findings",
                                "value": str(severity_distribution.get('critical', 0)),
                                "short": True
                            },
                            {
                                "title": "High Findings",
                                "value": str(severity_distribution.get('high', 0)),
                                "short": True
                            },
                            {
                                "title": "Medium Findings",
                                "value": str(severity_distribution.get('medium', 0)),
                                "short": True
                            },
                            {
                                "title": "Low Findings",
                                "value": str(severity_distribution.get('low', 0)),
                                "short": True
                            }
                        ],
                        "footer": "SOAR Platform",
                        "ts": int(datetime.now(timezone.utc).timestamp())
                    }
                ]
            }
            
            # Add recommendations if available
            recommendations = report_summary.get('recommendations', [])
            if recommendations:
                rec_text = "\n".join([f"• {rec['priority'].upper()}: {rec['description']}" for rec in recommendations[:3]])
                message["attachments"][0]["fields"].append({
                    "title": "Top Recommendations",
                    "value": rec_text,
                    "short": False
                })
            
            response = self._send_slack_message(message)
            
            return {
                'notification_sent': True,
                'message_type': 'forensics_notification',
                'instance_id': instance_id,
                'total_findings': total_findings,
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'slack_response': response
            }
            
        except Exception as e:
            logger.error(f"Failed to send forensics notification: {str(e)}")
            return {
                'notification_sent': False,
                'error': str(e),
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
    
    def send_termination_notification(self, termination_data):
        """
        Send instance termination notification to Slack
        
        Args:
            termination_data (dict): Termination information
            
        Returns:
            dict: Notification result
        """
        try:
            instance_id = termination_data.get('instance_id', 'Unknown')
            success = termination_data.get('termination_successful', False)
            
            color = 'good' if success else 'danger'
            emoji = '✅' if success else '❌'
            title = f"{emoji} Instance {instance_id} Terminated" if success else f"❌ Instance Termination Failed"
            
            message = {
                "username": "SOAR Bot",
                "icon_emoji": ":no_entry:",
                "attachments": [
                    {
                        "color": color,
                        "title": title,
                        "fields": [
                            {
                                "title": "Instance ID",
                                "value": instance_id,
                                "short": True
                            },
                            {
                                "title": "Status",
                                "value": "Successfully Terminated" if success else "Termination Failed",
                                "short": True
                            },
                            {
                                "title": "Final State",
                                "value": termination_data.get('final_state', 'N/A'),
                                "short": True
                            },
                            {
                                "title": "Timestamp",
                                "value": termination_data.get('termination_timestamp', 'N/A'),
                                "short": True
                            }
                        ],
                        "footer": "SOAR Platform",
                        "ts": int(datetime.now(timezone.utc).timestamp())
                    }
                ]
            }
            
            # Add error information if termination failed
            if not success:
                error = termination_data.get('error', 'Unknown error')
                message["attachments"][0]["fields"].append({
                    "title": "Error Details",
                    "value": error,
                    "short": False
                })
            
            response = self._send_slack_message(message)
            
            return {
                'notification_sent': True,
                'message_type': 'termination_notification',
                'instance_id': instance_id,
                'success': success,
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'slack_response': response
            }
            
        except Exception as e:
            logger.error(f"Failed to send termination notification: {str(e)}")
            return {
                'notification_sent': False,
                'error': str(e),
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
    
    def send_approval_request(self, approval_data):
        """
        Send human approval request to Slack
        
        Args:
            approval_data (dict): Approval request information
            
        Returns:
            dict: Notification result
        """
        try:
            instance_id = approval_data.get('instance_id', 'Unknown')
            severity = approval_data.get('severity_level', 'MEDIUM')
            wait_time = approval_data.get('approval_wait_time', 3600)
            
            message = {
                "username": "SOAR Bot",
                "icon_emoji": ":warning:",
                "attachments": [
                    {
                        "color": "warning",
                        "title": f"⚠️ Approval Required - Instance Termination",
                        "fields": [
                            {
                                "title": "Instance ID",
                                "value": instance_id,
                                "short": True
                            },
                            {
                                "title": "Severity",
                                "value": severity,
                                "short": True
                            },
                            {
                                "title": "Wait Time",
                                "value": f"{wait_time // 60} minutes",
                                "short": True
                            },
                            {
                                "title": "Request Time",
                                "value": datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC'),
                                "short": True
                            }
                        ],
                        "actions": [
                            {
                                "type": "button",
                                "text": "Approve Termination",
                                "url": "https://console.aws.amazon.com/stepfunctions/",
                                "style": "danger"
                            },
                            {
                                "type": "button",
                                "text": "Review Details",
                                "url": "https://console.aws.amazon.com/guardduty/",
                                "style": "default"
                            }
                        ],
                        "footer": "SOAR Platform - Manual Approval Required",
                        "ts": int(datetime.now(timezone.utc).timestamp())
                    }
                ]
            }
            
            response = self._send_slack_message(message)
            
            return {
                'notification_sent': True,
                'message_type': 'approval_request',
                'instance_id': instance_id,
                'severity_level': severity,
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'slack_response': response
            }
            
        except Exception as e:
            logger.error(f"Failed to send approval request: {str(e)}")
            return {
                'notification_sent': False,
                'error': str(e),
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
    
    def _send_slack_message(self, message):
        """Send message to Slack webhook"""
        try:
            response = requests.post(
                self.webhook_url,
                json=message,
                headers={'Content-Type': 'application/json'},
                timeout=30
            )
            
            response.raise_for_status()
            
            return {
                'status_code': response.status_code,
                'response_text': response.text
            }
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to send Slack message: {str(e)}")
            raise

def lambda_handler(event, context):
    """
    Lambda handler for Slack notifications
    
    Expected input:
    {
        "message_type": "incident_alert|isolation_notification|forensics_notification|termination_notification|approval_request",
        "data": {
            // Message-specific data
        }
    }
    """
    try:
        logger.info(f"Processing Slack notification: {json.dumps(event)}")
        
        message_type = event.get('message_type')
        data = event.get('data', {})
        
        if not message_type:
            raise ValueError("message_type is required")
        
        notifier = SlackNotifier()
        
        # Route to appropriate notification method
        if message_type == 'incident_alert':
            result = notifier.send_incident_alert(data)
        elif message_type == 'isolation_notification':
            result = notifier.send_isolation_notification(data)
        elif message_type == 'forensics_notification':
            result = notifier.send_forensics_notification(data)
        elif message_type == 'termination_notification':
            result = notifier.send_termination_notification(data)
        elif message_type == 'approval_request':
            result = notifier.send_approval_request(data)
        else:
            raise ValueError(f"Unknown message type: {message_type}")
        
        logger.info(f"Slack notification completed successfully")
        return result
        
    except Exception as e:
        logger.error(f"Error in Slack notifier: {str(e)}")
        raise e
