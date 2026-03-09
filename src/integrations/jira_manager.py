"""
Advanced SOAR - Jira Integration
Creates and manages Jira tickets for incident response
"""

import json
import os
import boto3
import logging
import requests
from datetime import datetime, timezone
from botocore.exceptions import ClientError
from requests.auth import HTTPBasicAuth

# Configure logging
logging.basicConfig(
    level=getattr(logging, os.environ.get('LOG_LEVEL', 'INFO')),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class JiraManager:
    """Advanced Jira integration for incident ticket management"""
    
    def __init__(self):
        self.ssm_client = boto3.client('ssm')
        self.jira_config = self._get_jira_config()
        
    def _get_jira_config(self):
        """Retrieve Jira configuration from AWS Systems Manager Parameter Store"""
        try:
            url_response = self.ssm_client.get_parameter(
                Name='/soar/jira/url',
                WithDecryption=True
            )
            username_response = self.ssm_client.get_parameter(
                Name='/soar/jira/username',
                WithDecryption=True
            )
            token_response = self.ssm_client.get_parameter(
                Name='/soar/jira/api_token',
                WithDecryption=True
            )
            
            return {
                'url': url_response['Parameter']['Value'],
                'username': username_response['Parameter']['Value'],
                'api_token': token_response['Parameter']['Value']
            }
        except ClientError as e:
            logger.error(f"Failed to retrieve Jira configuration: {str(e)}")
            raise
    
    def create_incident_ticket(self, incident_data):
        """
        Create Jira ticket for security incident
        
        Args:
            incident_data (dict): Incident information
            
        Returns:
            dict: Ticket creation result
        """
        try:
            severity = incident_data.get('severity_classification', {})
            severity_level = severity.get('severity_level', 'MEDIUM')
            priority = severity.get('priority', 'P3')
            
            # Map SOAR severity to Jira priority
            jira_priority_map = {
                'CRITICAL': 'Highest',
                'HIGH': 'High',
                'MEDIUM': 'Medium',
                'LOW': 'Low'
            }
            jira_priority = jira_priority_map.get(severity_level, 'Medium')
            
            # Build ticket description
            description = self._build_incident_description(incident_data)
            
            # Create Jira ticket
            ticket_data = {
                "fields": {
                    "project": {
                        "key": os.environ.get('JIRA_PROJECT_KEY', 'SEC')
                    },
                    "summary": f"Security Incident - {severity_level} - {incident_data.get('isolation_result', {}).get('instance_id', 'Unknown Instance')}",
                    "description": description,
                    "issuetype": {
                        "name": "Security Incident"
                    },
                    "priority": {
                        "name": jira_priority
                    },
                    "labels": [
                        "soar",
                        "security-incident",
                        severity_level.lower(),
                        "automated"
                    ],
                    "customfield_10010": severity_level,  # Custom field for severity
                    "customfield_10011": priority,       # Custom field for priority
                    "customfield_10012": incident_data.get('original_finding', {}).get('account', 'Unknown')  # Account field
                }
            }
            
            response = self._make_jira_request('POST', '/rest/api/2/issue', ticket_data)
            
            ticket_key = response.get('key')
            ticket_id = response.get('id')
            
            # Add attachments if available
            self._add_ticket_attachments(ticket_key, incident_data)
            
            # Add watchers if configured
            watchers = os.environ.get('JIRA_WATCHERS', '').split(',')
            for watcher in watchers:
                if watcher.strip():
                    self._add_watcher(ticket_key, watcher.strip())
            
            result = {
                'ticket_created': True,
                'ticket_key': ticket_key,
                'ticket_id': ticket_id,
                'ticket_url': f"{self.jira_config['url']}/browse/{ticket_key}",
                'severity_level': severity_level,
                'priority': priority,
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
            
            logger.info(f"Successfully created Jira ticket {ticket_key} for security incident")
            return result
            
        except Exception as e:
            logger.error(f"Failed to create Jira ticket: {str(e)}")
            return {
                'ticket_created': False,
                'error': str(e),
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
    
    def update_ticket_status(self, ticket_key, status, comment=None):
        """
        Update Jira ticket status
        
        Args:
            ticket_key (str): Jira ticket key
            status (str): New status
            comment (str): Optional comment
            
        Returns:
            dict: Update result
        """
        try:
            # Get transition ID for the status
            transition_id = self._get_transition_id(ticket_key, status)
            
            if not transition_id:
                raise ValueError(f"No transition found for status: {status}")
            
            # Perform transition
            transition_data = {
                "transition": {
                    "id": transition_id
                }
            }
            
            if comment:
                transition_data["update"] = {
                    "comment": [
                        {
                            "add": {
                                "body": comment
                            }
                        }
                    ]
                }
            
            self._make_jira_request('POST', f'/rest/api/2/issue/{ticket_key}/transitions', transition_data)
            
            result = {
                'ticket_updated': True,
                'ticket_key': ticket_key,
                'new_status': status,
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
            
            logger.info(f"Successfully updated Jira ticket {ticket_key} to {status}")
            return result
            
        except Exception as e:
            logger.error(f"Failed to update Jira ticket {ticket_key}: {str(e)}")
            return {
                'ticket_updated': False,
                'ticket_key': ticket_key,
                'error': str(e),
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
    
    def add_comment(self, ticket_key, comment):
        """
        Add comment to Jira ticket
        
        Args:
            ticket_key (str): Jira ticket key
            comment (str): Comment text
            
        Returns:
            dict: Comment result
        """
        try:
            comment_data = {
                "body": comment
            }
            
            response = self._make_jira_request('POST', f'/rest/api/2/issue/{ticket_key}/comment', comment_data)
            
            result = {
                'comment_added': True,
                'ticket_key': ticket_key,
                'comment_id': response.get('id'),
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
            
            logger.info(f"Successfully added comment to Jira ticket {ticket_key}")
            return result
            
        except Exception as e:
            logger.error(f"Failed to add comment to Jira ticket {ticket_key}: {str(e)}")
            return {
                'comment_added': False,
                'ticket_key': ticket_key,
                'error': str(e),
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
    
    def _build_incident_description(self, incident_data):
        """Build detailed incident description for Jira ticket"""
        severity = incident_data.get('severity_classification', {})
        isolation = incident_data.get('isolation_result', {})
        snapshot = incident_data.get('snapshot_result', {})
        threat_context = incident_data.get('threat_context', {})
        
        description = f"""# Security Incident Report

## Incident Overview
* **Severity Level**: {severity.get('severity_level', 'Unknown')}
* **Priority**: {severity.get('priority', 'Unknown')}
* **Severity Score**: {severity.get('severity_score', 0)}
* **Finding Type**: {severity.get('finding_type', 'Unknown')}
* **Detection Time**: {severity.get('classification_timestamp', 'Unknown')}
* **Instance ID**: {isolation.get('instance_id', 'Unknown')}
* **Account**: {incident_data.get('original_finding', {}).get('account', 'Unknown')}

## Threat Context
"""
        
        if threat_context.get('is_malware_related'):
            description += "* 🦠 **Malware Related**: Yes\n"
        if threat_context.get('is_data_exfiltration'):
            description += "* 📤 **Data Exfiltration**: Yes\n"
        if threat_context.get('is_lateral_movement'):
            description += "* 🔄 **Lateral Movement**: Yes\n"
        if threat_context.get('is_persistence_attempt'):
            description += "* 🔐 **Persistence Attempt**: Yes\n"
        
        description += f"""
## Response Actions

### Instance Isolation
* **Status**: {'✅ Successful' if isolation.get('isolation_successful') else '❌ Failed'}
* **Isolation SG**: {isolation.get('isolation_security_group', 'N/A')}
* **Timestamp**: {isolation.get('isolation_timestamp', 'N/A')}
"""
        
        if isolation.get('original_security_groups'):
            description += f"* **Original SGs**: {', '.join(isolation['original_security_groups'])}\n"
        
        description += f"""
### Forensic Analysis
* **Snapshots Created**: {snapshot.get('snapshot_count', 0)}
* **Timestamp**: {snapshot.get('snapshot_timestamp', 'N/A')}
"""
        
        if snapshot.get('snapshots_created'):
            description += "* **Snapshot IDs**:\n"
            for snap in snapshot['snapshots_created']:
                description += f"  * {snap.get('snapshot_id', 'Unknown')} ({snap.get('device_name', 'Unknown')})\n"
        
        description += f"""
## Original Finding Details
{json.dumps(incident_data.get('original_finding', {}), indent=2)}

## Automated Response
This ticket was automatically created by the SOAR (Security Orchestration, Automation and Response) platform.

---
*Generated by SOAR Platform at {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}*
"""
        
        return description
    
    def _add_ticket_attachments(self, ticket_key, incident_data):
        """Add relevant attachments to the ticket"""
        try:
            # In a real implementation, you might attach:
            # - Forensic reports
            # - Screenshots
            # - Log files
            # - Network captures
            
            # For now, we'll just log that this would happen
            logger.info(f"Would add attachments to Jira ticket {ticket_key}")
            
        except Exception as e:
            logger.warning(f"Failed to add attachments to Jira ticket {ticket_key}: {str(e)}")
    
    def _add_watcher(self, ticket_key, watcher_email):
        """Add watcher to the ticket"""
        try:
            watcher_data = {
                "self": watcher_email
            }
            
            self._make_jira_request('POST', f'/rest/api/2/issue/{ticket_key}/watchers', watcher_data)
            logger.info(f"Added watcher {watcher_email} to ticket {ticket_key}")
            
        except Exception as e:
            logger.warning(f"Failed to add watcher {watcher_email} to ticket {ticket_key}: {str(e)}")
    
    def _get_transition_id(self, ticket_key, target_status):
        """Get transition ID for a given status"""
        try:
            response = self._make_jira_request('GET', f'/rest/api/2/issue/{ticket_key}/transitions')
            
            transitions = response.get('transitions', [])
            
            for transition in transitions:
                if transition['to']['name'].lower() == target_status.lower():
                    return transition['id']
            
            return None
            
        except Exception as e:
            logger.error(f"Failed to get transitions for ticket {ticket_key}: {str(e)}")
            return None
    
    def _make_jira_request(self, method, endpoint, data=None):
        """Make authenticated request to Jira API"""
        try:
            url = f"{self.jira_config['url']}{endpoint}"
            auth = HTTPBasicAuth(self.jira_config['username'], self.jira_config['api_token'])
            headers = {
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            }
            
            response = requests.request(
                method=method,
                url=url,
                json=data,
                auth=auth,
                headers=headers,
                timeout=30
            )
            
            response.raise_for_status()
            
            if response.text:
                return response.json()
            else:
                return {}
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Jira API request failed: {str(e)}")
            raise

def lambda_handler(event, context):
    """
    Lambda handler for Jira operations
    
    Expected input:
    {
        "operation": "create_ticket|update_status|add_comment",
        "ticket_key": "JIRA-123",  // For update operations
        "data": {
            // Operation-specific data
        }
    }
    """
    try:
        logger.info(f"Processing Jira operation: {json.dumps(event)}")
        
        operation = event.get('operation')
        ticket_key = event.get('ticket_key')
        data = event.get('data', {})
        
        if not operation:
            raise ValueError("operation is required")
        
        manager = JiraManager()
        
        # Route to appropriate operation
        if operation == 'create_ticket':
            result = manager.create_incident_ticket(data)
        elif operation == 'update_status':
            if not ticket_key:
                raise ValueError("ticket_key is required for update_status operation")
            status = data.get('status')
            comment = data.get('comment')
            result = manager.update_ticket_status(ticket_key, status, comment)
        elif operation == 'add_comment':
            if not ticket_key:
                raise ValueError("ticket_key is required for add_comment operation")
            comment = data.get('comment')
            result = manager.add_comment(ticket_key, comment)
        else:
            raise ValueError(f"Unknown operation: {operation}")
        
        logger.info(f"Jira operation completed successfully")
        return result
        
    except Exception as e:
        logger.error(f"Error in Jira manager: {str(e)}")
        raise e
