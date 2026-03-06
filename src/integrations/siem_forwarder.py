"""
Enterprise SOAR - SIEM Integration
Forwards incident data to SIEM systems (Splunk, Chronicle, Elastic)
"""

import json
import os
import boto3
import logging
import requests
from datetime import datetime
from botocore.exceptions import ClientError

# Configure logging
logging.basicConfig(
    level=getattr(logging, os.environ.get('LOG_LEVEL', 'INFO')),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class SIEMForwarder:
    """Enterprise SIEM integration for incident data forwarding"""
    
    def __init__(self):
        self.ssm_client = boto3.client('ssm')
        self.siem_config = self._get_siem_config()
        self.siem_type = os.environ.get('SIEM_TYPE', 'splunk').lower()
        
    def _get_siem_config(self):
        """Retrieve SIEM configuration from AWS Systems Manager Parameter Store"""
        try:
            endpoint_response = self.ssm_client.get_parameter(
                Name='/soar/siem/endpoint',
                WithDecryption=True
            )
            api_key_response = self.ssm_client.get_parameter(
                Name='/soar/siem/api_key',
                WithDecryption=True
            )
            
            return {
                'endpoint': endpoint_response['Parameter']['Value'],
                'api_key': api_key_response['Parameter']['Value']
            }
        except ClientError as e:
            logger.error(f"Failed to retrieve SIEM configuration: {str(e)}")
            raise
    
    def forward_incident_data(self, incident_data):
        """
        Forward incident data to SIEM system
        
        Args:
            incident_data (dict): Complete incident information
            
        Returns:
            dict: Forwarding result
        """
        try:
            # Transform incident data for SIEM format
            siem_event = self._transform_incident_for_siem(incident_data)
            
            # Send to SIEM based on type
            if self.siem_type == 'splunk':
                result = self._send_to_splunk(siem_event)
            elif self.siem_type == 'chronicle':
                result = self._send_to_chronicle(siem_event)
            elif self.siem_type == 'elastic':
                result = self._send_to_elastic(siem_event)
            else:
                raise ValueError(f"Unsupported SIEM type: {self.siem_type}")
            
            return {
                'forwarded': True,
                'siem_type': self.siem_type,
                'incident_id': incident_data.get('workflow_metadata', {}).get('step', 'unknown'),
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'siem_response': result
            }
            
        except Exception as e:
            logger.error(f"Failed to forward incident data to SIEM: {str(e)}")
            return {
                'forwarded': False,
                'error': str(e),
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
    
    def _transform_incident_for_siem(self, incident_data):
        """Transform incident data into SIEM-compatible format"""
        severity = incident_data.get('severity_classification', {})
        isolation = incident_data.get('isolation_result', {})
        snapshot = incident_data.get('snapshot_result', {})
        threat_context = incident_data.get('threat_context', {})
        
        # Base event structure
        siem_event = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'event_type': 'security_incident',
            'source': 'soar_platform',
            'severity': severity.get('severity_level', 'MEDIUM').lower(),
            'priority': severity.get('priority', 'P3'),
            'severity_score': severity.get('severity_score', 0),
            'finding_type': severity.get('finding_type', 'unknown'),
            'account_id': incident_data.get('original_finding', {}).get('account', 'unknown'),
            'region': incident_data.get('original_finding', {}).get('region', 'unknown'),
            'instance_id': isolation.get('instance_id', 'unknown'),
            'detection_time': severity.get('classification_timestamp', datetime.now(timezone.utc).isoformat()),
            'workflow_metadata': incident_data.get('workflow_metadata', {}),
            'threat_indicators': {
                'malware_detected': threat_context.get('is_malware_related', False),
                'data_exfiltration': threat_context.get('is_data_exfiltration', False),
                'lateral_movement': threat_context.get('is_lateral_movement', False),
                'persistence_attempt': threat_context.get('is_persistence_attempt', False)
            },
            'response_actions': {
                'isolation_performed': isolation.get('isolation_successful', False),
                'snapshots_created': snapshot.get('snapshot_count', 0),
                'forensics_completed': bool(snapshot.get('snapshot_count', 0) > 0)
            }
        }
        
        # Add original GuardDuty finding details
        original_finding = incident_data.get('original_finding', {})
        if original_finding:
            siem_event['guardduty_finding'] = {
                'finding_id': original_finding.get('id'),
                'title': original_finding.get('title'),
                'description': original_finding.get('description'),
                'resource_type': original_finding.get('resource', {}).get('resourceType'),
                'service': original_finding.get('service', {}).get('serviceName')
            }
        
        # Add detailed response information
        if isolation.get('isolation_successful'):
            siem_event['isolation_details'] = {
                'isolation_sg': isolation.get('isolation_security_group'),
                'original_sgs': isolation.get('original_security_groups', []),
                'isolation_timestamp': isolation.get('isolation_timestamp')
            }
        
        if snapshot.get('snapshot_count', 0) > 0:
            siem_event['forensics_details'] = {
                'snapshot_count': snapshot.get('snapshot_count'),
                'snapshot_ids': [s.get('snapshot_id') for s in snapshot.get('snapshots_created', [])],
                'forensics_timestamp': snapshot.get('snapshot_timestamp')
            }
        
        return siem_event
    
    def _send_to_splunk(self, event):
        """Send event to Splunk HTTP Event Collector"""
        try:
            # Splunk HEC endpoint format
            url = f"{self.siem_config['endpoint']}/services/collector/event"
            
            headers = {
                'Authorization': f"Splunk {self.siem_config['api_key']}",
                'Content-Type': 'application/json'
            }
            
            # Splunk event format
            splunk_event = {
                'time': int(datetime.now(timezone.utc).timestamp()),
                'index': os.environ.get('SPLUNK_INDEX', 'security'),
                'source': 'soar_platform',
                'sourcetype': 'json:soar_incident',
                'event': event
            }
            
            response = requests.post(
                url,
                json=splunk_event,
                headers=headers,
                timeout=30
            )
            
            response.raise_for_status()
            
            return {
                'status_code': response.status_code,
                'response_text': response.text
            }
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to send event to Splunk: {str(e)}")
            raise
    
    def _send_to_chronicle(self, event):
        """Send event to Google Chronicle"""
        try:
            # Chronicle API endpoint format
            url = f"{self.siem_config['endpoint']}/v1/ingest"
            
            headers = {
                'Authorization': f"Bearer {self.siem_config['api_key']}",
                'Content-Type': 'application/json'
            }
            
            # Chronicle UDM format (simplified)
            chronicle_event = {
                'events': [{
                    'udm': {
                        'metadata': {
                            'event_type': 'SECURITY_INCIDENT',
                            'product_name': 'SOAR Platform',
                            'vendor_name': 'Enterprise'
                        },
                        'principal': {
                            'hostname': event.get('instance_id', 'unknown'),
                            'ip': event.get('instance_ip', 'unknown')
                        },
                        'security_result': {
                            'severity': event.get('severity', 'medium'),
                            'category': 'security_incident',
                            'description': f"SOAR incident: {event.get('finding_type', 'unknown')}"
                        }
                    }
                }]
            }
            
            response = requests.post(
                url,
                json=chronicle_event,
                headers=headers,
                timeout=30
            )
            
            response.raise_for_status()
            
            return {
                'status_code': response.status_code,
                'response_text': response.text
            }
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to send event to Chronicle: {str(e)}")
            raise
    
    def _send_to_elastic(self, event):
        """Send event to Elastic SIEM"""
        try:
            # Elasticsearch endpoint format
            index_name = f"soar-incidents-{datetime.now(timezone.utc).strftime('%Y.%m')}"
            url = f"{self.siem_config['endpoint']}/{index_name}/_doc"
            
            headers = {
                'Authorization': f"ApiKey {self.siem_config['api_key']}",
                'Content-Type': 'application/json'
            }
            
            # Elastic Common Schema (ECS) format
            ecs_event = {
                '@timestamp': datetime.now(timezone.utc).isoformat(),
                'event': {
                    'kind': 'alert',
                    'category': 'intrusion_detection',
                    'type': 'security_incident',
                    'severity': event.get('severity', 3),  # ECS severity 1-7
                    'action': 'security-incident-response'
                },
                'agent': {
                    'name': 'soar-platform',
                    'type': 'soar',
                    'version': '1.0'
                },
                'cloud': {
                    'account': {
                        'id': event.get('account_id')
                    },
                    'region': event.get('region')
                },
                'host': {
                    'hostname': event.get('instance_id'),
                    'id': event.get('instance_id')
                },
                'soar': {
                    'incident': {
                        'severity_level': event.get('severity'),
                        'priority': event.get('priority'),
                        'finding_type': event.get('finding_type'),
                        'threat_indicators': event.get('threat_indicators', {}),
                        'response_actions': event.get('response_actions', {})
                    }
                },
                'tags': [
                    'soar',
                    'security-incident',
                    'automated-response',
                    event.get('severity', 'medium')
                ]
            }
            
            # Add GuardDuty specific fields if available
            if event.get('guardduty_finding'):
                ecs_event['aws'] = {
                    'guardduty': {
                        'finding': event['guardduty_finding']
                    }
                }
            
            response = requests.post(
                url,
                json=ecs_event,
                headers=headers,
                timeout=30
            )
            
            response.raise_for_status()
            
            return {
                'status_code': response.status_code,
                'response_text': response.text,
                'document_id': response.json().get('_id')
            }
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to send event to Elastic: {str(e)}")
            raise
    
    def forward_batch_events(self, events):
        """
        Forward multiple events to SIEM system
        
        Args:
            events (list): List of incident events
            
        Returns:
            dict: Batch forwarding result
        """
        try:
            successful_forwards = 0
            failed_forwards = 0
            errors = []
            
            for event in events:
                try:
                    result = self.forward_incident_data(event)
                    if result.get('forwarded'):
                        successful_forwards += 1
                    else:
                        failed_forwards += 1
                        errors.append(result.get('error', 'Unknown error'))
                except Exception as e:
                    failed_forwards += 1
                    errors.append(str(e))
            
            return {
                'batch_completed': True,
                'total_events': len(events),
                'successful_forwards': successful_forwards,
                'failed_forwards': failed_forwards,
                'errors': errors,
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
            
        except Exception as e:
            logger.error(f"Failed to forward batch events: {str(e)}")
            return {
                'batch_completed': False,
                'error': str(e),
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
    
    def test_siem_connection(self):
        """Test connectivity to SIEM system"""
        try:
            # Send a test event
            test_event = {
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'event_type': 'test_connection',
                'source': 'soar_platform',
                'severity': 'info',
                'message': 'SOAR platform connectivity test'
            }
            
            if self.siem_type == 'splunk':
                result = self._send_to_splunk(test_event)
            elif self.siem_type == 'chronicle':
                result = self._send_to_chronicle(test_event)
            elif self.siem_type == 'elastic':
                result = self._send_to_elastic(test_event)
            else:
                raise ValueError(f"Unsupported SIEM type: {self.siem_type}")
            
            return {
                'connection_test': 'success',
                'siem_type': self.siem_type,
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'response': result
            }
            
        except Exception as e:
            return {
                'connection_test': 'failed',
                'siem_type': self.siem_type,
                'error': str(e),
                'timestamp': datetime.now(timezone.utc).isoformat()
            }

def lambda_handler(event, context):
    """
    Lambda handler for SIEM operations
    
    Expected input:
    {
        "operation": "forward_incident|forward_batch|test_connection",
        "data": {
            // Operation-specific data
        }
    }
    """
    try:
        logger.info(f"Processing SIEM operation: {json.dumps(event)}")
        
        operation = event.get('operation')
        data = event.get('data', {})
        
        if not operation:
            raise ValueError("operation is required")
        
        forwarder = SIEMForwarder()
        
        # Route to appropriate operation
        if operation == 'forward_incident':
            result = forwarder.forward_incident_data(data)
        elif operation == 'forward_batch':
            events = data.get('events', [])
            if not events:
                raise ValueError("events list is required for forward_batch operation")
            result = forwarder.forward_batch_events(events)
        elif operation == 'test_connection':
            result = forwarder.test_siem_connection()
        else:
            raise ValueError(f"Unknown operation: {operation}")
        
        logger.info(f"SIEM operation completed successfully")
        return result
        
    except Exception as e:
        logger.error(f"Error in SIEM forwarder: {str(e)}")
        raise e
