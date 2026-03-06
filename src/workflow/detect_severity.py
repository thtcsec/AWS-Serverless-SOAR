"""
Enterprise SOAR - Severity Detection Lambda
Analyzes GuardDuty findings to determine incident severity
"""

import json
import os
import boto3
from datetime import datetime

def lambda_handler(event, context):
    """
    Analyze GuardDuty finding and determine severity level
    
    Expected input: GuardDuty finding from Step Functions
    Output: Enhanced finding with severity classification
    """
    try:
        print(f"Processing severity detection for event: {json.dumps(event)}")
        
        # Extract finding details
        finding = event.get('detail', {})
        severity_score = finding.get('severity', 0)
        finding_type = finding.get('type', '')
        resource_type = finding.get('resource', {}).get('resourceType', '')
        
        # Determine severity level
        if severity_score >= 8.0:
            severity_level = "CRITICAL"
            priority = "P1"
        elif severity_score >= 6.0:
            severity_level = "HIGH"
            priority = "P2"
        elif severity_score >= 4.0:
            severity_level = "MEDIUM"
            priority = "P3"
        else:
            severity_level = "LOW"
            priority = "P4"
        
        # Enhanced classification
        classification = {
            'severity_level': severity_level,
            'priority': priority,
            'severity_score': severity_score,
            'requires_immediate_action': severity_score >= 7.0,
            'requires_human_approval': severity_score >= 6.0,
            'finding_type': finding_type,
            'resource_type': resource_type,
            'classification_timestamp': datetime.now(timezone.utc).isoformat()
        }
        
        # Add threat intelligence context
        threat_context = analyze_threat_context(finding)
        
        # Build enhanced event for next step
        enhanced_event = {
            'original_finding': finding,
            'severity_classification': classification,
            'threat_context': threat_context,
            'workflow_metadata': {
                'step': 'severity_detected',
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'lambda_request_id': context.aws_request_id
            }
        }
        
        print(f"Severity classification complete: {severity_level} ({priority})")
        
        return enhanced_event
        
    except Exception as e:
        print(f"Error in severity detection: {str(e)}")
        raise e

def analyze_threat_context(finding):
    """Analyze threat context based on finding details"""
    context = {
        'is_malware_related': False,
        'is_data_exfiltration': False,
        'is_lateral_movement': False,
        'is_persistence_attempt': False
    }
    
    finding_type = finding.get('type', '').lower()
    description = finding.get('description', '').lower()
    
    # Malware indicators
    if any(keyword in finding_type for keyword in ['malware', 'backdoor', 'trojan']):
        context['is_malware_related'] = True
    
    # Data exfiltration indicators
    if any(keyword in description for keyword in ['exfiltration', 'data transfer', 'unusual api calls']):
        context['is_data_exfiltration'] = True
    
    # Lateral movement indicators
    if any(keyword in finding_type for keyword in ['lateral', 'port scanning', 'unusual network']):
        context['is_lateral_movement'] = True
    
    # Persistence indicators
    if any(keyword in finding_type for keyword in ['persistence', 'privilege escalation', 'iam']):
        context['is_persistence_attempt'] = True
    
    return context
