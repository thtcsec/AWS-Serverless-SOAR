import botocore
"""
Enterprise SOAR - Instance Termination Lambda
Terminates compromised instances after human approval
"""

import json
import os
import boto3
from datetime import datetime, timezone
import time

def lambda_handler(event, context):
    """
    Terminate compromised instance after human approval
    
    Expected input: Event from human approval wait step
    Output: Event with termination status
    """
    try:
        print(f"Starting instance termination for event: {json.dumps(event)}")
        
        # Extract instance information
        instance_id = event.get('isolation_result', {}).get('instance_id')
        if not instance_id:
            error_msg = "No instance ID found in isolation result"
            print(error_msg)
            raise ValueError(error_msg)
        
        # Initialize EC2 client
        ec2 = boto3.client('ec2')
        
        # Check if instance still exists
        try:
            response = ec2.describe_instances(InstanceIds=[instance_id])
            instance = response['Reservations'][0]['Instances'][0]
            instance_state = instance['State']['Name']
            
            if instance_state == 'terminated':
                print(f"Instance {instance_id} is already terminated")
                event['termination_result'] = {
                    'instance_id': instance_id,
                    'termination_successful': True,
                    'termination_timestamp': datetime.now(timezone.utc).isoformat(),
                    'message': 'Instance was already terminated',
                    'previous_state': instance_state
                }
                return event
                
        except botocore.exceptions.ClientError as e:
            if 'InvalidInstanceID.NotFound' in str(e):
                print(f"Instance {instance_id} no longer exists")
                event['termination_result'] = {
                    'instance_id': instance_id,
                    'termination_successful': True,
                    'termination_timestamp': datetime.now(timezone.utc).isoformat(),
                    'message': 'Instance no longer exists',
                    'error_code': 'InstanceNotFound'
                }
                return event
            else:
                raise
        
        # Terminate the instance
        print(f"Terminating instance {instance_id}")
        
        ec2.terminate_instances(InstanceIds=[instance_id])
        
        # Wait for termination to initiate
        time.sleep(5)
        
        # Verify termination
        termination_success = verify_instance_termination(ec2, instance_id)
        
        # Get final instance state
        try:
            response = ec2.describe_instances(InstanceIds=[instance_id])
            instance = response['Reservations'][0]['Instances'][0]
            final_state = instance['State']['Name']
        except:
            final_state = 'unknown'
        
        # Build termination result
        termination_result = {
            'instance_id': instance_id,
            'termination_successful': termination_success,
            'final_state': final_state,
            'termination_timestamp': datetime.now(timezone.utc).isoformat(),
            'lambda_request_id': context.aws_request_id
        }
        
        # Update event with termination result
        event['termination_result'] = termination_result
        event['workflow_metadata']['step'] = 'instance_terminated'
        event['workflow_metadata']['timestamp'] = datetime.now(timezone.utc).isoformat()
        
        if termination_success:
            print(f"Successfully terminated instance {instance_id}")
        else:
            print(f"Failed to verify termination for instance {instance_id}")
            raise RuntimeError("Termination verification failed")
        
        return event
        
    except Exception as e:
        print(f"Error in instance termination: {str(e)}")
        raise e

def verify_instance_termination(ec2_client, instance_id, max_attempts=6):
    """Verify that instance is terminated"""
    for attempt in range(max_attempts):
        try:
            response = ec2_client.describe_instances(InstanceIds=[instance_id])
            instance = response['Reservations'][0]['Instances'][0]
            state = instance['State']['Name']
            
            if state == 'terminated':
                return True
            elif state in ['shutting-down', 'stopping']:
                print(f"Instance {instance_id} is {state}, waiting...")
                time.sleep(10)
            else:
                print(f"Unexpected instance state: {state}")
                return False
                
        except botocore.exceptions.ClientError as e:
            if 'InvalidInstanceID.NotFound' in str(e):
                print(f"Instance {instance_id} no longer exists")
                return True
            else:
                raise
        except Exception as e:
            print(f"Error during termination verification: {str(e)}")
            if attempt == max_attempts - 1:
                raise
            time.sleep(10)
    
    return False

def create_incident_report(event):
    """Create a comprehensive incident report"""
    try:
        severity = event.get('severity_classification', {})
        isolation = event.get('isolation_result', {})
        snapshot = event.get('snapshot_result', {})
        termination = event.get('termination_result', {})
        
        report = {
            'incident_summary': {
                'instance_id': isolation.get('instance_id'),
                'severity_level': severity.get('severity_level'),
                'priority': severity.get('priority'),
                'severity_score': severity.get('severity_score'),
                'finding_type': severity.get('finding_type'),
                'incident_timestamp': severity.get('classification_timestamp')
            },
            'response_actions': {
                'isolation': {
                    'successful': isolation.get('isolation_successful'),
                    'timestamp': isolation.get('isolation_timestamp'),
                    'original_security_groups': isolation.get('original_security_groups')
                },
                'forensics': {
                    'snapshots_created': snapshot.get('snapshot_count', 0),
                    'snapshot_ids': [s.get('snapshot_id') for s in snapshot.get('snapshots_created', [])],
                    'timestamp': snapshot.get('snapshot_timestamp')
                },
                'termination': {
                    'successful': termination.get('termination_successful'),
                    'timestamp': termination.get('termination_timestamp'),
                    'final_state': termination.get('final_state')
                }
            },
            'threat_context': event.get('threat_context', {}),
            'workflow_metadata': event.get('workflow_metadata', {}),
            'report_generated': datetime.now(timezone.utc).isoformat()
        }
        
        return report
        
    except Exception as e:
        print(f"Error creating incident report: {str(e)}")
        return {'error': str(e)}
