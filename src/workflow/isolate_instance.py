"""
Enterprise SOAR - Instance Isolation Lambda
Isolates compromised EC2 instances using security groups
"""

import json
import os
import boto3
from datetime import datetime
import time

def lambda_handler(event, context):
    """
    Isolate EC2 instance by applying isolation security group
    
    Expected input: Enhanced event from severity detection step
    Output: Event with isolation status
    """
    try:
        print(f"Starting instance isolation for event: {json.dumps(event)}")
        
        # Extract instance information
        finding = event.get('original_finding', {})
        resource = finding.get('resource', {})
        instance_id = resource.get('instanceDetails', {}).get('instanceId')
        
        if not instance_id:
            error_msg = "No instance ID found in finding"
            print(error_msg)
            raise ValueError(error_msg)
        
        # Initialize EC2 client
        ec2 = boto3.client('ec2')
        
        # Get isolation security group ID from environment
        isolation_sg_id = os.environ.get('ISOLATION_SG_ID')
        if not isolation_sg_id:
            error_msg = "ISOLATION_SG_ID environment variable not set"
            print(error_msg)
            raise ValueError(error_msg)
        
        # Get current security groups
        response = ec2.describe_instances(InstanceIds=[instance_id])
        instance = response['Reservations'][0]['Instances'][0]
        current_sgs = [sg['GroupId'] for sg in instance['SecurityGroups']]
        
        print(f"Current security groups for instance {instance_id}: {current_sgs}")
        
        # Store original security groups for potential restoration
        original_sgs = current_sgs.copy()
        
        # Apply isolation security group (replaces all current SGs)
        print(f"Applying isolation security group {isolation_sg_id} to instance {instance_id}")
        
        ec2.modify_instance_attribute(
            InstanceId=instance_id,
            Groups=[isolation_sg_id]
        )
        
        # Wait for isolation to take effect
        time.sleep(5)
        
        # Verify isolation
        response = ec2.describe_instances(InstanceIds=[instance_id])
        instance = response['Reservations'][0]['Instances'][0]
        updated_sgs = [sg['GroupId'] for sg in instance['SecurityGroups']]
        
        isolation_success = isolation_sg_id in updated_sgs and len(updated_sgs) == 1
        
        # Build isolation result
        isolation_result = {
            'instance_id': instance_id,
            'isolation_successful': isolation_success,
            'original_security_groups': original_sgs,
            'isolation_security_group': isolation_sg_id,
            'current_security_groups': updated_sgs,
            'isolation_timestamp': datetime.now(timezone.utc).isoformat(),
            'lambda_request_id': context.aws_request_id
        }
        
        # Update event with isolation result
        event['isolation_result'] = isolation_result
        event['workflow_metadata']['step'] = 'instance_isolated'
        event['workflow_metadata']['timestamp'] = datetime.now(timezone.utc).isoformat()
        
        if isolation_success:
            print(f"Successfully isolated instance {instance_id}")
        else:
            print(f"Failed to verify isolation for instance {instance_id}")
            raise RuntimeError("Isolation verification failed")
        
        return event
        
    except Exception as e:
        print(f"Error in instance isolation: {str(e)}")
        raise e

def verify_instance_isolation(ec2_client, instance_id, isolation_sg_id, max_attempts=3):
    """Verify that instance is properly isolated"""
    for attempt in range(max_attempts):
        try:
            response = ec2_client.describe_instances(InstanceIds=[instance_id])
            instance = response['Reservations'][0]['Instances'][0]
            current_sgs = [sg['GroupId'] for sg in instance['SecurityGroups']]
            
            # Instance is isolated if it only has the isolation SG
            if len(current_sgs) == 1 and current_sgs[0] == isolation_sg_id:
                return True
                
            print(f"Isolation verification attempt {attempt + 1} failed, retrying...")
            time.sleep(2)
            
        except Exception as e:
            print(f"Error during isolation verification: {str(e)}")
            if attempt == max_attempts - 1:
                raise
    
    return False
