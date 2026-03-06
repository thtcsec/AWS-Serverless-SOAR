"""
Enterprise SOAR - Forensic Snapshot Lambda
Creates EBS snapshots for forensic analysis
"""

import json
import os
import boto3
from datetime import datetime, timezone
import time

def lambda_handler(event, context):
    """
    Create forensic snapshots of instance volumes
    
    Expected input: Event from instance isolation step
    Output: Event with snapshot information
    """
    try:
        print(f"Starting forensic snapshot for event: {json.dumps(event)}")
        
        # Extract instance information
        instance_id = event.get('isolation_result', {}).get('instance_id')
        if not instance_id:
            error_msg = "No instance ID found in isolation result"
            print(error_msg)
            raise ValueError(error_msg)
        
        # Initialize EC2 client
        ec2 = boto3.client('ec2')
        
        # Get instance details and volumes
        instance_details = get_instance_details(ec2, instance_id)
        volumes = instance_details.get('BlockDeviceMappings', [])
        
        if not volumes:
            print(f"No volumes found for instance {instance_id}")
            event['snapshot_result'] = {
                'instance_id': instance_id,
                'snapshots_created': [],
                'snapshot_count': 0,
                'snapshot_timestamp': datetime.now(timezone.utc).isoformat(),
                'message': 'No volumes found to snapshot'
            }
            return event
        
        # Create snapshots for all volumes
        snapshots = []
        for volume_mapping in volumes:
            volume_id = volume_mapping.get('Ebs', {}).get('VolumeId')
            device_name = volume_mapping.get('DeviceName')
            
            if volume_id:
                snapshot = create_volume_snapshot(ec2, volume_id, device_name, instance_id)
                snapshots.append(snapshot)
        
        # Wait for snapshots to complete (or at least start)
        print(f"Waiting for {len(snapshots)} snapshots to initiate...")
        time.sleep(10)
        
        # Build snapshot result
        snapshot_result = {
            'instance_id': instance_id,
            'instance_details': {
                'instance_type': instance_details.get('InstanceType'),
                'ami_id': instance_details.get('ImageId'),
                'launch_time': instance_details.get('LaunchTime').isoformat() if instance_details.get('LaunchTime') else None
            },
            'snapshots_created': snapshots,
            'snapshot_count': len(snapshots),
            'snapshot_timestamp': datetime.now(timezone.utc).isoformat(),
            'lambda_request_id': context.aws_request_id
        }
        
        # Update event with snapshot result
        event['snapshot_result'] = snapshot_result
        event['workflow_metadata']['step'] = 'snapshot_created'
        event['workflow_metadata']['timestamp'] = datetime.now(timezone.utc).isoformat()
        
        print(f"Successfully initiated {len(snapshots)} forensic snapshots for instance {instance_id}")
        
        return event
        
    except Exception as e:
        print(f"Error in forensic snapshot creation: {str(e)}")
        raise e

def get_instance_details(ec2_client, instance_id):
    """Get detailed information about the instance"""
    try:
        response = ec2_client.describe_instances(InstanceIds=[instance_id])
        return response['Reservations'][0]['Instances'][0]
    except Exception as e:
        print(f"Error getting instance details: {str(e)}")
        raise

def create_volume_snapshot(ec2_client, volume_id, device_name, instance_id):
    """Create snapshot of a specific volume"""
    try:
        # Create snapshot with descriptive name and tags
        timestamp = datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')
        snapshot_name = f"forensic-{instance_id}-{device_name.replace('/', '-')}-{timestamp}"
        
        print(f"Creating snapshot for volume {volume_id} ({device_name})")
        
        response = ec2_client.create_snapshot(
            VolumeId=volume_id,
            Description=f"Forensic snapshot for incident response - Instance {instance_id}, Device {device_name}",
            TagSpecifications=[
                {
                    'ResourceType': 'snapshot',
                    'Tags': [
                        {
                            'Key': 'Name',
                            'Value': snapshot_name
                        },
                        {
                            'Key': 'Purpose',
                            'Value': 'forensic-analysis'
                        },
                        {
                            'Key': 'IncidentInstance',
                            'Value': instance_id
                        },
                        {
                            'Key': 'DeviceName',
                            'Value': device_name
                        },
                        {
                            'Key': 'CreatedDate',
                            'Value': datetime.now(timezone.utc).isoformat()
                        },
                        {
                            'Key': 'CreatedBy',
                            'Value': 'SOAR-Workflow'
                        }
                    ]
                }
            ]
        )
        
        snapshot_id = response['SnapshotId']
        print(f"Created snapshot {snapshot_id} for volume {volume_id}")
        
        return {
            'snapshot_id': snapshot_id,
            'volume_id': volume_id,
            'device_name': device_name,
            'snapshot_name': snapshot_name,
            'status': response['State'],
            'creation_time': datetime.now(timezone.utc).isoformat()
        }
        
    except Exception as e:
        print(f"Error creating snapshot for volume {volume_id}: {str(e)}")
        raise

def wait_for_snapshot_completion(ec2_client, snapshot_id, timeout_minutes=30):
    """Wait for snapshot to complete (optional, for critical cases)"""
    timeout_seconds = timeout_minutes * 60
    start_time = time.time()
    
    while time.time() - start_time < timeout_seconds:
        try:
            response = ec2_client.describe_snapshots(SnapshotIds=[snapshot_id])
            snapshot = response['Snapshots'][0]
            status = snapshot['State']
            
            if status == 'completed':
                print(f"Snapshot {snapshot_id} completed successfully")
                return True
            elif status == 'error':
                print(f"Snapshot {snapshot_id} failed")
                return False
            
            print(f"Snapshot {snapshot_id} status: {status}")
            time.sleep(30)
            
        except Exception as e:
            print(f"Error checking snapshot status: {str(e)}")
            time.sleep(30)
    
    print(f"Snapshot {snapshot_id} did not complete within {timeout_minutes} minutes")
    return False
