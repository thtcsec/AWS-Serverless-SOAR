"""
Enterprise SOAR - Isolation Worker Container
Long-running container for instance isolation operations
"""

import os
import json
import boto3
import logging
from datetime import datetime
from flask import Flask, request, jsonify
import threading
import time
from botocore.exceptions import ClientError

# Configure logging
logging.basicConfig(
    level=getattr(logging, os.environ.get('LOG_LEVEL', 'INFO')),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)

# AWS clients
ec2_client = boto3.client('ec2')
sns_client = boto3.client('sns')

# Configuration
ISOLATION_SG_ID = os.environ.get('ISOLATION_SG_ID')
SNS_TOPIC_ARN = os.environ.get('SNS_TOPIC_ARN')
ENVIRONMENT = os.environ.get('ENVIRONMENT', 'production')

class IsolationWorker:
    """Enterprise-grade isolation worker with retry logic and monitoring"""
    
    def __init__(self):
        self.active_operations = {}
        self.operation_counter = 0
        
    def isolate_instance(self, instance_id, operation_id=None):
        """
        Isolate EC2 instance with comprehensive error handling and monitoring
        
        Args:
            instance_id (str): EC2 instance ID to isolate
            operation_id (str): Unique operation identifier
            
        Returns:
            dict: Operation result with detailed status
        """
        if not operation_id:
            self.operation_counter += 1
            operation_id = f"isolation-{int(time.time())}-{self.operation_counter}"
        
        try:
            logger.info(f"Starting isolation operation {operation_id} for instance {instance_id}")
            
            # Track operation
            self.active_operations[operation_id] = {
                'instance_id': instance_id,
                'status': 'in_progress',
                'start_time': datetime.now(timezone.utc).isoformat(),
                'steps': []
            }
            
            # Step 1: Validate instance exists
            self._validate_instance(instance_id, operation_id)
            
            # Step 2: Get current security groups
            original_sgs = self._get_current_security_groups(instance_id, operation_id)
            
            # Step 3: Apply isolation security group
            self._apply_isolation_security_group(instance_id, operation_id)
            
            # Step 4: Verify isolation
            self._verify_isolation(instance_id, operation_id)
            
            # Step 5: Send notification
            self._send_isolation_notification(instance_id, original_sgs, operation_id)
            
            # Mark operation complete
            self.active_operations[operation_id]['status'] = 'completed'
            self.active_operations[operation_id]['end_time'] = datetime.now(timezone.utc).isoformat()
            
            result = {
                'operation_id': operation_id,
                'instance_id': instance_id,
                'status': 'success',
                'original_security_groups': original_sgs,
                'isolation_security_group': ISOLATION_SG_ID,
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'steps': self.active_operations[operation_id]['steps']
            }
            
            logger.info(f"Successfully completed isolation operation {operation_id}")
            return result
            
        except Exception as e:
            logger.error(f"Isolation operation {operation_id} failed: {str(e)}")
            
            # Mark operation failed
            if operation_id in self.active_operations:
                self.active_operations[operation_id]['status'] = 'failed'
                self.active_operations[operation_id]['error'] = str(e)
                self.active_operations[operation_id]['end_time'] = datetime.now(timezone.utc).isoformat()
            
            # Send failure notification
            self._send_failure_notification(instance_id, operation_id, str(e))
            
            return {
                'operation_id': operation_id,
                'instance_id': instance_id,
                'status': 'failed',
                'error': str(e),
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
    
    def _validate_instance(self, instance_id, operation_id):
        """Validate that the instance exists and is accessible"""
        try:
            response = ec2_client.describe_instances(InstanceIds=[instance_id])
            instances = response['Reservations'][0]['Instances']
            
            if not instances:
                raise ValueError(f"Instance {instance_id} not found")
            
            instance = instances[0]
            state = instance['State']['Name']
            
            if state == 'terminated':
                raise ValueError(f"Instance {instance_id} is already terminated")
            
            if state == 'stopping':
                raise ValueError(f"Instance {instance_id} is stopping, cannot isolate")
            
            self._log_step(operation_id, 'validate_instance', 'success', f"Instance {instance_id} validated (state: {state})")
            
        except ClientError as e:
            if 'InvalidInstanceID.NotFound' in str(e):
                raise ValueError(f"Instance {instance_id} not found")
            else:
                raise
    
    def _get_current_security_groups(self, instance_id, operation_id):
        """Get current security groups for backup purposes"""
        try:
            response = ec2_client.describe_instances(InstanceIds=[instance_id])
            instance = response['Reservations'][0]['Instances'][0]
            current_sgs = [sg['GroupId'] for sg in instance['SecurityGroups']]
            
            self._log_step(operation_id, 'get_security_groups', 'success', f"Current SGs: {current_sgs}")
            return current_sgs
            
        except Exception as e:
            self._log_step(operation_id, 'get_security_groups', 'failed', str(e))
            raise
    
    def _apply_isolation_security_group(self, instance_id, operation_id):
        """Apply isolation security group to instance"""
        try:
            logger.info(f"Applying isolation security group {ISOLATION_SG_ID} to instance {instance_id}")
            
            ec2_client.modify_instance_attribute(
                InstanceId=instance_id,
                Groups=[ISOLATION_SG_ID]
            )
            
            # Wait for change to propagate
            time.sleep(5)
            
            self._log_step(operation_id, 'apply_isolation_sg', 'success', f"Applied isolation SG {ISOLATION_SG_ID}")
            
        except Exception as e:
            self._log_step(operation_id, 'apply_isolation_sg', 'failed', str(e))
            raise
    
    def _verify_isolation(self, instance_id, operation_id, max_attempts=3):
        """Verify that instance is properly isolated"""
        for attempt in range(max_attempts):
            try:
                response = ec2_client.describe_instances(InstanceIds=[instance_id])
                instance = response['Reservations'][0]['Instances'][0]
                current_sgs = [sg['GroupId'] for sg in instance['SecurityGroups']]
                
                if len(current_sgs) == 1 and current_sgs[0] == ISOLATION_SG_ID:
                    self._log_step(operation_id, 'verify_isolation', 'success', f"Isolation verified (attempt {attempt + 1})")
                    return True
                
                logger.warning(f"Isolation verification attempt {attempt + 1} failed. Current SGs: {current_sgs}")
                time.sleep(2)
                
            except Exception as e:
                logger.warning(f"Error during isolation verification attempt {attempt + 1}: {str(e)}")
                if attempt == max_attempts - 1:
                    raise
                time.sleep(2)
        
        raise RuntimeError("Failed to verify instance isolation")
    
    def _send_isolation_notification(self, instance_id, original_sgs, operation_id):
        """Send notification about successful isolation"""
        try:
            if SNS_TOPIC_ARN:
                message = {
                    'event_type': 'instance_isolated',
                    'instance_id': instance_id,
                    'environment': ENVIRONMENT,
                    'operation_id': operation_id,
                    'original_security_groups': original_sgs,
                    'isolation_security_group': ISOLATION_SG_ID,
                    'timestamp': datetime.now(timezone.utc).isoformat()
                }
                
                sns_client.publish(
                    TopicArn=SNS_TOPIC_ARN,
                    Subject=f"SOAR: Instance {instance_id} Isolated",
                    Message=json.dumps(message, indent=2)
                )
                
                self._log_step(operation_id, 'send_notification', 'success', 'Isolation notification sent')
            
        except Exception as e:
            self._log_step(operation_id, 'send_notification', 'failed', str(e))
            # Don't raise - notification failure shouldn't fail the operation
    
    def _send_failure_notification(self, instance_id, operation_id, error):
        """Send notification about isolation failure"""
        try:
            if SNS_TOPIC_ARN:
                message = {
                    'event_type': 'isolation_failed',
                    'instance_id': instance_id,
                    'environment': ENVIRONMENT,
                    'operation_id': operation_id,
                    'error': error,
                    'timestamp': datetime.now(timezone.utc).isoformat()
                }
                
                sns_client.publish(
                    TopicArn=SNS_TOPIC_ARN,
                    Subject=f"SOAR ALERT: Isolation Failed for Instance {instance_id}",
                    Message=json.dumps(message, indent=2)
                )
            
        except Exception as e:
            logger.error(f"Failed to send failure notification: {str(e)}")
    
    def _log_step(self, operation_id, step_name, status, details):
        """Log operation step details"""
        if operation_id in self.active_operations:
            self.active_operations[operation_id]['steps'].append({
                'step': step_name,
                'status': status,
                'details': details,
                'timestamp': datetime.now(timezone.utc).isoformat()
            })
    
    def get_operation_status(self, operation_id):
        """Get status of a specific operation"""
        return self.active_operations.get(operation_id, {'status': 'not_found'})
    
    def get_active_operations(self):
        """Get all active operations"""
        return self.active_operations

# Initialize worker
worker = IsolationWorker()

# Flask routes
@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'environment': ENVIRONMENT,
        'active_operations': len(worker.active_operations)
    })

@app.route('/isolate', methods=['POST'])
def isolate_instance():
    """Isolate instance endpoint"""
    try:
        data = request.get_json()
        
        if not data or 'instance_id' not in data:
            return jsonify({'error': 'instance_id is required'}), 400
        
        instance_id = data['instance_id']
        operation_id = data.get('operation_id')
        
        result = worker.isolate_instance(instance_id, operation_id)
        
        return jsonify(result), 200
        
    except Exception as e:
        logger.error(f"Error in isolate endpoint: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/status/<operation_id>', methods=['GET'])
def get_operation_status(operation_id):
    """Get operation status endpoint"""
    try:
        status = worker.get_operation_status(operation_id)
        
        if status.get('status') == 'not_found':
            return jsonify({'error': 'Operation not found'}), 404
        
        return jsonify(status), 200
        
    except Exception as e:
        logger.error(f"Error in status endpoint: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/operations', methods=['GET'])
def get_active_operations():
    """Get all active operations endpoint"""
    try:
        operations = worker.get_active_operations()
        return jsonify(operations), 200
        
    except Exception as e:
        logger.error(f"Error in operations endpoint: {str(e)}")
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    logger.info("Starting SOAR Isolation Worker")
    app.run(host='0.0.0.0', port=8080, debug=False)
