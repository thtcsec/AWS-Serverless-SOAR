"""
Enterprise SOAR - Cross-Account Responder
Handles incident response across multiple AWS accounts
"""

import json
import os
import boto3
import logging
from datetime import datetime, timezone
from botocore.exceptions import ClientError

# Configure logging
logging.basicConfig(
    level=getattr(logging, os.environ.get('LOG_LEVEL', 'INFO')),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class CrossAccountResponder:
    """Enterprise cross-account incident response handler"""
    
    def __init__(self):
        self.sts_client = boto3.client('sts')
        self.external_id = os.environ.get('CROSS_ACCOUNT_EXTERNAL_ID', 'soar-cross-account-2024')
        
        # Account configurations
        self.account_configs = {
            'dev': {
                'account_id': os.environ.get('DEV_ACCOUNT_ID'),
                'role_name': os.environ.get('DEV_SOAR_ROLE_NAME', 'soar-cross-account-responder')
            },
            'staging': {
                'account_id': os.environ.get('STAGING_ACCOUNT_ID'),
                'role_name': os.environ.get('STAGING_SOAR_ROLE_NAME', 'soar-cross-account-responder')
            },
            'prod': {
                'account_id': os.environ.get('PROD_ACCOUNT_ID'),
                'role_name': os.environ.get('PROD_SOAR_ROLE_NAME', 'soar-cross-account-responder')
            }
        }
    
    def assume_cross_account_role(self, account_name):
        """
        Assume role in target account
        
        Args:
            account_name (str): Target account name (dev, staging, prod)
            
        Returns:
            boto3.Session: Session with assumed role credentials
        """
        try:
            config = self.account_configs.get(account_name)
            if not config or not config['account_id']:
                raise ValueError(f"Account {account_name} not configured")
            
            role_arn = f"arn:aws:iam::{config['account_id']}:role/{config['role_name']}"
            
            logger.info(f"Assuming role {role_arn} in account {account_name}")
            
            response = self.sts_client.assume_role(
                RoleArn=role_arn,
                RoleSessionName=f"soar-cross-account-{account_name}-{int(datetime.now(timezone.utc).timestamp())}",
                ExternalId=self.external_id
            )
            
            credentials = response['Credentials']
            
            # Create session with assumed role credentials
            assumed_session = boto3.Session(
                aws_access_key_id=credentials['AccessKeyId'],
                aws_secret_access_key=credentials['SecretAccessKey'],
                aws_session_token=credentials['SessionToken']
            )
            
            logger.info(f"Successfully assumed role in account {account_name}")
            return assumed_session
            
        except Exception as e:
            logger.error(f"Failed to assume role in account {account_name}: {str(e)}")
            raise
    
    def isolate_instance_cross_account(self, account_name, instance_id, isolation_sg_id):
        """
        Isolate instance in target account
        
        Args:
            account_name (str): Target account name
            instance_id (str): EC2 instance ID to isolate
            isolation_sg_id (str): Isolation security group ID
            
        Returns:
            dict: Operation result
        """
        try:
            # Assume role in target account
            session = self.assume_cross_account_role(account_name)
            ec2_client = session.client('ec2')
            
            logger.info(f"Isolating instance {instance_id} in account {account_name}")
            
            # Get current security groups
            response = ec2_client.describe_instances(InstanceIds=[instance_id])
            instance = response['Reservations'][0]['Instances'][0]
            current_sgs = [sg['GroupId'] for sg in instance['SecurityGroups']]
            
            # Store original security groups
            original_sgs = current_sgs.copy()
            
            # Apply isolation security group
            ec2_client.modify_instance_attribute(
                InstanceId=instance_id,
                Groups=[isolation_sg_id]
            )
            
            result = {
                'account_name': account_name,
                'account_id': self.account_configs[account_name]['account_id'],
                'instance_id': instance_id,
                'isolation_successful': True,
                'original_security_groups': original_sgs,
                'isolation_security_group': isolation_sg_id,
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
            
            logger.info(f"Successfully isolated instance {instance_id} in account {account_name}")
            return result
            
        except Exception as e:
            logger.error(f"Failed to isolate instance {instance_id} in account {account_name}: {str(e)}")
            return {
                'account_name': account_name,
                'instance_id': instance_id,
                'isolation_successful': False,
                'error': str(e),
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
    
    def create_snapshot_cross_account(self, account_name, volume_id, description):
        """
        Create snapshot in target account
        
        Args:
            account_name (str): Target account name
            volume_id (str): EBS volume ID
            description (str): Snapshot description
            
        Returns:
            dict: Operation result
        """
        try:
            # Assume role in target account
            session = self.assume_cross_account_role(account_name)
            ec2_client = session.client('ec2')
            
            logger.info(f"Creating snapshot of volume {volume_id} in account {account_name}")
            
            # Create snapshot
            response = ec2_client.create_snapshot(
                VolumeId=volume_id,
                Description=description,
                TagSpecifications=[
                    {
                        'ResourceType': 'snapshot',
                        'Tags': [
                            {
                                'Key': 'Name',
                                'Value': f"forensic-{volume_id}-{int(datetime.now(timezone.utc).timestamp())}"
                            },
                            {
                                'Key': 'Purpose',
                                'Value': 'cross-account-forensics'
                            },
                            {
                                'Key': 'CreatedBy',
                                'Value': 'SOAR-CrossAccount'
                            },
                            {
                                'Key': 'CreatedDate',
                                'Value': datetime.now(timezone.utc).isoformat()
                            }
                        ]
                    }
                ]
            )
            
            result = {
                'account_name': account_name,
                'account_id': self.account_configs[account_name]['account_id'],
                'volume_id': volume_id,
                'snapshot_id': response['SnapshotId'],
                'snapshot_status': response['State'],
                'creation_successful': True,
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
            
            logger.info(f"Successfully created snapshot {response['SnapshotId']} in account {account_name}")
            return result
            
        except Exception as e:
            logger.error(f"Failed to create snapshot of volume {volume_id} in account {account_name}: {str(e)}")
            return {
                'account_name': account_name,
                'volume_id': volume_id,
                'creation_successful': False,
                'error': str(e),
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
    
    def terminate_instance_cross_account(self, account_name, instance_id):
        """
        Terminate instance in target account
        
        Args:
            account_name (str): Target account name
            instance_id (str): EC2 instance ID to terminate
            
        Returns:
            dict: Operation result
        """
        try:
            # Assume role in target account
            session = self.assume_cross_account_role(account_name)
            ec2_client = session.client('ec2')
            
            logger.info(f"Terminating instance {instance_id} in account {account_name}")
            
            # Terminate instance
            ec2_client.terminate_instances(InstanceIds=[instance_id])
            
            result = {
                'account_name': account_name,
                'account_id': self.account_configs[account_name]['account_id'],
                'instance_id': instance_id,
                'termination_successful': True,
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
            
            logger.info(f"Successfully terminated instance {instance_id} in account {account_name}")
            return result
            
        except Exception as e:
            logger.error(f"Failed to terminate instance {instance_id} in account {account_name}: {str(e)}")
            return {
                'account_name': account_name,
                'instance_id': instance_id,
                'termination_successful': False,
                'error': str(e),
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
    
    def revoke_iam_credentials_cross_account(self, account_name, user_name, access_key_id=None):
        """
        Revoke IAM credentials in target account
        
        Args:
            account_name (str): Target account name
            user_name (str): IAM user name
            access_key_id (str): Specific access key ID to revoke (optional)
            
        Returns:
            dict: Operation result
        """
        try:
            # Assume role in target account
            session = self.assume_cross_account_role(account_name)
            iam_client = session.client('iam')
            
            logger.info(f"Revoking credentials for user {user_name} in account {account_name}")
            
            revoked_keys = []
            
            if access_key_id:
                # Deactivate specific access key
                iam_client.update_access_key(
                    UserName=user_name,
                    AccessKeyId=access_key_id,
                    Status='Inactive'
                )
                revoked_keys.append(access_key_id)
            else:
                # Deactivate all access keys for the user
                response = iam_client.list_access_keys(UserName=user_name)
                
                for key in response['AccessKeyMetadata']:
                    if key['Status'] == 'Active':
                        iam_client.update_access_key(
                            UserName=user_name,
                            AccessKeyId=key['AccessKeyId'],
                            Status='Inactive'
                        )
                        revoked_keys.append(key['AccessKeyId'])
            
            result = {
                'account_name': account_name,
                'account_id': self.account_configs[account_name]['account_id'],
                'user_name': user_name,
                'revoked_access_keys': revoked_keys,
                'revocation_successful': True,
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
            
            logger.info(f"Successfully revoked {len(revoked_keys)} access keys for user {user_name} in account {account_name}")
            return result
            
        except Exception as e:
            logger.error(f"Failed to revoke credentials for user {user_name} in account {account_name}: {str(e)}")
            return {
                'account_name': account_name,
                'user_name': user_name,
                'revocation_successful': False,
                'error': str(e),
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
    
    def secure_s3_bucket_cross_account(self, account_name, bucket_name):
        """
        Secure S3 bucket in target account
        
        Args:
            account_name (str): Target account name
            bucket_name (str): S3 bucket name to secure
            
        Returns:
            dict: Operation result
        """
        try:
            # Assume role in target account
            session = self.assume_cross_account_role(account_name)
            s3_client = session.client('s3')
            
            logger.info(f"Securing S3 bucket {bucket_name} in account {account_name}")
            
            # Enable versioning
            s3_client.put_bucket_versioning(
                Bucket=bucket_name,
                VersioningConfiguration={
                    'Status': 'Enabled',
                    'MFADelete': 'Disabled'
                }
            )
            
            # Enable default encryption
            s3_client.put_bucket_encryption(
                Bucket=bucket_name,
                ServerSideEncryptionConfiguration={
                    'Rules': [
                        {
                            'ApplyServerSideEncryptionByDefault': {
                                'SSEAlgorithm': 'AES256'
                            }
                        }
                    ]
                }
            )
            
            # Block public access
            s3_client.put_public_access_block(
                Bucket=bucket_name,
                PublicAccessBlockConfiguration={
                    'BlockPublicAcls': True,
                    'BlockPublicPolicy': True,
                    'IgnorePublicAcls': True,
                    'RestrictPublicBuckets': True
                }
            )
            
            # Enable logging
            log_bucket_name = f"{bucket_name}-access-logs"
            
            try:
                s3_client.put_bucket_logging(
                    Bucket=bucket_name,
                    BucketLoggingStatus={
                        'LoggingEnabled': {
                            'TargetBucket': log_bucket_name,
                            'TargetPrefix': 'access-logs/'
                        }
                    }
                )
                logging_enabled = True
            except ClientError as e:
                if 'NoSuchBucket' in str(e):
                    logging_enabled = False
                    logger.warning(f"Log bucket {log_bucket_name} not found, skipping logging configuration")
                else:
                    raise
            
            result = {
                'account_name': account_name,
                'account_id': self.account_configs[account_name]['account_id'],
                'bucket_name': bucket_name,
                'versioning_enabled': True,
                'encryption_enabled': True,
                'public_access_blocked': True,
                'logging_enabled': logging_enabled,
                'security_successful': True,
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
            
            logger.info(f"Successfully secured S3 bucket {bucket_name} in account {account_name}")
            return result
            
        except Exception as e:
            logger.error(f"Failed to secure S3 bucket {bucket_name} in account {account_name}: {str(e)}")
            return {
                'account_name': account_name,
                'bucket_name': bucket_name,
                'security_successful': False,
                'error': str(e),
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
    
    def get_account_security_posture(self, account_name):
        """
        Get security posture summary for target account
        
        Args:
            account_name (str): Target account name
            
        Returns:
            dict: Security posture summary
        """
        try:
            # Assume role in target account
            session = self.assume_cross_account_role(account_name)
            
            # Initialize clients
            ec2_client = session.client('ec2')
            iam_client = session.client('iam')
            s3_client = session.client('s3')
            
            posture = {
                'account_name': account_name,
                'account_id': self.account_configs[account_name]['account_id'],
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'security_metrics': {}
            }
            
            # Get EC2 instances count
            try:
                response = ec2_client.describe_instances()
                instances = [instance for reservation in response['Reservations'] for instance in reservation['Instances']]
                running_instances = [i for i in instances if i['State']['Name'] == 'running']
                
                posture['security_metrics']['ec2'] = {
                    'total_instances': len(instances),
                    'running_instances': len(running_instances),
                    'instances_with_public_ips': len([i for i in running_instances if i.get('PublicIpAddress')])
                }
            except Exception as e:
                posture['security_metrics']['ec2'] = {'error': str(e)}
            
            # Get IAM users and access keys
            try:
                response = iam_client.list_users()
                users = response['Users']
                
                total_access_keys = 0
                active_access_keys = 0
                
                for user in users:
                    keys_response = iam_client.list_access_keys(UserName=user['UserName'])
                    user_keys = keys_response['AccessKeyMetadata']
                    total_access_keys += len(user_keys)
                    active_access_keys += len([k for k in user_keys if k['Status'] == 'Active'])
                
                posture['security_metrics']['iam'] = {
                    'total_users': len(users),
                    'total_access_keys': total_access_keys,
                    'active_access_keys': active_access_keys
                }
            except Exception as e:
                posture['security_metrics']['iam'] = {'error': str(e)}
            
            # Get S3 buckets
            try:
                response = s3_client.list_buckets()
                buckets = response['Buckets']
                
                public_buckets = 0
                versioned_buckets = 0
                encrypted_buckets = 0
                
                for bucket in buckets[:50]:  # Limit to first 50 buckets for performance
                    try:
                        # Check public access block
                        try:
                            s3_client.get_public_access_block(Bucket=bucket['Name'])
                            # If no exception, public access is blocked
                        except ClientError:
                            public_buckets += 1
                        
                        # Check versioning
                        versioning = s3_client.get_bucket_versioning(Bucket=bucket['Name'])
                        if versioning.get('Status') == 'Enabled':
                            versioned_buckets += 1
                        
                        # Check encryption
                        try:
                            s3_client.get_bucket_encryption(Bucket=bucket['Name'])
                            encrypted_buckets += 1
                        except ClientError:
                            pass
                            
                    except Exception:
                        continue  # Skip buckets we can't access
                
                posture['security_metrics']['s3'] = {
                    'total_buckets': len(buckets),
                    'public_buckets': public_buckets,
                    'versioned_buckets': versioned_buckets,
                    'encrypted_buckets': encrypted_buckets
                }
            except Exception as e:
                posture['security_metrics']['s3'] = {'error': str(e)}
            
            return posture
            
        except Exception as e:
            logger.error(f"Failed to get security posture for account {account_name}: {str(e)}")
            return {
                'account_name': account_name,
                'error': str(e),
                'timestamp': datetime.now(timezone.utc).isoformat()
            }

def lambda_handler(event, context):
    """
    Lambda handler for cross-account operations
    
    Expected input:
    {
        "operation": "isolate_instance|create_snapshot|terminate_instance|revoke_credentials|secure_bucket|get_posture",
        "account_name": "dev|staging|prod",
        "parameters": {
            // Operation-specific parameters
        }
    }
    """
    try:
        logger.info(f"Processing cross-account operation: {json.dumps(event)}")
        
        operation = event.get('operation')
        account_name = event.get('account_name')
        parameters = event.get('parameters', {})
        
        if not operation or not account_name:
            raise ValueError("Both 'operation' and 'account_name' are required")
        
        responder = CrossAccountResponder()
        
        # Route to appropriate operation
        if operation == 'isolate_instance':
            instance_id = parameters.get('instance_id')
            isolation_sg_id = parameters.get('isolation_sg_id')
            
            if not instance_id or not isolation_sg_id:
                raise ValueError("'instance_id' and 'isolation_sg_id' are required for isolate_instance operation")
            
            result = responder.isolate_instance_cross_account(account_name, instance_id, isolation_sg_id)
            
        elif operation == 'create_snapshot':
            volume_id = parameters.get('volume_id')
            description = parameters.get('description', 'Cross-account forensic snapshot')
            
            if not volume_id:
                raise ValueError("'volume_id' is required for create_snapshot operation")
            
            result = responder.create_snapshot_cross_account(account_name, volume_id, description)
            
        elif operation == 'terminate_instance':
            instance_id = parameters.get('instance_id')
            
            if not instance_id:
                raise ValueError("'instance_id' is required for terminate_instance operation")
            
            result = responder.terminate_instance_cross_account(account_name, instance_id)
            
        elif operation == 'revoke_credentials':
            user_name = parameters.get('user_name')
            access_key_id = parameters.get('access_key_id')
            
            if not user_name:
                raise ValueError("'user_name' is required for revoke_credentials operation")
            
            result = responder.revoke_iam_credentials_cross_account(account_name, user_name, access_key_id)
            
        elif operation == 'secure_bucket':
            bucket_name = parameters.get('bucket_name')
            
            if not bucket_name:
                raise ValueError("'bucket_name' is required for secure_bucket operation")
            
            result = responder.secure_s3_bucket_cross_account(account_name, bucket_name)
            
        elif operation == 'get_posture':
            result = responder.get_account_security_posture(account_name)
            
        else:
            raise ValueError(f"Unknown operation: {operation}")
        
        logger.info(f"Cross-account operation completed successfully")
        return result
        
    except Exception as e:
        logger.error(f"Error in cross-account responder: {str(e)}")
        raise e
