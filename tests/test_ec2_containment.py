import json
import pytest
from moto import mock_aws
import boto3
import os

from src.playbooks.ec2_containment import EC2ContainmentPlaybook
from src.core.logger import logger

@pytest.fixture
def aws_credentials():
    """Mocked AWS Credentials for moto."""
    os.environ['AWS_ACCESS_KEY_ID'] = 'testing'
    os.environ['AWS_SECRET_ACCESS_KEY'] = 'testing'
    os.environ['AWS_SECURITY_TOKEN'] = 'testing'
    os.environ['AWS_SESSION_TOKEN'] = 'testing'
    os.environ['AWS_DEFAULT_REGION'] = 'us-east-1'
    os.environ['ISOLATION_SG_ID'] = 'sg-12345678'

@pytest.fixture
def ec2_client(aws_credentials):
    with mock_aws():
        yield boto3.client('ec2', region_name='us-east-1')

def test_ec2_containment_playbook_execution(ec2_client):
    """Test full execution of EC2 playbook using Moto mocks."""
    
    # 1. Setup mock infrastructure
    vpc = ec2_client.create_vpc(CidrBlock='10.0.0.0/16')
    subnet = ec2_client.create_subnet(VpcId=vpc['Vpc']['VpcId'], CidrBlock='10.0.1.0/24')
    
    reservation = ec2_client.run_instances(
        ImageId='ami-12c6146b',
        MinCount=1,
        MaxCount=1,
        InstanceType='t2.micro',
        SubnetId=subnet['Subnet']['SubnetId']
    )
    instance_id = reservation['Instances'][0]['InstanceId']
    
    # Mock Isolation SG
    sg = ec2_client.create_security_group(
        GroupName="IsolationSG", 
        Description="Isolate", 
        VpcId=vpc['Vpc']['VpcId']
    )
    os.environ['ISOLATION_SG_ID'] = sg['GroupId']

    # 2. Setup mock GuardDuty Event
    mock_event = {
        "version": "0",
        "id": "event-id-123",
        "detail-type": "GuardDuty Finding",
        "source": "aws.guardduty",
        "account": "123456789012",
        "time": "2026-03-01T00:00:00Z",
        "region": "us-east-1",
        "resources": [],
        "detail": {
            "schemaVersion": "2.0",
            "accountId": "123456789012",
            "region": "us-east-1",
            "partition": "aws",
            "id": "1234567890",
            "arn": "arn:aws:guardduty:us-east-1:12345:finding/1",
            "type": "CryptoCurrency:EC2/BitcoinTool.B!DNS",
            "service": {"resourceRole": "TARGET"},
            "severity": 8.0,
            "createdAt": "2026-03-01T00:00:00Z",
            "updatedAt": "2026-03-01T00:00:00Z",
            "title": "Crypto mining detected",
            "description": "Bitcoin mining detected",
            "resources": [{"instanceDetails": {"instanceId": instance_id}}]
        }
    }

    # 3. Execute playbook
    playbook = EC2ContainmentPlaybook()
    assert playbook.can_handle(mock_event) == True
    
    success = playbook.execute(mock_event)
    assert success == True

    # 4. Verify outcomes
    instance = ec2_client.describe_instances(InstanceIds=[instance_id])['Reservations'][0]['Instances'][0]
    
    # Check if instance is stopped
    assert instance['State']['Name'] in ['stopping', 'stopped']
    
    # Check if security group was swapped
    assert any(g['GroupId'] == sg['GroupId'] for g in instance['SecurityGroups'])
