import os

import boto3
import pytest
from moto import mock_aws


@pytest.fixture(autouse=True)
def aws_credentials():
    """Mocked AWS Credentials for moto."""
    os.environ["AWS_ACCESS_KEY_ID"] = "testing"
    os.environ["AWS_SECRET_ACCESS_KEY"] = "testing"
    os.environ["AWS_SECURITY_TOKEN"] = "testing"
    os.environ["AWS_SESSION_TOKEN"] = "testing"
    os.environ["AWS_DEFAULT_REGION"] = "us-east-1"

    from src.clients.aws import AWSClientFacade

    for cached in (
        AWSClientFacade.ec2,
        AWSClientFacade.s3,
        AWSClientFacade.iam,
        AWSClientFacade.sns,
        AWSClientFacade.cloudtrail,
        AWSClientFacade.cloudwatch,
        AWSClientFacade.securityhub,
        AWSClientFacade.rds,
        AWSClientFacade.eks,
        AWSClientFacade.wafv2,
        AWSClientFacade.codepipeline,
        AWSClientFacade.codebuild,
    ):
        cached.cache_clear()
    yield


@pytest.fixture
def mock_aws_env():
    """Provide a full moto mock context."""
    with mock_aws():
        yield


@pytest.fixture
def ec2_client(mock_aws_env):
    return boto3.client("ec2", region_name="us-east-1")


@pytest.fixture
def s3_client(mock_aws_env):
    return boto3.client("s3", region_name="us-east-1")


@pytest.fixture
def iam_client(mock_aws_env):
    return boto3.client("iam", region_name="us-east-1")


def make_guardduty_event(instance_id="i-1234567890abcdef0"):
    """Factory for mock GuardDuty events."""
    return {
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
            "id": "finding-001",
            "arn": "arn:aws:guardduty:us-east-1:12345:finding/1",
            "type": "CryptoCurrency:EC2/BitcoinTool.B!DNS",
            "service": {"resourceRole": "TARGET"},
            "severity": 8.0,
            "createdAt": "2026-03-01T00:00:00Z",
            "updatedAt": "2026-03-01T00:00:00Z",
            "title": "Crypto mining detected",
            "description": "Bitcoin mining detected",
            "resources": [{"instanceDetails": {"instanceId": instance_id}}],
        },
    }


def make_s3_cloudtrail_event(
    event_name="GetObject",
    bucket_name="target-bucket",
    user_arn="arn:aws:iam::123456789012:user/attacker",
):
    """Factory for mock S3 CloudTrail events."""
    return {
        "source": "aws.s3",
        "detail": {
            "eventName": event_name,
            "requestParameters": {"bucketName": bucket_name},
            "userIdentity": {"arn": user_arn},
            "sourceIPAddress": "198.51.100.1",
        },
    }


def make_iam_cloudtrail_event(event_name="CreateAccessKey", username="compromised-user"):
    """Factory for mock IAM CloudTrail events."""
    return {
        "source": "aws.iam",
        "detail": {
            "eventName": event_name,
            "userIdentity": {"userName": username},
            "sourceIPAddress": "198.51.100.1",
        },
    }


def build_incident(event: dict, decision: str = "AUTO_ISOLATE", risk_score: float = 95.0):
    """Build a UnifiedIncident with pipeline decision fields set (for playbook unit tests)."""
    from src.core.event_normalizer import EventNormalizer

    incident = EventNormalizer.ensure(event)
    incident.decision = decision
    incident.risk_score = risk_score
    return incident
