"""Tests for the Ransomware Response Playbook (AWS)."""

from unittest.mock import patch

import boto3
from moto import mock_aws

from src.playbooks.ransomware_response import RansomwareResponsePlaybook

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_ransomware_event(
    finding_type: str = "Impact:EC2/BitcoinDomainRequest.Reputation",
    instance_id: str = "i-0abcdef1234567890",
) -> dict:
    """Factory for a GuardDuty ransomware event."""
    return {
        "version": "0",
        "id": "event-ransomware-001",
        "detail-type": "GuardDuty Finding",
        "source": "aws.guardduty",
        "account": "123456789012",
        "time": "2026-03-10T00:00:00Z",
        "region": "us-east-1",
        "resources": [],
        "detail": {
            "schemaVersion": "2.0",
            "accountId": "123456789012",
            "region": "us-east-1",
            "partition": "aws",
            "id": "finding-ransomware-001",
            "arn": "arn:aws:guardduty:us-east-1:12345:finding/ransomware-1",
            "type": finding_type,
            "service": {"resourceRole": "TARGET"},
            "severity": 9.0,
            "createdAt": "2026-03-10T00:00:00Z",
            "updatedAt": "2026-03-10T00:00:00Z",
            "title": "Ransomware activity detected",
            "description": "Ransomware-like activity detected on instance",
            "resource": {
                "instanceDetails": {"instanceId": instance_id},
            },
        },
    }


def _make_s3_ransomware_event(bucket_name: str = "victim-bucket") -> dict:
    """Factory for a GuardDuty S3 ransomware event."""
    return {
        "version": "0",
        "id": "event-ransomware-s3-001",
        "detail-type": "GuardDuty Finding",
        "source": "aws.guardduty",
        "account": "123456789012",
        "time": "2026-03-10T00:00:00Z",
        "region": "us-east-1",
        "resources": [],
        "detail": {
            "schemaVersion": "2.0",
            "accountId": "123456789012",
            "region": "us-east-1",
            "partition": "aws",
            "id": "finding-ransomware-s3-001",
            "arn": "arn:aws:guardduty:us-east-1:12345:finding/ransomware-s3-1",
            "type": "Impact:S3/MaliciousIPCaller",
            "service": {"resourceRole": "TARGET"},
            "severity": 8.0,
            "createdAt": "2026-03-10T00:00:00Z",
            "updatedAt": "2026-03-10T00:00:00Z",
            "title": "S3 ransomware detected",
            "description": "Malicious activity on S3 bucket",
            "resource": {
                "s3BucketDetails": [{"name": bucket_name}],
            },
        },
    }


# ---------------------------------------------------------------------------
# can_handle tests
# ---------------------------------------------------------------------------


class TestCanHandle:
    def test_matches_ransomware_finding(self):
        pb = RansomwareResponsePlaybook()
        assert pb.can_handle(_make_ransomware_event()) is True

    def test_matches_cryptocurrency_finding(self):
        pb = RansomwareResponsePlaybook()
        event = _make_ransomware_event(finding_type="CryptoCurrency:EC2/BitcoinTool.B!DNS")
        assert pb.can_handle(event) is True

    def test_matches_impact_s3_finding(self):
        pb = RansomwareResponsePlaybook()
        assert pb.can_handle(_make_s3_ransomware_event()) is True

    def test_rejects_non_guardduty(self):
        pb = RansomwareResponsePlaybook()
        assert pb.can_handle({"source": "aws.s3", "detail": {}}) is False

    def test_rejects_benign_guardduty(self):
        pb = RansomwareResponsePlaybook()
        event = _make_ransomware_event(finding_type="Recon:EC2/PortProbeUnprotectedPort")
        assert pb.can_handle(event) is False

    def test_rejects_garbage(self):
        pb = RansomwareResponsePlaybook()
        assert pb.can_handle({"garbage": True}) is False


# ---------------------------------------------------------------------------
# execute tests — EC2 branch
# ---------------------------------------------------------------------------


class TestExecuteEC2:
    @mock_aws
    def test_snapshot_isolate_stop(self):
        """Full EC2 flow: snapshot → isolate → stop."""
        ec2 = boto3.client("ec2", region_name="us-east-1")

        # Create a VPC + SG for isolation
        vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")
        vpc_id = vpc["Vpc"]["VpcId"]
        sg = ec2.create_security_group(GroupName="isolation-sg", Description="Isolation SG", VpcId=vpc_id)
        sg_id = sg["GroupId"]

        # Create an instance
        reservation = ec2.run_instances(ImageId="ami-12345678", MinCount=1, MaxCount=1)
        instance_id = reservation["Instances"][0]["InstanceId"]

        event = _make_ransomware_event(instance_id=instance_id)

        with patch.dict("os.environ", {"ISOLATION_SG_ID": sg_id}):
            pb = RansomwareResponsePlaybook()
            result = pb.execute(event)

        assert result is True

        # Verify instance stopped
        desc = ec2.describe_instances(InstanceIds=[instance_id])
        state = desc["Reservations"][0]["Instances"][0]["State"]["Name"]
        assert state in ("stopped", "stopping")


# ---------------------------------------------------------------------------
# execute tests — S3 branch
# ---------------------------------------------------------------------------


class TestExecuteS3:
    @mock_aws
    def test_enable_versioning_and_freeze(self):
        """Full S3 flow: enable versioning → apply deny-all policy."""
        s3 = boto3.client("s3", region_name="us-east-1")
        bucket = "victim-bucket"
        s3.create_bucket(Bucket=bucket)

        event = _make_s3_ransomware_event(bucket_name=bucket)

        pb = RansomwareResponsePlaybook()
        result = pb.execute(event)

        assert result is True

        # Verify versioning enabled
        versioning = s3.get_bucket_versioning(Bucket=bucket)
        assert versioning.get("Status") == "Enabled"

        # Verify policy applied
        policy = s3.get_bucket_policy(Bucket=bucket)
        assert "SOARRansomwareFreeze" in policy["Policy"]


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


class TestEdgeCases:
    def test_no_resource_still_succeeds(self):
        """If no instance nor bucket, playbook should still return True (just warns)."""
        event = _make_ransomware_event()
        event["detail"]["resource"] = {}

        pb = RansomwareResponsePlaybook()
        result = pb.execute(event)
        assert result is True

    def test_execute_failure_returns_false(self):
        """Simulate a hard failure inside execute."""
        event = _make_ransomware_event()

        with patch(
            "src.playbooks.ransomware_response.GuardDutyEvent.model_validate",
            side_effect=RuntimeError("boom"),
        ):
            pb = RansomwareResponsePlaybook()
            assert pb.execute(event) is False
