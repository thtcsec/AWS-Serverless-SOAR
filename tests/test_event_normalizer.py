"""Tests for AWS Unified Event Normalizer."""
import pytest
from src.core.event_normalizer import EventNormalizer, UnifiedIncident


class TestUnifiedIncidentSchema:
    def test_default_platform_is_aws(self):
        incident = UnifiedIncident()
        assert incident.platform == "aws"

    def test_custom_fields(self):
        incident = UnifiedIncident(
            incident_id="test-123",
            severity="CRITICAL",
            source_ip="1.2.3.4",
            actor="admin",
        )
        assert incident.incident_id == "test-123"
        assert incident.severity == "CRITICAL"


class TestEventNormalizerGuardDuty:
    @pytest.fixture
    def guardduty_event(self):
        return {
            "source": "aws.guardduty",
            "detail-type": "GuardDuty Finding",
            "time": "2026-03-10T00:00:00Z",
            "detail": {
                "type": "Recon:EC2/Portscan",
                "severity": 8.0,
                "service": {
                    "action": {
                        "networkConnectionAction": {
                            "remoteIpDetails": {"ipAddressV4": "198.51.100.1"}
                        }
                    }
                },
                "resource": {
                    "instanceDetails": {"instanceId": "i-0abc123def"},
                    "accessKeyDetails": {"userName": "attacker"},
                },
            },
        }

    def test_normalize_guardduty(self, guardduty_event):
        result = EventNormalizer.normalize(guardduty_event)
        assert result is not None
        assert result.platform == "aws"
        assert result.source_ip == "198.51.100.1"
        assert result.severity == "CRITICAL"
        assert result.raw_event_type == "GuardDutyFinding"
        assert "guardduty" in result.tags

    def test_guardduty_correlation_keys(self, guardduty_event):
        result = EventNormalizer.from_guardduty(guardduty_event)
        assert "198.51.100.1" in result.correlation_keys
        assert "attacker" in result.correlation_keys


class TestEventNormalizerIAM:
    @pytest.fixture
    def iam_event(self):
        return {
            "source": "aws.iam",
            "detail": {
                "eventName": "CreateAccessKey",
                "userIdentity": {"userName": "malicious-user"},
                "sourceIPAddress": "203.0.113.5",
            },
        }

    def test_normalize_iam(self, iam_event):
        result = EventNormalizer.normalize(iam_event)
        assert result is not None
        assert result.platform == "aws"
        assert result.actor == "malicious-user"
        assert result.action == "CreateAccessKey"
        assert result.resource_type == "iam_user"

    def test_iam_correlation_keys(self, iam_event):
        result = EventNormalizer.from_cloudtrail_iam(iam_event)
        assert "203.0.113.5" in result.correlation_keys
        assert "malicious-user" in result.correlation_keys


class TestEventNormalizerS3:
    @pytest.fixture
    def s3_event(self):
        return {
            "source": "aws.s3",
            "detail": {
                "eventName": "GetObject",
                "userIdentity": {"userName": "data-thief"},
                "sourceIPAddress": "10.0.0.1",
                "requestParameters": {"bucketName": "sensitive-bucket"},
            },
        }

    def test_normalize_s3(self, s3_event):
        result = EventNormalizer.normalize(s3_event)
        assert result is not None
        assert result.resource == "sensitive-bucket"
        assert result.resource_type == "s3_bucket"

    def test_unknown_event_returns_none(self):
        result = EventNormalizer.normalize({"source": "aws.unknown"})
        assert result is None
