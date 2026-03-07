"""Tests for Pydantic event models."""
from src.models.events import (
    GuardDutyEvent, GuardDutyDetail, GuardDutyResource,
    S3CloudTrailEvent, S3CloudTrailDetail,
    IAMCloudTrailEvent, IAMCloudTrailDetail,
)
from pydantic import ValidationError
import pytest


class TestGuardDutyEvent:
    def test_valid_guardduty_event(self):
        data = {
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
                "id": "123",
                "arn": "arn:aws:guardduty:us-east-1:12345:finding/1",
                "type": "CryptoCurrency:EC2/BitcoinTool.B!DNS",
                "service": {"resourceRole": "TARGET"},
                "severity": 8.0,
                "createdAt": "2026-03-01T00:00:00Z",
                "updatedAt": "2026-03-01T00:00:00Z",
                "title": "Test",
                "description": "Test",
            }
        }
        event = GuardDutyEvent.model_validate(data)
        assert event.source == "aws.guardduty"
        assert event.detail.severity == 8.0
        assert event.detail.type == "CryptoCurrency:EC2/BitcoinTool.B!DNS"

    def test_invalid_source_rejected(self):
        data = {
            "version": "0", "id": "x",
            "detail-type": "GuardDuty Finding",
            "source": "aws.iam",
            "account": "1", "time": "t", "region": "r", "resources": [],
            "detail": {
                "schemaVersion": "2.0", "accountId": "1", "region": "r",
                "partition": "aws", "id": "1",
                "arn": "arn", "type": "t", "service": {},
                "severity": 1.0, "createdAt": "t", "updatedAt": "t",
                "title": "t", "description": "d"
            }
        }
        with pytest.raises(ValidationError):
            GuardDutyEvent.model_validate(data)

    def test_extra_fields_ignored(self):
        data = {
            "version": "0", "id": "x",
            "detail-type": "GuardDuty Finding",
            "source": "aws.guardduty",
            "account": "1", "time": "t", "region": "r", "resources": [],
            "extra_field": "should_be_ignored",
            "detail": {
                "schemaVersion": "2.0", "accountId": "1", "region": "r",
                "partition": "aws", "id": "1", "arn": "arn", "type": "t",
                "service": {}, "severity": 1.0, "createdAt": "t",
                "updatedAt": "t", "title": "t", "description": "d",
                "unknownField": "ignored"
            }
        }
        event = GuardDutyEvent.model_validate(data)
        assert event.source == "aws.guardduty"


class TestS3CloudTrailEvent:
    def test_valid_s3_event(self):
        data = {
            "source": "aws.s3",
            "detail": {
                "eventName": "GetObject",
                "requestParameters": {"bucketName": "my-bucket"},
                "userIdentity": {"arn": "arn:aws:iam::123456789012:user/test"},
            }
        }
        event = S3CloudTrailEvent.model_validate(data)
        assert event.detail.eventName == "GetObject"

    def test_invalid_source_rejected(self):
        with pytest.raises(ValidationError):
            S3CloudTrailEvent.model_validate({
                "source": "aws.ec2",
                "detail": {"eventName": "X", "userIdentity": {}}
            })

    def test_optional_fields(self):
        data = {
            "source": "aws.s3",
            "detail": {
                "eventName": "ListObjects",
                "userIdentity": {"arn": "test"},
            }
        }
        event = S3CloudTrailEvent.model_validate(data)
        assert event.detail.requestParameters is None
        assert event.detail.sourceIPAddress is None


class TestIAMCloudTrailEvent:
    def test_valid_iam_event(self):
        data = {
            "source": "aws.iam",
            "detail": {
                "eventName": "CreateAccessKey",
                "userIdentity": {"userName": "testuser"},
            }
        }
        event = IAMCloudTrailEvent.model_validate(data)
        assert event.detail.eventName == "CreateAccessKey"

    def test_error_code_optional(self):
        data = {
            "source": "aws.iam",
            "detail": {
                "eventName": "CreateUser",
                "userIdentity": {"userName": "x"},
                "errorCode": "AccessDenied"
            }
        }
        event = IAMCloudTrailEvent.model_validate(data)
        assert event.detail.errorCode == "AccessDenied"
