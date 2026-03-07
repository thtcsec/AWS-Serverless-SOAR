"""Tests for S3 Exfiltration playbook."""
import pytest
from unittest.mock import patch, MagicMock
from tests.conftest import make_s3_cloudtrail_event


class TestS3ExfiltrationCanHandle:
    def test_handles_get_object(self):
        from src.playbooks.s3_exfiltration import S3ExfiltrationPlaybook
        with patch.object(S3ExfiltrationPlaybook, '__init__', lambda self: None):
            pb = S3ExfiltrationPlaybook()
            assert pb.can_handle(make_s3_cloudtrail_event("GetObject")) is True

    def test_handles_list_objects(self):
        from src.playbooks.s3_exfiltration import S3ExfiltrationPlaybook
        with patch.object(S3ExfiltrationPlaybook, '__init__', lambda self: None):
            pb = S3ExfiltrationPlaybook()
            assert pb.can_handle(make_s3_cloudtrail_event("ListObjects")) is True

    def test_handles_download_file(self):
        from src.playbooks.s3_exfiltration import S3ExfiltrationPlaybook
        with patch.object(S3ExfiltrationPlaybook, '__init__', lambda self: None):
            pb = S3ExfiltrationPlaybook()
            assert pb.can_handle(make_s3_cloudtrail_event("DownloadFile")) is True

    def test_rejects_put_object(self):
        from src.playbooks.s3_exfiltration import S3ExfiltrationPlaybook
        with patch.object(S3ExfiltrationPlaybook, '__init__', lambda self: None):
            pb = S3ExfiltrationPlaybook()
            assert pb.can_handle(make_s3_cloudtrail_event("PutObject")) is False

    def test_rejects_invalid_event(self):
        from src.playbooks.s3_exfiltration import S3ExfiltrationPlaybook
        with patch.object(S3ExfiltrationPlaybook, '__init__', lambda self: None):
            pb = S3ExfiltrationPlaybook()
            assert pb.can_handle({"source": "aws.ec2", "detail": {}}) is False

    def test_rejects_malformed_event(self):
        from src.playbooks.s3_exfiltration import S3ExfiltrationPlaybook
        with patch.object(S3ExfiltrationPlaybook, '__init__', lambda self: None):
            pb = S3ExfiltrationPlaybook()
            assert pb.can_handle({"garbage": True}) is False


class TestS3ExfiltrationExecute:
    @patch("src.playbooks.s3_exfiltration.emit_metric")
    @patch("src.playbooks.s3_exfiltration.PlaybookTimer")
    def test_execute_blocks_user_and_enables_protection(self, mock_timer, mock_emit):
        mock_timer.return_value.__enter__ = MagicMock()
        mock_timer.return_value.__exit__ = MagicMock(return_value=False)

        from src.playbooks.s3_exfiltration import S3ExfiltrationPlaybook
        pb = S3ExfiltrationPlaybook.__new__(S3ExfiltrationPlaybook)
        pb.s3 = MagicMock()
        pb.s3.get_bucket_policy.return_value = {
            'Policy': '{"Version": "2012-10-17", "Statement": []}'
        }

        event = make_s3_cloudtrail_event("GetObject", "target-bucket",
                                          "arn:aws:iam::123456789012:user/attacker")
        result = pb.execute(event)

        assert result is True
        pb.s3.put_bucket_policy.assert_called_once()
        pb.s3.put_bucket_versioning.assert_called_once()

    @patch("src.playbooks.s3_exfiltration.emit_metric")
    @patch("src.playbooks.s3_exfiltration.PlaybookTimer")
    def test_execute_returns_false_missing_bucket(self, mock_timer, mock_emit):
        mock_timer.return_value.__enter__ = MagicMock()
        mock_timer.return_value.__exit__ = MagicMock(return_value=False)

        from src.playbooks.s3_exfiltration import S3ExfiltrationPlaybook
        pb = S3ExfiltrationPlaybook.__new__(S3ExfiltrationPlaybook)
        pb.s3 = MagicMock()

        event = {
            "source": "aws.s3",
            "detail": {
                "eventName": "GetObject",
                "requestParameters": None,
                "userIdentity": {"arn": "arn:aws:iam::123:user/x"},
            }
        }
        result = pb.execute(event)
        assert result is False

    @patch("src.playbooks.s3_exfiltration.emit_metric")
    @patch("src.playbooks.s3_exfiltration.PlaybookTimer")
    def test_execute_returns_false_missing_user_arn(self, mock_timer, mock_emit):
        mock_timer.return_value.__enter__ = MagicMock()
        mock_timer.return_value.__exit__ = MagicMock(return_value=False)

        from src.playbooks.s3_exfiltration import S3ExfiltrationPlaybook
        pb = S3ExfiltrationPlaybook.__new__(S3ExfiltrationPlaybook)
        pb.s3 = MagicMock()

        event = {
            "source": "aws.s3",
            "detail": {
                "eventName": "GetObject",
                "requestParameters": {"bucketName": "bucket"},
                "userIdentity": {},
            }
        }
        result = pb.execute(event)
        assert result is False
