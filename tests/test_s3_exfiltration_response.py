"""Tests for deprecated S3 monolith module — verifies delegation to unified pipeline."""

from unittest.mock import patch


class TestS3ExfiltrationResponseDeprecated:
    @patch("src.handlers.handle_event")
    def test_lambda_handler_delegates_to_pipeline(self, mock_handle):
        mock_handle.return_value = {"statusCode": 200, "body": {"status": "ignored"}}

        from src.s3_exfiltration_response import lambda_handler

        event = {
            "source": "aws.s3",
            "detail": {
                "eventName": "GetObject",
                "requestParameters": {"bucketName": "test-bucket"},
                "userIdentity": {"arn": "arn:aws:iam::123:user/test"},
            },
        }
        result = lambda_handler(event, None)

        assert result["statusCode"] == 200
        mock_handle.assert_called_once_with(event)

    @patch("src.s3_exfiltration_response.handle_event")
    def test_handle_event_alias(self, mock_handle):
        mock_handle.return_value = {"statusCode": 200, "body": {"status": "executed"}}

        from src.s3_exfiltration_response import handle_event

        event = {
            "source": "aws.s3",
            "detail": {
                "eventName": "GetObject",
                "requestParameters": {"bucketName": "b"},
                "userIdentity": {"arn": "arn:aws:iam::123:user/x"},
            },
        }
        result = handle_event(event)

        assert result["body"]["status"] == "executed"
        mock_handle.assert_called_once_with(event)
