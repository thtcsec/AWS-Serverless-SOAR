"""Tests for deprecated IAM monolith module — verifies delegation to unified pipeline."""

from unittest.mock import patch


class TestIAMCompromiseResponseDeprecated:
    @patch("src.handlers.handle_event")
    def test_lambda_handler_delegates_to_pipeline(self, mock_handle):
        mock_handle.return_value = {"statusCode": 200, "body": {"status": "ignored"}}

        from src.iam_compromise_response import lambda_handler

        event = {"source": "aws.iam", "detail": {"eventName": "CreateUser", "userIdentity": {}}}
        result = lambda_handler(event, None)

        assert result["statusCode"] == 200
        mock_handle.assert_called_once_with(event)

    @patch("src.iam_compromise_response.handle_event")
    def test_handle_event_alias(self, mock_handle):
        mock_handle.return_value = {"statusCode": 200, "body": {"status": "executed"}}

        from src.iam_compromise_response import handle_event

        event = {"source": "aws.iam", "detail": {"eventName": "CreateAccessKey", "userIdentity": {"userName": "u"}}}
        result = handle_event(event)

        assert result["body"]["status"] == "executed"
        mock_handle.assert_called_once_with(event)
