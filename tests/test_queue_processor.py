"""Tests for SQS queue_processor → unified pipeline (no Step Functions)."""

from unittest.mock import MagicMock, patch

from src.queue_processor import _to_pipeline_event, lambda_handler


def test_to_pipeline_event_passthrough_eventbridge():
    event = {"source": "aws.guardduty", "detail": {"id": "finding-1"}}
    assert _to_pipeline_event(event) is event


def test_to_pipeline_event_custom_guardduty_envelope():
    mapped = _to_pipeline_event(
        {
            "event_source": "aws.guardduty",
            "event_id": "e-1",
            "finding": {"type": "CryptoCurrency:EC2/BitcoinTool.B"},
            "account": "123",
            "region": "us-east-1",
            "event_time": "2026-01-01T00:00:00Z",
        }
    )
    assert mapped["source"] == "aws.guardduty"
    assert mapped["detail"]["type"] == "CryptoCurrency:EC2/BitcoinTool.B"
    assert mapped["id"] == "e-1"


@patch("src.queue_processor.handle_event", return_value={"mode": "dry_run", "ok": True})
def test_lambda_handler_routes_to_handle_event(mock_handle):
    sqs_event = {
        "Records": [
            {
                "messageId": "m1",
                "body": '{"source":"aws.guardduty","detail":{"id":"f1"}}',
            }
        ]
    }
    context = MagicMock()
    context.aws_request_id = "req-1"

    result = lambda_handler(sqs_event, context)

    assert result["processed_messages"] == 1
    assert result["failed_messages"] == 0
    assert result["spine"] == "handlers.handle_event"
    mock_handle.assert_called_once()
    assert mock_handle.call_args[0][0]["source"] == "aws.guardduty"
