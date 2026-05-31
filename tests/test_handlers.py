"""Tests for Lambda handler and unified incident pipeline."""

from unittest.mock import patch

from src.handlers import handle_event, lambda_handler
from tests.conftest import make_guardduty_event


class TestHandleEvent:
    @patch("src.handlers.pipeline")
    def test_successful_dispatch(self, mock_pipeline):
        mock_pipeline.process.return_value = {"statusCode": 200, "body": {"status": "executed"}}

        event = make_guardduty_event()
        result = handle_event(event)
        assert result["statusCode"] == 200
        assert result["body"]["status"] == "executed"
        mock_pipeline.process.assert_called_once_with(event)

    @patch("src.handlers.pipeline")
    def test_no_matching_playbook(self, mock_pipeline):
        mock_pipeline.process.return_value = {"statusCode": 200, "body": {"status": "no_playbook"}}

        result = handle_event({"source": "unknown"})
        assert result["statusCode"] == 200
        assert result["body"]["status"] == "no_playbook"

    @patch("src.handlers.pipeline")
    def test_dry_run_preview_response(self, mock_pipeline):
        mock_pipeline.process.return_value = {
            "statusCode": 200,
            "body": {
                "mode": "dry_run",
                "playbook": "EC2Containment",
                "planned_actions": [],
            },
        }

        result = handle_event({"dry_run": True})
        assert result["statusCode"] == 200
        assert result["body"]["mode"] == "dry_run"
        assert result["body"]["playbook"] == "EC2Containment"

    @patch("src.handlers.pipeline")
    def test_lambda_handler_delegates_to_pipeline(self, mock_pipeline):
        mock_pipeline.process.return_value = {"statusCode": 200, "body": {"status": "executed"}}

        event = make_guardduty_event()
        result = lambda_handler(event, None)
        assert result["statusCode"] == 200
        mock_pipeline.process.assert_called_once_with(event)

    @patch("src.handlers.pipeline")
    def test_critical_failure(self, mock_pipeline):
        mock_pipeline.process.side_effect = Exception("Boom")

        result = lambda_handler(make_guardduty_event(), None)
        assert result["statusCode"] == 500
        assert result["body"] == "Internal Server Error"


class TestImports:
    def test_import_handlers(self):
        import src.handlers

        assert hasattr(src.handlers, "handle_event")
        assert hasattr(src.handlers, "lambda_handler")
        assert hasattr(src.handlers, "pipeline")

    def test_import_models(self):
        from src.models.events import GuardDutyEvent

        assert GuardDutyEvent is not None

    def test_import_config(self):
        from src.core.config import config

        assert config is not None

    def test_import_metrics(self):
        from src.core.metrics import emit_metric

        assert callable(emit_metric)

    def test_import_playbooks(self):
        from src.playbooks.ec2_containment import EC2ContainmentPlaybook

        assert EC2ContainmentPlaybook is not None

    def test_import_registry(self):
        from src.playbooks.registry import registry

        assert registry is not None

    def test_import_clients(self):
        from src.clients.aws import AWSClientFacade

        assert AWSClientFacade is not None
