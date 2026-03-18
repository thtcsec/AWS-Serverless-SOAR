"""Tests for Lambda handler and event routing."""

from unittest.mock import patch

from tests.conftest import make_guardduty_event


class TestLambdaHandler:
    @patch("src.handlers.registry")
    def test_successful_dispatch(self, mock_registry):
        from src.handlers import lambda_handler

        mock_registry.dispatch.return_value = True

        result = lambda_handler(make_guardduty_event(), None)
        assert result["statusCode"] == 200
        assert result["body"] == "Remediation Successful"
        mock_registry.dispatch.assert_called_once()

    @patch("src.handlers.registry")
    def test_no_matching_playbook(self, mock_registry):
        from src.handlers import lambda_handler

        mock_registry.dispatch.return_value = False

        result = lambda_handler({"source": "unknown"}, None)
        assert result["statusCode"] == 200
        assert result["body"] == "Event Ignored"

    @patch("src.handlers.registry")
    def test_critical_failure(self, mock_registry):
        from src.handlers import lambda_handler

        mock_registry.dispatch.side_effect = Exception("Boom")

        result = lambda_handler(make_guardduty_event(), None)
        assert result["statusCode"] == 500
        assert result["body"] == "Internal Server Error"


class TestImports:
    def test_import_handlers(self):
        import src.handlers

        assert hasattr(src.handlers, "lambda_handler")

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
