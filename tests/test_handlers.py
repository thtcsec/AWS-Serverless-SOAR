"""Tests for Lambda handler and event routing."""
import pytest
from unittest.mock import patch, MagicMock
from tests.conftest import make_guardduty_event, make_s3_cloudtrail_event


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
        assert hasattr(src.handlers, 'lambda_handler')

    def test_import_models(self):
        from src.models.events import GuardDutyEvent, S3CloudTrailEvent, IAMCloudTrailEvent
        assert GuardDutyEvent is not None

    def test_import_config(self):
        from src.core.config import SOARConfig, config
        assert config is not None

    def test_import_metrics(self):
        from src.core.metrics import emit_metric, PlaybookTimer
        assert callable(emit_metric)

    def test_import_playbooks(self):
        from src.playbooks.ec2_containment import EC2ContainmentPlaybook
        from src.playbooks.s3_exfiltration import S3ExfiltrationPlaybook
        from src.playbooks.iam_compromise import IAMCompromisePlaybook
        assert EC2ContainmentPlaybook is not None

    def test_import_registry(self):
        from src.playbooks.registry import PlaybookRegistry, registry
        assert registry is not None

    def test_import_clients(self):
        from src.clients.aws import AWSClientFacade
        assert AWSClientFacade is not None
