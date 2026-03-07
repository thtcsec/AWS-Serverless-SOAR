"""Tests for core modules: config, metrics, logger, registry."""
import os
import pytest
from unittest.mock import patch, MagicMock


class TestSOARConfig:
    def test_default_values(self):
        from src.core.config import SOARConfig
        cfg = SOARConfig()
        assert cfg.log_level == "INFO"
        assert cfg.exfiltration_threshold == 10737418240
        assert cfg.sns_topic_arn == ""
        assert cfg.evidence_bucket == ""
        assert cfg.metrics_namespace == "SOAR/IncidentResponse"

    def test_env_override(self):
        from src.core.config import SOARConfig
        with patch.dict(os.environ, {
            "LOG_LEVEL": "DEBUG",
            "SNS_TOPIC_ARN": "arn:aws:sns:us-east-1:123:topic",
            "EVIDENCE_BUCKET": "my-evidence-bucket",
        }):
            cfg = SOARConfig()
            assert cfg.log_level == "DEBUG"
            assert cfg.sns_topic_arn == "arn:aws:sns:us-east-1:123:topic"
            assert cfg.evidence_bucket == "my-evidence-bucket"


class TestLogger:
    def test_logger_creation(self):
        from src.core.logger import logger
        assert logger is not None
        assert logger.name is not None


class TestMetrics:
    @patch("src.core.metrics.AWSClientFacade")
    def test_emit_metric(self, mock_facade):
        from src.core.metrics import emit_metric
        mock_cw = MagicMock()
        mock_facade.cloudwatch.return_value = mock_cw

        emit_metric("TestMetric", 1.0, "Count", {"Playbook": "Test"})
        mock_cw.put_metric_data.assert_called_once()
        call_kwargs = mock_cw.put_metric_data.call_args
        assert call_kwargs[1]["Namespace"] == "SOAR/IncidentResponse"

    @patch("src.core.metrics.AWSClientFacade")
    def test_emit_metric_failure_logged(self, mock_facade):
        from src.core.metrics import emit_metric
        mock_cw = MagicMock()
        mock_cw.put_metric_data.side_effect = Exception("CloudWatch error")
        mock_facade.cloudwatch.return_value = mock_cw

        # Should not raise — logs warning instead
        emit_metric("FailMetric", 1.0)

    @patch("src.core.metrics.emit_metric")
    def test_playbook_timer_success(self, mock_emit):
        from src.core.metrics import PlaybookTimer
        with PlaybookTimer("TestPlaybook"):
            pass  # simulate work
        # Should emit duration + success
        assert mock_emit.call_count == 2
        calls = [c[0][0] for c in mock_emit.call_args_list]
        assert "PlaybookDuration" in calls
        assert "PlaybookSuccess" in calls

    @patch("src.core.metrics.emit_metric")
    def test_playbook_timer_failure(self, mock_emit):
        from src.core.metrics import PlaybookTimer
        try:
            with PlaybookTimer("FailPlaybook"):
                raise ValueError("simulated failure")
        except ValueError:
            pass
        calls = [c[0][0] for c in mock_emit.call_args_list]
        assert "PlaybookDuration" in calls
        assert "PlaybookFailure" in calls


class TestPlaybookRegistry:
    def test_register_and_dispatch(self):
        from src.playbooks.registry import PlaybookRegistry

        class MockPlaybook:
            def can_handle(self, event_data):
                return event_data.get("source") == "test"

            def execute(self, event_data):
                return True

        reg = PlaybookRegistry()
        reg.register(MockPlaybook())
        assert reg.dispatch({"source": "test"}) is True

    def test_no_matching_playbook(self):
        from src.playbooks.registry import PlaybookRegistry
        reg = PlaybookRegistry()
        assert reg.dispatch({"source": "unknown"}) is False

    def test_dispatch_order(self):
        from src.playbooks.registry import PlaybookRegistry

        class FirstPlaybook:
            def can_handle(self, event_data):
                return True

            def execute(self, event_data):
                return "first"

        class SecondPlaybook:
            def can_handle(self, event_data):
                return True

            def execute(self, event_data):
                return "second"

        reg = PlaybookRegistry()
        reg.register(FirstPlaybook())
        reg.register(SecondPlaybook())
        # First registered playbook wins
        assert reg.dispatch({}) == "first"
