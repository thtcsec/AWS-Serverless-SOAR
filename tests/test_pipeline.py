"""Tests for the unified incident pipeline."""

from unittest.mock import MagicMock, patch

from src.core.pipeline import IncidentPipeline
from src.core.policy import PolicyEngine
from src.handlers import registry
from tests.conftest import make_guardduty_event, make_iam_cloudtrail_event


class TestIncidentPipeline:
    @patch("src.core.pipeline.SlackNotifier")
    def test_pipeline_ignore_decision_skips_playbook(self, _mock_slack):
        pipeline = IncidentPipeline(registry=registry, policy=PolicyEngine())
        event = make_guardduty_event()
        event["detail"]["severity"] = 0.5

        with patch.object(registry, "dispatch") as mock_dispatch:
            result = pipeline.process(event)

        assert result["statusCode"] == 200
        assert result["body"]["decision"] == "IGNORE"
        mock_dispatch.assert_not_called()

    @patch("src.core.pipeline.SlackNotifier")
    def test_pipeline_auto_isolate_dispatches_playbook(self, _mock_slack):
        pipeline = IncidentPipeline(registry=registry, policy=PolicyEngine())
        event = make_guardduty_event()

        def _auto_isolate(incident):
            incident.risk_score = 95.0
            incident.decision = "AUTO_ISOLATE"
            return {
                "risk_score": 95.0,
                "decision": "AUTO_ISOLATE",
                "summary": "test",
                "decision_rationale": "test",
                "recommended_action": "isolate",
                "breakdown": {},
            }

        with (
            patch.object(PolicyEngine, "evaluate", side_effect=_auto_isolate),
            patch.object(registry, "dispatch", return_value=True) as mock_dispatch,
        ):
            result = pipeline.process(event)

        assert result["statusCode"] == 200
        mock_dispatch.assert_called_once()

    @patch("src.core.pipeline.SlackNotifier")
    def test_pipeline_s3_evaluate_dispatches_playbook(self, _mock_slack):
        from tests.conftest import make_s3_cloudtrail_event

        pipeline = IncidentPipeline(registry=registry, policy=PolicyEngine())
        event = make_s3_cloudtrail_event()

        with patch.object(registry, "dispatch", return_value=True) as mock_dispatch:
            result = pipeline.process(event)

        assert result["statusCode"] == 200
        mock_dispatch.assert_called_once()

    def test_pipeline_unknown_event_returns_422(self):
        pipeline = IncidentPipeline(registry=registry)
        result = pipeline.process({"unexpected": True})
        assert result["statusCode"] == 422

    @patch("src.core.pipeline.SlackNotifier")
    def test_pipeline_iam_require_approval(self, mock_slack):
        pipeline = IncidentPipeline(registry=registry, policy=PolicyEngine())
        event = make_iam_cloudtrail_event()

        def _require_approval(incident):
            incident.decision = "REQUIRE_APPROVAL"
            incident.risk_score = 55.0
            return {
                "decision": "REQUIRE_APPROVAL",
                "risk_score": 55.0,
                "summary": "approval needed",
            }

        with (
            patch.object(registry, "dispatch") as mock_dispatch,
            patch.object(PolicyEngine, "evaluate", side_effect=_require_approval),
        ):
            result = pipeline.process(event)

        assert result["statusCode"] == 200
        assert result["body"]["status"] == "pending_approval"
        mock_dispatch.assert_not_called()

    @patch("src.core.pipeline.emit_metric")
    @patch("src.core.pipeline.SlackNotifier")
    def test_pipeline_enriches_response_with_mitre_ttps(self, _mock_slack, _mock_metric):
        classifier = MagicMock()
        classifier.predict_threat_severity.return_value = {
            "threat_type": "crypto_mining",
            "mitre_ttps": ["T1496"],
            "confidence": 0.9,
            "predicted_severity": "HIGH",
        }
        pipeline = IncidentPipeline(registry=registry, policy=PolicyEngine(), threat_classifier=classifier)
        event = make_guardduty_event()
        event["detail"]["severity"] = 0.5

        result = pipeline.process(event)

        assert result["statusCode"] == 200
        assert result["body"]["mitre_ttps"] == ["T1496"]
        assert result["body"]["threat_type"] == "crypto_mining"

    @patch("src.core.pipeline.emit_metric")
    @patch("src.core.pipeline.SlackNotifier")
    def test_pipeline_archives_audit_when_bucket_set(self, _mock_slack, _mock_metric, monkeypatch):
        audit = MagicMock()
        audit.log = MagicMock()
        audit.export_to_s3 = MagicMock(return_value=True)
        pipeline = IncidentPipeline(registry=registry, policy=PolicyEngine(), audit=audit)
        monkeypatch.setenv("AUDIT_BUCKET", "soar-audit-lab")

        event = make_guardduty_event()
        event["detail"]["severity"] = 0.5
        result = pipeline.process(event)

        assert result["statusCode"] == 200
        audit.export_to_s3.assert_called_with("soar-audit-lab")
