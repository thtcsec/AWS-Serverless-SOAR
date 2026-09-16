"""Tests for PolicyEngine anomaly wiring."""

from unittest.mock import MagicMock

from src.core.event_normalizer import UnifiedIncident
from src.core.policy import PolicyEngine
from src.integrations.scoring import ScoringEngine


class TestPolicyAnomalyWiring:
    def test_anomaly_boost_applied_to_risk_score(self):
        anomaly = MagicMock()
        anomaly.predict.return_value = -0.8
        anomaly._history = []
        anomaly._extract_features.side_effect = lambda d: [0.0] * 5

        intel = MagicMock()
        intel.get_ip_report.return_value = {}

        policy = PolicyEngine(
            intel_service=intel,
            scoring_engine=ScoringEngine(),
            anomaly_detector=anomaly,
        )
        incident = UnifiedIncident(
            incident_id="t1",
            raw_event_type="GuardDutyFinding",
            severity="HIGH",
            source_ip="1.2.3.4",
            raw_event={"detail": {"severity": 8.0}},
        )

        result = policy.evaluate(incident)

        assert result["anomaly_score"] == -0.8
        assert result["breakdown"]["anomaly_boost"] == 15.0
        assert incident.anomaly_score == -0.8
        # severity 10 * 3 + 15 = 45 → REQUIRE_APPROVAL
        assert result["risk_score"] == 45.0
        assert result["decision"] == "REQUIRE_APPROVAL"

    def test_heuristic_cold_start_for_critical_severity(self):
        features = {
            "hour_of_day": 12.0,
            "day_of_week": 1.0,
            "ip_reputation_score": 0.0,
            "action_risk_level": 10.0,
            "request_frequency": 1.0,
        }
        assert PolicyEngine._heuristic_anomaly(features) == -0.55

    def test_s3_evaluate_skips_anomaly_scoring(self):
        policy = PolicyEngine()
        incident = UnifiedIncident(incident_id="s3", raw_event_type="S3CloudTrailEvent")
        result = policy.evaluate(incident)
        assert result["decision"] == "EVALUATE"
        assert result["anomaly_score"] == 0.0
