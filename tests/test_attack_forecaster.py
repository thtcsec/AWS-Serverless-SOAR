"""Unit tests for ML Attack Forecaster."""

import pytest

from src.ml.attack_forecaster import AttackForecaster


@pytest.fixture
def forecaster():
    af = AttackForecaster()
    af.ingest(
        [
            {
                "action": "CryptoMining",
                "severity": "HIGH",
                "resource_type": "ec2",
                "source_ip": "1.2.3.4",
                "timestamp": "2026-03-01T10:00:00Z",
            },
            {
                "action": "CryptoMining",
                "severity": "CRITICAL",
                "resource_type": "ec2",
                "source_ip": "1.2.3.5",
                "timestamp": "2026-03-02T10:00:00Z",
            },
            {
                "action": "DataExfiltration",
                "severity": "HIGH",
                "resource_type": "s3",
                "source_ip": "5.6.7.8",
                "timestamp": "2026-03-03T10:00:00Z",
            },
            {
                "action": "BruteForce",
                "severity": "MEDIUM",
                "resource_type": "iam",
                "source_ip": "9.10.11.12",
                "timestamp": "2026-03-04T10:00:00Z",
            },
            {
                "action": "CryptoMining",
                "severity": "HIGH",
                "resource_type": "ec2",
                "source_ip": "1.2.3.6",
                "timestamp": "2026-03-05T10:00:00Z",
            },
            {
                "action": "PrivilegeEscalation",
                "severity": "CRITICAL",
                "resource_type": "iam",
                "source_ip": "13.14.15.16",
                "timestamp": "2026-03-06T10:00:00Z",
            },
        ]
    )
    return af


class TestAttackForecaster:
    def test_forecast_with_data(self, forecaster):
        result = forecaster.forecast()
        assert result["status"] == "FORECAST_READY"
        assert len(result["top_predicted_attacks"]) > 0

    def test_forecast_insufficient_data(self):
        af = AttackForecaster()
        af.ingest([{"action": "test", "severity": "LOW"}])
        result = af.forecast()
        assert result["status"] == "INSUFFICIENT_DATA"

    def test_top_attack_is_crypto(self, forecaster):
        result = forecaster.forecast()
        top = result["top_predicted_attacks"][0]
        assert top["attack_type"] == "cryptomining"
        assert top["historical_count"] == 3

    def test_risk_heatmap(self, forecaster):
        result = forecaster.forecast()
        heatmap = result["risk_heatmap"]
        assert "ec2" in heatmap
        assert heatmap["ec2"]["incident_count"] == 3

    def test_trend_analysis(self, forecaster):
        result = forecaster.forecast()
        trend = result["trend_analysis"]
        assert trend["direction"] in ("ESCALATING", "STABLE", "DECREASING")
        assert "avg_severity" in trend

    def test_proactive_recommendations(self, forecaster):
        result = forecaster.forecast()
        recs = result["proactive_recommendations"]
        assert len(recs) > 0

    def test_ingest_returns_count(self):
        af = AttackForecaster()
        count = af.ingest([{"action": "a"}, {"action": "b"}])
        assert count == 2
        count = af.ingest([{"action": "c"}])
        assert count == 3
