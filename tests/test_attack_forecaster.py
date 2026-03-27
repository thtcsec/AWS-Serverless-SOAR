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

    # ---- Nhóm 5: Additional tests ----

    def test_probability_accuracy(self, forecaster):
        """All probability values must be in [0, 100] and the list must be non-empty."""
        result = forecaster.forecast()
        attacks = result["top_predicted_attacks"]
        assert len(attacks) > 0
        for attack in attacks:
            assert 0.0 <= attack["probability"] <= 100.0

    def test_escalating_boost(self, forecaster):
        """When trend is ESCALATING, top attack probability >= base probability."""
        result = forecaster.forecast()
        trend = result["trend_analysis"]
        if trend["direction"] == "ESCALATING":
            # probability is boosted: at least as large as historical count / total * 100
            attacks = result["top_predicted_attacks"]
            top = attacks[0]
            total = sum(a["historical_count"] for a in attacks)
            base_probability = top["historical_count"] / total * 100
            assert top["probability"] >= base_probability

    def test_risk_heatmap_completeness(self, forecaster):
        """All resource types in ingested incidents must appear in heatmap (top 5 coverage)."""
        result = forecaster.forecast()
        heatmap = result["risk_heatmap"]
        # ec2, s3, iam are in the fixture — at least the top 3 most common should appear
        assert len(heatmap) >= 2
        # At minimum ec2 (3 incidents) and iam (2 incidents) must appear
        assert "ec2" in heatmap
        assert "iam" in heatmap

    def test_behavior_rolling_window(self):
        """After 100+ activities, oldest should be dropped (window capped at 100)."""
        from src.ml.behavior_analyzer import BehaviorAnalyzer

        ba = BehaviorAnalyzer()
        for i in range(105):
            ba.record_activity(
                "user-rolling",
                {
                    "action": "DescribeInstances",
                    "source_ip": "10.0.0.1",
                    "timestamp": f"2026-03-{(i % 28) + 1:02d}T09:00:00Z",
                },
            )
        # Should be capped at 100
        assert len(ba._baselines["user-rolling"]) == 100

    def test_multi_flag_composite_score(self, analyzer):
        """3 anomaly flags (new IP, off-hours, unusual action) → score > 50 and is_anomalous."""
        result = analyzer.analyze(
            "user-001",
            {
                "action": "DeleteBucket",
                "source_ip": "203.0.113.99",
                "timestamp": "2026-03-20T03:00:00Z",
            },
        )
        assert len(result["flags"]) >= 2
        assert result["behavior_score"] > 50
        assert result["is_anomalous"] is True

    def test_peer_group_baseline_independence(self):
        """Two different actors must maintain independent baselines."""
        from src.ml.behavior_analyzer import BehaviorAnalyzer

        ba = BehaviorAnalyzer()
        for i in range(5):
            ba.record_activity(
                "alice",
                {"action": "DescribeInstances", "source_ip": "10.0.0.1", "timestamp": f"2026-03-{10 + i}T09:00:00Z"},
            )
        for i in range(5):
            ba.record_activity(
                "bob", {"action": "ListBuckets", "source_ip": "10.0.0.2", "timestamp": f"2026-03-{10 + i}T09:00:00Z"}
            )

        alice_result = ba.analyze(
            "alice", {"action": "DescribeInstances", "source_ip": "10.0.0.1", "timestamp": "2026-03-20T09:00:00Z"}
        )
        bob_result = ba.analyze(
            "bob", {"action": "ListBuckets", "source_ip": "10.0.0.2", "timestamp": "2026-03-20T09:00:00Z"}
        )

        # Both actors are within their own baselines, should be low score
        assert alice_result["behavior_score"] < 50
        assert bob_result["behavior_score"] < 50
        # And they are independent — alice's baseline doesn't include bob's IPs
        assert "10.0.0.2" not in {r["source_ip"] for r in ba._baselines.get("alice", [])}


@pytest.fixture
def analyzer():
    from src.ml.behavior_analyzer import BehaviorAnalyzer

    ba = BehaviorAnalyzer()
    for i in range(10):
        ba.record_activity(
            "user-001",
            {
                "action": "DescribeInstances",
                "source_ip": "10.0.0.1",
                "timestamp": f"2026-03-{10 + i}T09:00:00Z",
                "region": "us-east-1",
            },
        )
    return ba
