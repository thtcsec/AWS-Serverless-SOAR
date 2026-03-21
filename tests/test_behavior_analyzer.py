"""Unit tests for ML Behavior Analyzer."""

import pytest

from src.ml.behavior_analyzer import BehaviorAnalyzer


@pytest.fixture
def analyzer():
    ba = BehaviorAnalyzer()
    # Build a baseline of normal behavior
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


class TestBehaviorAnalyzer:
    def test_normal_activity(self, analyzer):
        result = analyzer.analyze(
            "user-001",
            {
                "action": "DescribeInstances",
                "source_ip": "10.0.0.1",
                "timestamp": "2026-03-20T10:00:00Z",
            },
        )
        assert result["behavior_score"] < 50
        assert result["is_anomalous"] is False

    def test_new_ip_detected(self, analyzer):
        result = analyzer.analyze(
            "user-001",
            {
                "action": "DescribeInstances",
                "source_ip": "203.0.113.66",
                "timestamp": "2026-03-20T10:00:00Z",
            },
        )
        assert "NEW_SOURCE_IP" in result["flags"]
        assert result["behavior_score"] > 20

    def test_unusual_action(self, analyzer):
        result = analyzer.analyze(
            "user-001",
            {
                "action": "DeleteBucket",
                "source_ip": "10.0.0.1",
                "timestamp": "2026-03-20T10:00:00Z",
            },
        )
        assert "UNUSUAL_ACTION_TYPE" in result["flags"]

    def test_off_hours_activity(self, analyzer):
        result = analyzer.analyze(
            "user-001",
            {
                "action": "DescribeInstances",
                "source_ip": "10.0.0.1",
                "timestamp": "2026-03-20T02:00:00Z",
            },
        )
        assert "OFF_HOURS_ACTIVITY" in result["flags"]

    def test_insufficient_baseline(self):
        ba = BehaviorAnalyzer()
        result = ba.analyze("new-user", {"action": "Login"})
        assert "INSUFFICIENT_BASELINE" in result["flags"]

    def test_highly_anomalous_multi_flag(self, analyzer):
        result = analyzer.analyze(
            "user-001",
            {
                "action": "DeleteBucket",
                "source_ip": "203.0.113.99",
                "timestamp": "2026-03-20T03:00:00Z",
            },
        )
        assert result["is_anomalous"] is True
        assert len(result["flags"]) >= 2

    def test_recommendation_field(self, analyzer):
        result = analyzer.analyze(
            "user-001",
            {
                "action": "DescribeInstances",
                "source_ip": "10.0.0.1",
                "timestamp": "2026-03-20T10:00:00Z",
            },
        )
        assert "recommendation" in result

    # ---- Nhóm 5: Additional tests ----

    def test_behavior_rolling_window(self):
        """After 100+ activities, oldest should be dropped (window capped at 100)."""
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
        assert len(ba._baselines["user-rolling"]) == 100

    def test_multi_flag_composite_score(self, analyzer):
        """3 anomaly flags → score > 50 and is_anomalous True."""
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
        """Two different actors maintain independent baselines."""
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

        assert alice_result["behavior_score"] < 50
        assert bob_result["behavior_score"] < 50
        # Alice's baseline doesn't contain Bob's IP
        assert "10.0.0.2" not in {r["source_ip"] for r in ba._baselines.get("alice", [])}
