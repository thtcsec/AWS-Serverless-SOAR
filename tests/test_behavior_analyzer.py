"""Unit tests for ML Behavior Analyzer."""

import pytest
from src.ml.behavior_analyzer import BehaviorAnalyzer


@pytest.fixture
def analyzer():
    ba = BehaviorAnalyzer()
    # Build a baseline of normal behavior
    for i in range(10):
        ba.record_activity("user-001", {
            "action": "DescribeInstances",
            "source_ip": "10.0.0.1",
            "timestamp": f"2026-03-{10+i}T09:00:00Z",
            "region": "us-east-1",
        })
    return ba


class TestBehaviorAnalyzer:
    def test_normal_activity(self, analyzer):
        result = analyzer.analyze("user-001", {
            "action": "DescribeInstances",
            "source_ip": "10.0.0.1",
            "timestamp": "2026-03-20T10:00:00Z",
        })
        assert result["behavior_score"] < 50
        assert result["is_anomalous"] is False

    def test_new_ip_detected(self, analyzer):
        result = analyzer.analyze("user-001", {
            "action": "DescribeInstances",
            "source_ip": "203.0.113.66",
            "timestamp": "2026-03-20T10:00:00Z",
        })
        assert "NEW_SOURCE_IP" in result["flags"]
        assert result["behavior_score"] > 20

    def test_unusual_action(self, analyzer):
        result = analyzer.analyze("user-001", {
            "action": "DeleteBucket",
            "source_ip": "10.0.0.1",
            "timestamp": "2026-03-20T10:00:00Z",
        })
        assert "UNUSUAL_ACTION_TYPE" in result["flags"]

    def test_off_hours_activity(self, analyzer):
        result = analyzer.analyze("user-001", {
            "action": "DescribeInstances",
            "source_ip": "10.0.0.1",
            "timestamp": "2026-03-20T02:00:00Z",
        })
        assert "OFF_HOURS_ACTIVITY" in result["flags"]

    def test_insufficient_baseline(self):
        ba = BehaviorAnalyzer()
        result = ba.analyze("new-user", {"action": "Login"})
        assert "INSUFFICIENT_BASELINE" in result["flags"]

    def test_highly_anomalous_multi_flag(self, analyzer):
        result = analyzer.analyze("user-001", {
            "action": "DeleteBucket",
            "source_ip": "203.0.113.99",
            "timestamp": "2026-03-20T03:00:00Z",
        })
        assert result["is_anomalous"] is True
        assert len(result["flags"]) >= 2

    def test_recommendation_field(self, analyzer):
        result = analyzer.analyze("user-001", {
            "action": "DescribeInstances",
            "source_ip": "10.0.0.1",
            "timestamp": "2026-03-20T10:00:00Z",
        })
        assert "recommendation" in result
