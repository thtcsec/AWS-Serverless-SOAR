"""Tests for AWS Anomaly Detector."""
import pytest
from src.integrations.anomaly_detector import AnomalyDetector


class TestAnomalyDetector:
    @pytest.fixture
    def detector(self):
        return AnomalyDetector()

    @pytest.fixture
    def normal_data(self):
        """Generate 20 normal data points."""
        return [
            {
                "hour_of_day": 14.0,
                "day_of_week": 2.0,
                "ip_reputation_score": 5.0,
                "action_risk_level": 2.0,
                "request_frequency": 10.0,
            }
            for _ in range(20)
        ]

    def test_predict_without_training(self, detector):
        features = {
            "hour_of_day": 3.0,
            "day_of_week": 6.0,
            "ip_reputation_score": 90.0,
            "action_risk_level": 9.0,
            "request_frequency": 100.0,
        }
        score = detector.predict(features)
        assert isinstance(score, float)

    def test_is_anomalous_threshold(self, detector):
        assert detector.is_anomalous(-0.8) is True
        assert detector.is_anomalous(-0.5) is False
        assert detector.is_anomalous(0.5) is False

    def test_train_with_insufficient_data(self, detector):
        result = detector.train([{"hour_of_day": 1.0}])
        assert result is False

    def test_zscore_fallback_normal(self, detector, normal_data):
        # Load history manually (simulate fallback)
        detector._history = [detector._extract_features(d) for d in normal_data]

        normal_features = {
            "hour_of_day": 14.0,
            "day_of_week": 2.0,
            "ip_reputation_score": 5.0,
            "action_risk_level": 2.0,
            "request_frequency": 10.0,
        }
        score = detector.predict(normal_features)
        assert score >= 0.0  # Normal events should have positive score

    def test_zscore_fallback_anomalous(self, detector, normal_data):
        detector._history = [detector._extract_features(d) for d in normal_data]

        anomalous_features = {
            "hour_of_day": 3.0,
            "day_of_week": 6.0,
            "ip_reputation_score": 95.0,
            "action_risk_level": 10.0,
            "request_frequency": 500.0,
        }
        score = detector.predict(anomalous_features)
        assert score <= 0.0  # Anomalous events should have negative score

    def test_extract_features_order(self, detector):
        data = {
            "hour_of_day": 1.0,
            "day_of_week": 2.0,
            "ip_reputation_score": 3.0,
            "action_risk_level": 4.0,
            "request_frequency": 5.0,
        }
        features = detector._extract_features(data)
        assert features == [1.0, 2.0, 3.0, 4.0, 5.0]

    def test_extract_features_missing_keys(self, detector):
        features = detector._extract_features({})
        assert features == [0.0, 0.0, 0.0, 0.0, 0.0]
