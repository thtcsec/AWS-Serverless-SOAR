"""Unit tests for ML Threat Classifier."""

import pytest
from src.ml.threat_classifier import ThreatClassifier


@pytest.fixture
def classifier():
    return ThreatClassifier()


@pytest.fixture
def crypto_incident():
    return {
        "action": "CryptoCurrency:EC2/BitcoinTool.B",
        "severity": "HIGH",
        "source_ip": "198.51.100.10",
        "risk_score": 75.0,
        "anomaly_score": -0.8,
        "timestamp": "2026-03-11T02:30:00Z",
        "intel_summary": {
            "virustotal": {"malicious": 8},
            "abuseipdb": {"abuseConfidenceScore": 90},
        },
    }


@pytest.fixture
def recon_incident():
    return {
        "action": "DescribeInstances",
        "severity": "LOW",
        "source_ip": "10.0.0.1",
        "risk_score": 15.0,
        "anomaly_score": 0.5,
        "timestamp": "2026-03-11T10:00:00Z",
        "intel_summary": {},
    }


class TestThreatClassifier:
    def test_classify_crypto_mining(self, classifier, crypto_incident):
        result = classifier.predict_threat_severity(crypto_incident)
        assert result["threat_type"] == "crypto_mining"
        assert result["predicted_severity"] in ("CRITICAL", "HIGH")
        assert result["confidence"] > 0.5
        assert "T1496" in result["mitre_ttps"]

    def test_classify_recon(self, classifier, recon_incident):
        result = classifier.predict_threat_severity(recon_incident)
        assert result["threat_type"] == "reconnaissance"
        assert result["predicted_score"] < 60

    def test_classify_unknown_action(self, classifier):
        result = classifier.predict_threat_severity({
            "action": "some_random_action",
            "severity": "MEDIUM",
        })
        assert result["threat_type"] == "unknown"

    def test_recommend_response_auto_isolate(self, classifier, crypto_incident):
        classification = classifier.predict_threat_severity(crypto_incident)
        response = classifier.recommend_response(classification)
        assert response["recommended_action"] in ("AUTO_ISOLATE", "REQUIRE_APPROVAL")
        assert "playbook" in response
        assert len(response["playbook"]) > 0

    def test_recommend_response_monitor(self, classifier, recon_incident):
        classification = classifier.predict_threat_severity(recon_incident)
        response = classifier.recommend_response(classification)
        assert response["recommended_action"] in ("MONITOR", "REQUIRE_APPROVAL")

    def test_temporal_analysis_off_hours(self, classifier):
        result = classifier.predict_threat_severity({
            "action": "bitcoin_mining",
            "severity": "HIGH",
            "timestamp": "2026-03-11T03:00:00Z",
            "risk_score": 60,
            "anomaly_score": -0.6,
        })
        assert result["feature_weights"]["temporal_risk"] >= 0.4

    def test_confidence_with_full_evidence(self, classifier, crypto_incident):
        result = classifier.predict_threat_severity(crypto_incident)
        assert result["confidence"] >= 0.75

    def test_confidence_with_no_evidence(self, classifier):
        result = classifier.predict_threat_severity({"action": "unknown"})
        assert result["confidence"] <= 0.5

    def test_empty_incident(self, classifier):
        result = classifier.predict_threat_severity({})
        assert "predicted_severity" in result
        assert "threat_type" in result
