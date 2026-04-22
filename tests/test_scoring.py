from src.integrations.scoring import ScoringEngine


class TestScoringEngine:
    def test_calculate_risk_score_includes_rationale_fields(self):
        intel_data = {"virustotal": {"malicious": 15}, "abuseipdb": {"abuseConfidenceScore": 90}}

        result = ScoringEngine.calculate_risk_score(intel_data, initial_severity=9.0)

        assert result["risk_score"] == 100.0
        assert result["decision"] == "AUTO_ISOLATE"
        assert "mapped to AUTO_ISOLATE" in result["decision_rationale"]
        assert "severity=9.0" in result["summary"]
        assert result["recommended_action"] == "Isolate resource immediately and preserve forensic evidence."

    def test_calculate_risk_score_ignore_recommendation(self):
        result = ScoringEngine.calculate_risk_score({}, initial_severity=0.0)

        assert result["decision"] == "IGNORE"
        assert result["recommended_action"] == "Record the event and continue monitoring for escalation."
