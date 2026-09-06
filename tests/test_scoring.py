from src.integrations.scoring import ScoringEngine


class TestScoringEngine:
    def test_canonical_thresholds(self):
        assert ScoringEngine.IGNORE_THRESHOLD == 40.0
        assert ScoringEngine.AUTO_ISOLATE_THRESHOLD == 70.0

    def test_calculate_risk_score_includes_rationale_fields(self):
        intel_data = {"virustotal": {"malicious": 15}, "abuseipdb": {"abuseConfidenceScore": 90}}

        result = ScoringEngine.calculate_risk_score(intel_data, initial_severity=9.0)

        assert result["risk_score"] == 100.0
        assert result["decision"] == "AUTO_ISOLATE"
        assert "mapped to AUTO_ISOLATE" in result["decision_rationale"]
        assert "severity=9.0" in result["summary"]
        assert result["recommended_action"] == "Isolate resource immediately and preserve forensic evidence."

    def test_calculate_risk_score_require_approval(self):
        intel_data = {"virustotal": {"malicious": 5}, "abuseipdb": {"abuseConfidenceScore": 40}}
        # (5*2)+(40*0.5)+(5*3) = 45 → REQUIRE_APPROVAL under 40/70 bands
        result = ScoringEngine.calculate_risk_score(intel_data, initial_severity=5.0)
        assert result["risk_score"] == 45.0
        assert result["decision"] == "REQUIRE_APPROVAL"

    def test_calculate_risk_score_ignore_recommendation(self):
        result = ScoringEngine.calculate_risk_score({}, initial_severity=0.0)

        assert result["decision"] == "IGNORE"
        assert result["recommended_action"] == "Record the event and continue monitoring for escalation."

    def test_calculate_risk_score_ignore_mid_low(self):
        intel_data = {"virustotal": {"malicious": 0}, "abuseipdb": {"abuseConfidenceScore": 10}}
        # 0 + 5 + 6 = 11 → IGNORE
        result = ScoringEngine.calculate_risk_score(intel_data, initial_severity=2.0)
        assert result["risk_score"] == 11.0
        assert result["decision"] == "IGNORE"
