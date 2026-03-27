import logging
from typing import Any

logger = logging.getLogger(__name__)


class ScoringEngine:
    """Engine to calculate risk scores based on multi-source intelligence."""

    ANOMALY_BOOST = 15.0

    @staticmethod
    def calculate_risk_score(
        intel_data: dict[str, Any],
        initial_severity: float,
        anomaly_score: float = 0.0,
    ) -> dict[str, Any]:
        """
        Calculate a weighted risk score (0-100).
        Formula: (VT_malicious * 2) + (Abuse_score * 0.5) + (Initial_Severity * 3) + Anomaly_boost
        Anomaly_boost = 15 if anomaly_score < -0.5, else 0.
        """
        vt_malicious = intel_data.get("virustotal", {}).get("malicious", 0)
        abuse_score = intel_data.get("abuseipdb", {}).get("abuseConfidenceScore", 0)

        # Anomaly boost: add 15 points if ML flags as anomalous
        anomaly_boost = ScoringEngine.ANOMALY_BOOST if anomaly_score < -0.5 else 0.0

        # Calculate raw score
        raw_score = (vt_malicious * 2) + (abuse_score * 0.5) + (initial_severity * 3) + anomaly_boost

        # Normalize to 100 max (cap it)
        normalized_score = min(float(raw_score), 100.0)

        # Determine decision
        decision = "IGNORE"
        if normalized_score >= 70:
            decision = "AUTO_ISOLATE"
        elif normalized_score >= 40:
            decision = "REQUIRE_APPROVAL"

        return {
            "risk_score": normalized_score,
            "decision": decision,
            "breakdown": {
                "vt_malicious": vt_malicious,
                "abuse_confidence": abuse_score,
                "initial_severity": initial_severity,
                "anomaly_boost": anomaly_boost,
            },
        }
