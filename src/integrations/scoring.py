import logging
from typing import Any

logger = logging.getLogger(__name__)


class ScoringEngine:
    """Engine to calculate risk scores based on multi-source intelligence."""

    ANOMALY_BOOST = 15.0
    IGNORE_THRESHOLD = 40.0
    AUTO_ISOLATE_THRESHOLD = 70.0

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

        decision = ScoringEngine._determine_decision(normalized_score)
        rationale = ScoringEngine._build_rationale(
            normalized_score=normalized_score,
            decision=decision,
            vt_malicious=vt_malicious,
            abuse_score=abuse_score,
            initial_severity=initial_severity,
            anomaly_boost=anomaly_boost,
        )

        return {
            "risk_score": normalized_score,
            "decision": decision,
            "decision_rationale": rationale["decision_rationale"],
            "recommended_action": rationale["recommended_action"],
            "summary": rationale["summary"],
            "breakdown": {
                "vt_malicious": vt_malicious,
                "abuse_confidence": abuse_score,
                "initial_severity": initial_severity,
                "anomaly_boost": anomaly_boost,
            },
        }

    @staticmethod
    def _determine_decision(normalized_score: float) -> str:
        if normalized_score >= ScoringEngine.AUTO_ISOLATE_THRESHOLD:
            return "AUTO_ISOLATE"
        if normalized_score >= ScoringEngine.IGNORE_THRESHOLD:
            return "REQUIRE_APPROVAL"
        return "IGNORE"

    @staticmethod
    def _build_rationale(
        *,
        normalized_score: float,
        decision: str,
        vt_malicious: int,
        abuse_score: int,
        initial_severity: float,
        anomaly_boost: float,
    ) -> dict[str, str]:
        risk_drivers = [
            f"severity={initial_severity}",
            f"vt_malicious={vt_malicious}",
            f"abuse_confidence={abuse_score}",
        ]
        if anomaly_boost:
            risk_drivers.append(f"anomaly_boost={anomaly_boost}")

        if decision == "AUTO_ISOLATE":
            recommended_action = "Isolate resource immediately and preserve forensic evidence."
        elif decision == "REQUIRE_APPROVAL":
            recommended_action = "Escalate for analyst approval before containment."
        else:
            recommended_action = "Record the event and continue monitoring for escalation."

        return {
            "decision_rationale": (
                f"Score {normalized_score:.1f} mapped to {decision} using thresholds "
                f"< {ScoringEngine.IGNORE_THRESHOLD:.0f} = IGNORE, "
                f"{ScoringEngine.IGNORE_THRESHOLD:.0f}-"
                f"{ScoringEngine.AUTO_ISOLATE_THRESHOLD - 0.1:.1f} = REQUIRE_APPROVAL, "
                f">= {ScoringEngine.AUTO_ISOLATE_THRESHOLD:.0f} = AUTO_ISOLATE."
            ),
            "recommended_action": recommended_action,
            "summary": f"Decision {decision} based on {', '.join(risk_drivers)}.",
        }
