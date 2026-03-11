"""
AWS SOAR — ML Threat Classifier
Advanced ML-driven threat classification with severity prediction
and automated response recommendations based on incident patterns.
"""

import logging
import math
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("aws-soar.ml.classifier")

# Known attack pattern signatures for pattern matching
ATTACK_SIGNATURES: Dict[str, Dict[str, Any]] = {
    "crypto_mining": {
        "keywords": ["bitcoin", "crypto", "mining", "xmr", "monero", "coinhive"],
        "severity_weight": 0.9,
        "response": "AUTO_ISOLATE",
        "ttps": ["T1496"],
    },
    "credential_theft": {
        "keywords": ["getpasswordata", "credential", "bruteforce", "password", "login"],
        "severity_weight": 0.85,
        "response": "AUTO_ISOLATE",
        "ttps": ["T1110", "T1555"],
    },
    "data_exfiltration": {
        "keywords": ["exfil", "upload", "putobject", "s3:put", "transfer", "copy"],
        "severity_weight": 0.95,
        "response": "AUTO_ISOLATE",
        "ttps": ["T1041", "T1567"],
    },
    "privilege_escalation": {
        "keywords": ["attachpolicy", "createrole", "admin", "escalat", "assume"],
        "severity_weight": 0.8,
        "response": "REQUIRE_APPROVAL",
        "ttps": ["T1078", "T1548"],
    },
    "reconnaissance": {
        "keywords": ["describe", "list", "get", "enumerate", "scan", "discover"],
        "severity_weight": 0.4,
        "response": "MONITOR",
        "ttps": ["T1595", "T1592"],
    },
    "ransomware": {
        "keywords": ["encrypt", "ransom", "lockbit", "wannacry", "decrypt", "bitcoin"],
        "severity_weight": 1.0,
        "response": "AUTO_ISOLATE",
        "ttps": ["T1486", "T1490"],
    },
}

# Severity mapping for numerical operations
SEVERITY_MAP = {
    "CRITICAL": 10.0,
    "HIGH": 7.5,
    "MEDIUM": 5.0,
    "LOW": 2.5,
    "INFO": 0.5,
}


class ThreatClassifier:
    """
    ML-driven threat classification engine.

    Uses a multi-factor feature-weighted algorithm to:
    1. Classify threat type based on action/pattern matching
    2. Predict severity using weighted feature scoring
    3. Recommend optimal response strategy
    4. Calculate confidence score for the classification
    """

    def __init__(self) -> None:
        self._attack_db = ATTACK_SIGNATURES
        self._history: List[Dict[str, Any]] = []

    def predict_threat_severity(
        self, incident_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Predict threat severity and classify the incident.

        Args:
            incident_data: Normalized incident dict (UnifiedIncident format).

        Returns:
            Classification result with severity, threat_type, confidence,
            MITRE TTPs, and recommended_response.
        """
        action = str(incident_data.get("action", "")).lower()
        severity_str = str(incident_data.get("severity", "MEDIUM")).upper()
        source_ip = str(incident_data.get("source_ip", ""))
        risk_score = float(incident_data.get("risk_score", 0))
        anomaly_score = float(incident_data.get("anomaly_score", 0))

        # ---- Feature Extraction ----
        base_severity = SEVERITY_MAP.get(severity_str, 5.0)
        pattern_match = self._match_attack_pattern(action)
        ip_reputation = self._assess_ip_risk(incident_data)
        temporal_risk = self._temporal_analysis(incident_data)

        # ---- Weighted Classification Score ----
        weights = {
            "base_severity": 0.20,
            "pattern_weight": 0.30,
            "risk_score": 0.15,
            "anomaly_factor": 0.15,
            "ip_reputation": 0.10,
            "temporal_risk": 0.10,
        }

        pattern_weight = pattern_match["severity_weight"] if pattern_match else 0.3
        anomaly_factor = max(0.0, (1.0 - anomaly_score)) if anomaly_score < 0 else 0.3

        raw_score = (
            weights["base_severity"] * (base_severity / 10.0)
            + weights["pattern_weight"] * pattern_weight
            + weights["risk_score"] * (risk_score / 100.0)
            + weights["anomaly_factor"] * anomaly_factor
            + weights["ip_reputation"] * ip_reputation
            + weights["temporal_risk"] * temporal_risk
        )

        # Normalize to 0-100
        predicted_score = min(raw_score * 100.0, 100.0)

        # Determine predicted severity
        predicted_severity = self._score_to_severity(predicted_score)

        # Confidence = how certain we are (based on data quality)
        confidence = self._calculate_confidence(
            pattern_match, risk_score, anomaly_score, ip_reputation
        )

        # Build result
        threat_type = pattern_match["name"] if pattern_match else "unknown"
        ttps = pattern_match.get("ttps", []) if pattern_match else []

        result = {
            "predicted_severity": predicted_severity,
            "predicted_score": round(predicted_score, 2),
            "threat_type": threat_type,
            "confidence": round(confidence, 2),
            "mitre_ttps": ttps,
            "feature_weights": {
                "base_severity": round(base_severity, 2),
                "pattern_weight": round(pattern_weight, 2),
                "risk_score_norm": round(risk_score / 100.0, 2),
                "anomaly_factor": round(anomaly_factor, 2),
                "ip_reputation": round(ip_reputation, 2),
                "temporal_risk": round(temporal_risk, 2),
            },
        }

        self._history.append(result)
        logger.info(
            "Threat classified: type=%s severity=%s score=%.1f confidence=%.0f%%",
            threat_type, predicted_severity, predicted_score, confidence * 100,
        )
        return result

    def recommend_response(
        self, classification: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Recommend a response strategy based on the classification result.

        Returns:
            Dict with recommended_action, urgency, and playbook steps.
        """
        score = classification.get("predicted_score", 0)
        threat_type = classification.get("threat_type", "unknown")
        confidence = classification.get("confidence", 0)

        # Match to known attack pattern for specific playbook
        matched = self._attack_db.get(threat_type, {})
        default_response = matched.get("response", "MONITOR")

        # Override based on confidence + score
        if score >= 80 and confidence >= 0.7:
            action = "AUTO_ISOLATE"
            urgency = "CRITICAL"
        elif score >= 60:
            action = "REQUIRE_APPROVAL"
            urgency = "HIGH"
        elif score >= 40:
            action = default_response
            urgency = "MEDIUM"
        else:
            action = "MONITOR"
            urgency = "LOW"

        playbook = self._generate_playbook(threat_type, action)

        return {
            "recommended_action": action,
            "urgency": urgency,
            "playbook": playbook,
            "reasoning": (
                f"Score={score:.1f}, Confidence={confidence:.0%}, "
                f"ThreatType={threat_type}"
            ),
        }

    # ---- Private Methods ----

    def _match_attack_pattern(self, action: str) -> Optional[Dict[str, Any]]:
        """Match an action string against known attack signatures."""
        best_match: Optional[Tuple[str, Dict[str, Any], int]] = None

        for name, sig in self._attack_db.items():
            hits = sum(1 for kw in sig["keywords"] if kw in action)
            if hits > 0:
                if best_match is None or hits > best_match[2]:
                    best_match = (name, sig, hits)

        if best_match:
            return {"name": best_match[0], **best_match[1]}
        return None

    @staticmethod
    def _assess_ip_risk(incident_data: Dict[str, Any]) -> float:
        """Assess IP risk from threat intel data (0.0 = safe, 1.0 = dangerous)."""
        intel = incident_data.get("intel_summary", {})
        vt = intel.get("virustotal", {})
        abuse = intel.get("abuseipdb", {})

        vt_score = min(float(vt.get("malicious", 0)) / 10.0, 1.0)
        abuse_score = float(abuse.get("abuseConfidenceScore", 0)) / 100.0

        return (vt_score * 0.6) + (abuse_score * 0.4)

    @staticmethod
    def _temporal_analysis(incident_data: Dict[str, Any]) -> float:
        """Score based on timing (off-hours = higher risk)."""
        timestamp = str(incident_data.get("timestamp", ""))
        try:
            # Extract hour from ISO timestamp
            hour_str = timestamp.split("T")[1][:2]
            hour = int(hour_str)
            # Off-hours (22:00 - 06:00) = higher risk
            if hour >= 22 or hour <= 6:
                return 0.8
            elif hour >= 18 or hour <= 8:
                return 0.4
            return 0.2
        except (IndexError, ValueError):
            return 0.3  # Unknown time = moderate risk

    @staticmethod
    def _score_to_severity(score: float) -> str:
        if score >= 80:
            return "CRITICAL"
        elif score >= 60:
            return "HIGH"
        elif score >= 40:
            return "MEDIUM"
        elif score >= 20:
            return "LOW"
        return "INFO"

    @staticmethod
    def _calculate_confidence(
        pattern_match: Optional[Dict[str, Any]],
        risk_score: float,
        anomaly_score: float,
        ip_reputation: float,
    ) -> float:
        """Calculate confidence (0.0 - 1.0) based on available evidence."""
        evidence_points = 0.0
        max_points = 4.0

        if pattern_match:
            evidence_points += 1.0
        if risk_score > 0:
            evidence_points += 1.0
        if anomaly_score != 0:
            evidence_points += 1.0
        if ip_reputation > 0:
            evidence_points += 1.0

        return evidence_points / max_points

    @staticmethod
    def _generate_playbook(threat_type: str, action: str) -> List[str]:
        """Generate a response playbook based on threat type."""
        common = [
            "1. Collect forensic evidence (logs, snapshots)",
            "2. Notify SOC team via Slack",
        ]

        specific: Dict[str, List[str]] = {
            "crypto_mining": [
                "3. Terminate mining processes via SSM Run Command",
                "4. Isolate instance from network",
                "5. Scan for persistence mechanisms",
            ],
            "credential_theft": [
                "3. Rotate all compromised credentials",
                "4. Revoke active sessions",
                "5. Enable MFA on affected accounts",
            ],
            "data_exfiltration": [
                "3. Block egress traffic immediately",
                "4. Identify exfiltrated data scope",
                "5. Initiate breach notification if PII involved",
            ],
            "ransomware": [
                "3. Isolate all affected instances IMMEDIATELY",
                "4. Activate backup restoration plan",
                "5. Engage incident response retainer",
            ],
            "privilege_escalation": [
                "3. Revert IAM policy changes",
                "4. Audit CloudTrail for lateral movement",
                "5. Review all role assumptions in last 24h",
            ],
        }

        steps = common + specific.get(threat_type, [
            "3. Investigate the incident manually",
            "4. Apply standard incident response procedures",
        ])

        if action == "AUTO_ISOLATE":
            steps.append("⚡ AUTO-ISOLATION ACTIVATED — resource quarantined")

        return steps
