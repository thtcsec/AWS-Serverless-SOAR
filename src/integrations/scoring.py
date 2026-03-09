from typing import Dict, Any
import logging

logger = logging.getLogger(__name__)

class ScoringEngine:
    """Engine to calculate risk scores based on multi-source intelligence."""
    
    @staticmethod
    def calculate_risk_score(intel_data: Dict[str, Any], initial_severity: float) -> Dict[str, Any]:
        """
        Calculate a weighted risk score (0-100).
        Formula: (VT_malicious * 2) + (Abuse_score * 0.5) + (Initial_Severity * 3)
        """
        vt_malicious = intel_data.get('virustotal', {}).get('malicious', 0)
        abuse_score = intel_data.get('abuseipdb', {}).get('abuseConfidenceScore', 0)
        
        # Calculate raw score
        raw_score = (vt_malicious * 2) + (abuse_score * 0.5) + (initial_severity * 3)
        
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
                "initial_severity": initial_severity
            }
        }
