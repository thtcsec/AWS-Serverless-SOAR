"""
AWS SOAR — Attack Forecaster (Predictive Security)
Uses historical incident data to forecast potential future attack
patterns and proactively strengthen defenses.
"""

import logging
import math
from collections import Counter
from typing import Any, Dict, List

logger = logging.getLogger("aws-soar.ml.forecaster")


class AttackForecaster:
    """
    Predictive security engine that analyzes historical incidents
    to forecast probable future attack vectors and severity trends.
    """

    def __init__(self) -> None:
        self._incident_history: List[Dict[str, Any]] = []

    def ingest(self, incidents: List[Dict[str, Any]]) -> int:
        """
        Ingest historical incident data for analysis.

        Args:
            incidents: List of incident dicts with keys:
                action, severity, source_ip, resource_type, timestamp

        Returns:
            Total number of incidents in the database.
        """
        self._incident_history.extend(incidents)
        logger.info("Ingested %d incidents (total: %d)",
                     len(incidents), len(self._incident_history))
        return len(self._incident_history)

    def forecast(self) -> Dict[str, Any]:
        """
        Generate attack forecasts based on historical data.

        Returns:
            Dict with top_predicted_attacks, trend_analysis,
            risk_heatmap, and proactive_recommendations.
        """
        if len(self._incident_history) < 5:
            return {
                "status": "INSUFFICIENT_DATA",
                "message": "Need at least 5 historical incidents for forecasting.",
                "top_predicted_attacks": [],
                "trend_analysis": {},
                "risk_heatmap": {},
                "proactive_recommendations": [],
            }

        # 1. Attack frequency analysis
        attack_freq = self._analyze_attack_frequency()

        # 2. Severity trend
        severity_trend = self._analyze_severity_trend()

        # 3. Resource targeting heatmap
        risk_heatmap = self._build_risk_heatmap()

        # 4. Top predicted attacks (based on frequency + trend)
        predictions = self._predict_top_attacks(attack_freq, severity_trend)

        # 5. Proactive recommendations
        recommendations = self._generate_proactive_recs(predictions, risk_heatmap)

        return {
            "status": "FORECAST_READY",
            "data_points": len(self._incident_history),
            "top_predicted_attacks": predictions,
            "trend_analysis": severity_trend,
            "risk_heatmap": risk_heatmap,
            "proactive_recommendations": recommendations,
        }

    # ---- Analysis Methods ----

    def _analyze_attack_frequency(self) -> Dict[str, int]:
        """Count frequency of each attack type."""
        actions = [
            str(inc.get("action", "unknown")).lower()
            for inc in self._incident_history
        ]
        return dict(Counter(actions).most_common(10))

    def _analyze_severity_trend(self) -> Dict[str, Any]:
        """Analyze whether severity is trending up or down."""
        severity_map = {
            "CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0,
        }

        scores = [
            severity_map.get(str(inc.get("severity", "MEDIUM")).upper(), 2)
            for inc in self._incident_history
        ]

        if len(scores) < 2:
            return {"direction": "STABLE", "avg_severity": 2.0}

        n = len(scores)
        first_half_avg = sum(scores[:n // 2]) / max(n // 2, 1)
        second_half_avg = sum(scores[n // 2:]) / max(n - n // 2, 1)
        overall_avg = sum(scores) / n

        diff = second_half_avg - first_half_avg

        if diff > 0.5:
            direction = "ESCALATING"
        elif diff < -0.5:
            direction = "DECREASING"
        else:
            direction = "STABLE"

        return {
            "direction": direction,
            "avg_severity": round(overall_avg, 2),
            "recent_avg": round(second_half_avg, 2),
            "historical_avg": round(first_half_avg, 2),
            "trend_delta": round(diff, 2),
        }

    def _build_risk_heatmap(self) -> Dict[str, Dict[str, Any]]:
        """Build a heatmap of which resource types are most targeted."""
        resource_counts: Counter[str] = Counter()
        resource_severity: Dict[str, List[int]] = {}
        severity_map = {
            "CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0,
        }

        for inc in self._incident_history:
            rtype = str(inc.get("resource_type", "unknown"))
            resource_counts[rtype] += 1
            sev = severity_map.get(str(inc.get("severity", "MEDIUM")).upper(), 2)
            resource_severity.setdefault(rtype, []).append(sev)

        total = sum(resource_counts.values()) or 1
        heatmap = {}
        for rtype, count in resource_counts.most_common(5):
            avg_sev = sum(resource_severity[rtype]) / len(resource_severity[rtype])
            heatmap[rtype] = {
                "incident_count": count,
                "percentage": round(count / total * 100, 1),
                "avg_severity": round(avg_sev, 2),
                "risk_level": "HIGH" if avg_sev > 2.5 else "MEDIUM",
            }

        return heatmap

    def _predict_top_attacks(
        self,
        freq: Dict[str, int],
        trend: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        """Predict top likely attack vectors."""
        total = sum(freq.values()) or 1
        escalating = trend.get("direction") == "ESCALATING"

        predictions = []
        for action, count in list(freq.items())[:5]:
            probability = count / total
            if escalating:
                probability = min(probability * 1.3, 1.0)

            predictions.append({
                "attack_type": action,
                "probability": round(probability * 100, 1),
                "historical_count": count,
                "trend": "↑" if escalating else "→",
            })

        return sorted(predictions, key=lambda x: x["probability"], reverse=True)

    @staticmethod
    def _generate_proactive_recs(
        predictions: List[Dict[str, Any]],
        heatmap: Dict[str, Dict[str, Any]],
    ) -> List[str]:
        """Generate proactive security recommendations."""
        recs = []

        if predictions:
            top = predictions[0]
            recs.append(
                f"🎯 Highest risk: '{top['attack_type']}' "
                f"({top['probability']}% probability) — review detection rules."
            )

        for rtype, info in heatmap.items():
            if info.get("risk_level") == "HIGH":
                recs.append(
                    f"🔥 Resource type '{rtype}' is heavily targeted "
                    f"({info['incident_count']} incidents) — harden security posture."
                )

        recs.extend([
            "📊 Schedule weekly threat review meetings with SOC team.",
            "🔄 Update IDS/IPS signatures based on attack pattern trends.",
            "🛡️ Consider deploying honeypots for top predicted attack vectors.",
        ])

        return recs
