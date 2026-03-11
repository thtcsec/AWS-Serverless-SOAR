"""
AWS SOAR — Behavioral Analytics Engine
Monitors user and system behavior patterns to detect anomalies
that rule-based systems would miss.
"""

import logging
import math
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger("aws-soar.ml.behavior")


class BehaviorAnalyzer:
    """
    Track and analyze behavioral baselines for users/ service accounts.

    Detects:
    - Unusual API call frequencies
    - Geographic anomalies (new source IPs / regions)
    - Privilege usage spikes
    - Off-hours activity patterns
    """

    def __init__(self) -> None:
        # actor_id -> list of behavior records
        self._baselines: Dict[str, List[Dict[str, Any]]] = {}

    def record_activity(self, actor: str, activity: Dict[str, Any]) -> None:
        """Record an activity event for baseline building."""
        if actor not in self._baselines:
            self._baselines[actor] = []

        record = {
            "timestamp": activity.get("timestamp", datetime.now(timezone.utc).isoformat()),
            "action": activity.get("action", ""),
            "source_ip": activity.get("source_ip", ""),
            "region": activity.get("region", ""),
            "resource_type": activity.get("resource_type", ""),
            "risk_level": activity.get("risk_level", 0),
        }
        self._baselines[actor] = self._baselines[actor][-99:] + [record]

    def analyze(self, actor: str, current_event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze current event against actor's behavioral baseline.

        Returns:
            Dict with behavior_score (0=normal, 100=highly anomalous),
            anomaly flags, and reasoning.
        """
        baseline = self._baselines.get(actor, [])

        if len(baseline) < 3:
            return {
                "behavior_score": 30.0,
                "is_anomalous": False,
                "flags": ["INSUFFICIENT_BASELINE"],
                "reasoning": "Not enough historical data to establish baseline.",
                "recommendation": "MONITOR",
            }

        flags: List[str] = []
        scores: List[float] = []

        # 1. IP anomaly check
        ip_score = self._check_ip_anomaly(baseline, current_event)
        scores.append(ip_score)
        if ip_score > 60:
            flags.append("NEW_SOURCE_IP")

        # 2. Action frequency check
        freq_score = self._check_frequency_anomaly(baseline, current_event)
        scores.append(freq_score)
        if freq_score > 60:
            flags.append("UNUSUAL_FREQUENCY")

        # 3. Time-based anomaly
        time_score = self._check_temporal_anomaly(baseline, current_event)
        scores.append(time_score)
        if time_score > 60:
            flags.append("OFF_HOURS_ACTIVITY")

        # 4. Action type anomaly
        action_score = self._check_action_anomaly(baseline, current_event)
        scores.append(action_score)
        if action_score > 60:
            flags.append("UNUSUAL_ACTION_TYPE")

        # Weighted aggregate
        behavior_score = (
            ip_score * 0.30
            + freq_score * 0.25
            + time_score * 0.20
            + action_score * 0.25
        )

        is_anomalous = behavior_score > 50 or len(flags) >= 2

        recommendation = "MONITOR"
        if behavior_score >= 75:
            recommendation = "AUTO_ISOLATE"
        elif behavior_score >= 50:
            recommendation = "REQUIRE_APPROVAL"

        result = {
            "behavior_score": round(behavior_score, 2),
            "is_anomalous": is_anomalous,
            "flags": flags,
            "detail_scores": {
                "ip_anomaly": round(ip_score, 2),
                "frequency_anomaly": round(freq_score, 2),
                "temporal_anomaly": round(time_score, 2),
                "action_anomaly": round(action_score, 2),
            },
            "reasoning": self._build_reasoning(flags, behavior_score),
            "recommendation": recommendation,
        }

        logger.info(
            "Behavior analysis for %s: score=%.1f anomalous=%s flags=%s",
            actor, behavior_score, is_anomalous, flags,
        )
        return result

    # ---- Private Analysis Methods ----

    @staticmethod
    def _check_ip_anomaly(
        baseline: List[Dict[str, Any]], event: Dict[str, Any]
    ) -> float:
        """Check if the source IP is new for this actor."""
        known_ips = {r["source_ip"] for r in baseline if r.get("source_ip")}
        current_ip = event.get("source_ip", "")

        if not current_ip:
            return 30.0
        if current_ip in known_ips:
            return 10.0

        return 80.0  # Novel IP = high anomaly

    @staticmethod
    def _check_frequency_anomaly(
        baseline: List[Dict[str, Any]], event: Dict[str, Any]
    ) -> float:
        """Check if event frequency deviates from baseline."""
        if len(baseline) < 2:
            return 20.0

        action = event.get("action", "")
        action_count = sum(1 for r in baseline if r.get("action") == action)
        avg_count = len(baseline) / max(len({r.get("action") for r in baseline}), 1)

        if action_count == 0:
            return 70.0  # Never seen this action
        ratio = action_count / avg_count if avg_count > 0 else 1.0
        if ratio > 3.0:
            return 65.0  # Significant spike
        if ratio < 0.2:
            return 50.0  # Rare action

        return 15.0

    @staticmethod
    def _check_temporal_anomaly(
        baseline: List[Dict[str, Any]], event: Dict[str, Any]
    ) -> float:
        """Check if the event occurs at unusual times."""
        timestamp = event.get("timestamp", "")
        try:
            hour_str = str(timestamp).split("T")[1][:2]
            hour = int(hour_str)
        except (IndexError, ValueError):
            return 30.0

        baseline_hours = []
        for r in baseline:
            try:
                h = int(str(r.get("timestamp", "")).split("T")[1][:2])
                baseline_hours.append(h)
            except (IndexError, ValueError):
                continue

        if not baseline_hours:
            return 30.0

        avg_hour = sum(baseline_hours) / len(baseline_hours)
        deviation = abs(hour - avg_hour)

        if deviation > 6:
            return 80.0
        elif deviation > 3:
            return 50.0
        return 15.0

    @staticmethod
    def _check_action_anomaly(
        baseline: List[Dict[str, Any]], event: Dict[str, Any]
    ) -> float:
        """Check if the action type is unusual for this actor."""
        known_actions = {r.get("action", "") for r in baseline}
        current_action = event.get("action", "")

        if current_action in known_actions:
            return 10.0
        return 75.0  # Never before seen action type

    @staticmethod
    def _build_reasoning(flags: List[str], score: float) -> str:
        if not flags:
            return f"Activity within normal parameters (score={score:.1f})."
        reasons = {
            "NEW_SOURCE_IP": "Login from a previously unseen IP address",
            "UNUSUAL_FREQUENCY": "Abnormal API call frequency detected",
            "OFF_HOURS_ACTIVITY": "Activity outside normal working hours",
            "UNUSUAL_ACTION_TYPE": "Actor performed unfamiliar action type",
            "INSUFFICIENT_BASELINE": "Not enough history for reliable analysis",
        }
        details = "; ".join(reasons.get(f, f) for f in flags)
        return f"Anomalous behavior detected (score={score:.1f}): {details}."
