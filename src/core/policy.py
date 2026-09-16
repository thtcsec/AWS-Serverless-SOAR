"""
AWS SOAR — Policy Engine
Central scoring and decision gate for the incident pipeline.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any

from src.core.event_normalizer import UnifiedIncident
from src.integrations.anomaly_detector import AnomalyDetector
from src.integrations.intel import ThreatIntelService
from src.integrations.scoring import ScoringEngine

logger = logging.getLogger("aws-soar.policy")

RISKY_IAM_ACTIONS = [
    "CreateUser",
    "CreateAccessKey",
    "AddUserToGroup",
    "AttachUserPolicy",
    "AttachRolePolicy",
    "CreateRole",
]

_EVALUATE_TYPES = {"S3CloudTrailEvent"}


class PolicyEngine:
    """Score incidents and produce a policy decision before playbook execution."""

    def __init__(
        self,
        intel_service: ThreatIntelService | None = None,
        scoring_engine: ScoringEngine | None = None,
        anomaly_detector: AnomalyDetector | None = None,
    ) -> None:
        self._intel = intel_service or ThreatIntelService()
        self._scoring = scoring_engine or ScoringEngine()
        self._anomaly = anomaly_detector or AnomalyDetector()

    def evaluate(self, incident: UnifiedIncident) -> dict[str, Any]:
        if incident.raw_event_type in _EVALUATE_TYPES:
            return self._evaluate_s3(incident)
        if incident.raw_event_type == "IAMCloudTrailEvent":
            return self._evaluate_iam(incident)
        if incident.raw_event_type == "GuardDutyFinding":
            return self._evaluate_guardduty(incident)
        return self._evaluate_default(incident)

    def _evaluate_guardduty(self, incident: UnifiedIncident) -> dict[str, Any]:
        detail = incident.raw_event.get("detail", {})
        severity_val = float(detail.get("severity", 0))
        if severity_val >= 7:
            base_severity = 10.0
        elif severity_val >= 4:
            base_severity = 8.0
        elif severity_val >= 2:
            base_severity = 5.0
        else:
            base_severity = 2.0

        intel_report: dict[str, Any] = {}
        source_ip = incident.source_ip
        if not source_ip:
            source_ip = self._extract_guardduty_ip(incident.raw_event)
            incident.source_ip = source_ip or incident.source_ip

        if source_ip:
            intel_report = self._intel.get_ip_report(source_ip)
            incident.intel_summary = intel_report

        return self._score_with_anomaly(incident, intel_report, base_severity)

    def _evaluate_iam(self, incident: UnifiedIncident) -> dict[str, Any]:
        caller_ip = incident.source_ip
        action = incident.action
        intel_report: dict[str, Any] = {}

        base_risk = 6.0 if any(a in action for a in RISKY_IAM_ACTIONS) else 4.0
        if caller_ip and not caller_ip.endswith(".amazonaws.com"):
            base_risk += 2.0
        hour = datetime.now(UTC).hour
        if hour >= 23 or hour <= 5:
            base_risk += 2.0
        base_risk = min(base_risk, 10.0)

        if caller_ip and not caller_ip.endswith(".amazonaws.com"):
            intel_report = self._intel.get_ip_report(caller_ip)
            incident.intel_summary = intel_report

        return self._score_with_anomaly(incident, intel_report, base_risk)

    def _evaluate_s3(self, incident: UnifiedIncident) -> dict[str, Any]:
        result = {
            "risk_score": 0.0,
            "decision": "EVALUATE",
            "decision_rationale": "S3 read event — delegated to S3Exfiltration playbook.",
            "recommended_action": "evaluate_exfiltration_patterns",
            "summary": "Pipeline delegated evaluation to S3 playbook.",
            "breakdown": {},
            "anomaly_score": 0.0,
        }
        self._apply_result(incident, result)
        return result

    def _evaluate_default(self, incident: UnifiedIncident) -> dict[str, Any]:
        severity_map = {"LOW": 2.0, "MEDIUM": 5.0, "HIGH": 8.0, "CRITICAL": 10.0}
        base = severity_map.get(incident.severity.upper(), 5.0)
        intel_report: dict[str, Any] = {}

        if incident.source_ip:
            intel_report = self._intel.get_ip_report(incident.source_ip)
            incident.intel_summary = intel_report

        return self._score_with_anomaly(incident, intel_report, base)

    def _score_with_anomaly(
        self,
        incident: UnifiedIncident,
        intel_report: dict[str, Any],
        base_severity: float,
    ) -> dict[str, Any]:
        features = self._build_anomaly_features(incident, intel_report, base_severity)
        anomaly_score = self._anomaly.predict(features)
        if anomaly_score == 0.0 and len(self._anomaly._history) < 2:
            anomaly_score = self._heuristic_anomaly(features)
        self._observe_anomaly(features)

        result = self._scoring.calculate_risk_score(
            intel_report,
            base_severity,
            anomaly_score=anomaly_score,
        )
        result["anomaly_score"] = anomaly_score
        breakdown = dict(result.get("breakdown") or {})
        breakdown["anomaly_score"] = anomaly_score
        result["breakdown"] = breakdown
        self._apply_result(incident, result)
        return result

    def _observe_anomaly(self, features: dict[str, float]) -> None:
        """Grow z-score baseline so subsequent events can detect outliers."""
        try:
            self._anomaly._history.append(self._anomaly._extract_features(features))
            if len(self._anomaly._history) > 500:
                self._anomaly._history = self._anomaly._history[-500:]
        except Exception as exc:
            logger.debug("anomaly observe skipped: %s", exc)

    @staticmethod
    def _build_anomaly_features(
        incident: UnifiedIncident,
        intel_report: dict[str, Any],
        base_severity: float,
    ) -> dict[str, float]:
        now = datetime.now(UTC)
        abuse = float(intel_report.get("abuseipdb", {}).get("abuseConfidenceScore", 0) or 0)
        vt = float(intel_report.get("virustotal", {}).get("malicious", 0) or 0)
        return {
            "hour_of_day": float(now.hour),
            "day_of_week": float(now.weekday()),
            "ip_reputation_score": max(abuse, vt * 10.0),
            "action_risk_level": float(base_severity),
            "request_frequency": float(len(incident.related_incidents) + 1),
        }

    @staticmethod
    def _heuristic_anomaly(features: dict[str, float]) -> float:
        """Cold-start anomaly signal when ML/z-score baseline is empty."""
        hour = features.get("hour_of_day", 12.0)
        risk = features.get("action_risk_level", 0.0)
        ip_rep = features.get("ip_reputation_score", 0.0)
        if ip_rep >= 80:
            return -0.8
        if (hour >= 23 or hour <= 5) and risk >= 7:
            return -0.7
        if risk >= 9:
            return -0.55
        return 0.0

    @staticmethod
    def _apply_result(incident: UnifiedIncident, result: dict[str, Any]) -> None:
        incident.risk_score = float(result.get("risk_score", 0.0))
        incident.decision = str(result.get("decision", "IGNORE"))
        incident.anomaly_score = float(result.get("anomaly_score", 0.0))

    @staticmethod
    def _extract_guardduty_ip(raw_event: dict[str, Any]) -> str:
        detail = raw_event.get("detail", {})
        service = detail.get("service", {})
        action_info = service.get("action", {})
        if "networkConnectionAction" in action_info:
            return action_info["networkConnectionAction"].get("remoteIpDetails", {}).get("ipAddressV4", "")
        return ""

    @staticmethod
    def should_execute_playbook(decision: str) -> bool:
        return decision in {"AUTO_ISOLATE", "EVALUATE"}
