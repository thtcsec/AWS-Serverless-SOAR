"""
AWS SOAR — Incident Report Generator
Produces professional Markdown incident reports from SOAR response data.
Reports include timeline, severity, actions taken, and recommendations.
"""

import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class ReportGenerator:
    """Generate structured Incident Reports in Markdown format."""

    TEMPLATE_HEADER = """# 🛡️ SOAR Incident Report

| Field | Value |
|-------|-------|
| **Report ID** | {report_id} |
| **Generated** | {generated_at} |
| **Platform** | AWS |
| **Severity** | {severity} |
| **Status** | {status} |

---

## 📋 Executive Summary

{executive_summary}

---

## 🕐 Timeline

| Time | Event |
|------|-------|
{timeline_rows}

---

## 🎯 Affected Resources

| Resource | Type | Details |
|----------|------|---------|
{resource_rows}

---

## 🔍 Threat Intelligence

| Source | Result |
|--------|--------|
{intel_rows}

---

## ⚙️ Automated Actions Taken

{actions_taken}

---

## 📊 Risk Assessment

| Metric | Score |
|--------|-------|
| **Risk Score** | {risk_score}/100 |
| **Decision** | {decision} |
| **Anomaly Score** | {anomaly_score} |

---

## 💡 Recommendations

{recommendations}

---

*Report generated automatically by SOAR Platform v1.0*
"""

    @classmethod
    def generate(
        cls,
        incident_data: Dict[str, Any],
        actions: Optional[List[Dict[str, str]]] = None,
        recommendations: Optional[List[str]] = None,
        output_dir: str = "",
    ) -> Dict[str, Any]:
        """
        Generate a Markdown incident report.

        Args:
            incident_data: UnifiedIncident dict or raw finding.
            actions: List of automated actions taken.
            recommendations: List of recommendation strings.
            output_dir: Directory to save the report. Defaults to system temp dir.

        Returns:
            Dict with 'report_path' and 'report_content'.
        """
        import tempfile
        if not output_dir:
            output_dir = os.path.join(tempfile.gettempdir(), "soar_reports")

        now = datetime.now(timezone.utc)
        report_id = f"IR-{now.strftime('%Y%m%d-%H%M%S')}"

        severity = incident_data.get("severity", "UNKNOWN")
        resource = incident_data.get("resource", "N/A")
        resource_type = incident_data.get("resource_type", "N/A")
        action = incident_data.get("action", "N/A")
        source_ip = incident_data.get("source_ip", "N/A")
        risk_score = incident_data.get("risk_score", 0)
        decision = incident_data.get("decision", "N/A")
        anomaly_score = incident_data.get("anomaly_score", "N/A")
        actor = incident_data.get("actor", "N/A")
        timestamp = incident_data.get("timestamp", now.isoformat())

        # Executive summary
        executive_summary = (
            f"A **{severity}** severity security incident was detected involving "
            f"resource `{resource}` (type: `{resource_type}`). "
            f"The attack originated from IP `{source_ip}` and involved the action "
            f"`{action}`. The SOAR platform assigned a risk score of **{risk_score}/100** "
            f"and executed the **{decision}** response protocol."
        )

        # Timeline
        timeline_entries = [
            (timestamp, f"Incident detected: `{action}`"),
            (timestamp, f"Source IP identified: `{source_ip}`"),
            (timestamp, f"Risk score calculated: **{risk_score}**"),
            (timestamp, f"Decision: **{decision}**"),
        ]
        timeline_rows = "\n".join(
            f"| {t} | {e} |" for t, e in timeline_entries
        )

        # Resources
        resource_rows = f"| `{resource}` | {resource_type} | Actor: `{actor}` |"

        # Threat intel
        intel = incident_data.get("intel_summary", {})
        vt = intel.get("virustotal", {})
        abuse = intel.get("abuseipdb", {})
        intel_rows = (
            f"| VirusTotal | Malicious: {vt.get('malicious', 'N/A')} |\n"
            f"| AbuseIPDB | Confidence: {abuse.get('abuseConfidenceScore', 'N/A')}% |"
        )

        # Actions taken
        if actions:
            actions_md = "\n".join(
                f"- ✅ **{a.get('action', 'N/A')}**: {a.get('detail', '')}"
                for a in actions
            )
        else:
            actions_md = "- ✅ Automated response executed per SOAR decision engine."

        # Recommendations
        if recommendations:
            recs_md = "\n".join(f"- {r}" for r in recommendations)
        else:
            recs_md = cls._default_recommendations(severity, decision)

        report = cls.TEMPLATE_HEADER.format(
            report_id=report_id,
            generated_at=now.strftime("%Y-%m-%d %H:%M:%S UTC"),
            severity=severity,
            status="RESOLVED" if decision != "REQUIRE_APPROVAL" else "PENDING APPROVAL",
            executive_summary=executive_summary,
            timeline_rows=timeline_rows,
            resource_rows=resource_rows,
            intel_rows=intel_rows,
            actions_taken=actions_md,
            risk_score=risk_score,
            decision=decision,
            anomaly_score=anomaly_score,
            recommendations=recs_md,
        )

        # Save to file
        os.makedirs(output_dir, exist_ok=True)
        filename = f"{report_id}.md"
        filepath = os.path.join(output_dir, filename)

        with open(filepath, "w", encoding="utf-8") as f:
            f.write(report)

        logger.info("Incident report saved to %s", filepath)

        return {
            "report_id": report_id,
            "report_path": filepath,
            "report_content": report,
        }

    @staticmethod
    def _default_recommendations(severity: str, decision: str) -> str:
        recs = []
        if severity in ("CRITICAL", "HIGH"):
            recs.append("- 🔴 Escalate to on-call Security Lead immediately.")
            recs.append("- 🔍 Conduct full forensic analysis of affected resources.")
            recs.append("- 🔒 Rotate all credentials associated with the compromised resource.")
        if decision == "AUTO_ISOLATE":
            recs.append("- ✅ Verify isolation is effective (no network egress).")
            recs.append("- 📦 Preserve forensic snapshots before any remediation.")
        if decision == "REQUIRE_APPROVAL":
            recs.append("- ⏳ Awaiting human approval — review finding in AWS Console.")
        recs.append("- 📝 Update internal threat intelligence database with new IOCs.")
        return "\n".join(recs) if recs else "- No additional recommendations."
