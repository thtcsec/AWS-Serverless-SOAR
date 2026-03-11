"""Unit tests for AWS Incident Report Generator."""

import os
import pytest
from src.core.report_generator import ReportGenerator


@pytest.fixture
def sample_incident():
    return {
        "incident_id": "abc123",
        "platform": "aws",
        "severity": "CRITICAL",
        "source_ip": "198.51.100.10",
        "actor": "malicious-user",
        "action": "CryptoCurrency:EC2/BitcoinTool.B",
        "resource": "i-abc123",
        "resource_type": "ec2",
        "risk_score": 85.0,
        "decision": "AUTO_ISOLATE",
        "anomaly_score": -0.8,
        "timestamp": "2026-03-11T12:00:00Z",
        "intel_summary": {
            "virustotal": {"malicious": 12},
            "abuseipdb": {"abuseConfidenceScore": 95},
        },
    }


class TestReportGenerator:
    def test_generate_creates_file(self, sample_incident, tmp_path):
        result = ReportGenerator.generate(
            sample_incident, output_dir=str(tmp_path)
        )
        assert os.path.exists(result["report_path"])
        assert result["report_id"].startswith("IR-")

    def test_report_contains_key_fields(self, sample_incident, tmp_path):
        result = ReportGenerator.generate(
            sample_incident, output_dir=str(tmp_path)
        )
        content = result["report_content"]
        assert "CRITICAL" in content
        assert "i-abc123" in content
        assert "198.51.100.10" in content
        assert "85.0" in content
        assert "AUTO_ISOLATE" in content

    def test_report_with_custom_actions(self, sample_incident, tmp_path):
        actions = [
            {"action": "Instance Isolated", "detail": "Security group replaced"},
            {"action": "Snapshot Created", "detail": "vol-snap-123"},
        ]
        result = ReportGenerator.generate(
            sample_incident, actions=actions, output_dir=str(tmp_path)
        )
        assert "Instance Isolated" in result["report_content"]
        assert "Snapshot Created" in result["report_content"]

    def test_report_with_custom_recommendations(self, sample_incident, tmp_path):
        recs = ["Rotate all IAM keys", "Review CloudTrail logs"]
        result = ReportGenerator.generate(
            sample_incident, recommendations=recs, output_dir=str(tmp_path)
        )
        assert "Rotate all IAM keys" in result["report_content"]

    def test_default_recommendations_critical(self):
        recs = ReportGenerator._default_recommendations("CRITICAL", "AUTO_ISOLATE")
        assert "Escalate" in recs
        assert "Verify isolation" in recs

    def test_report_with_empty_data(self, tmp_path):
        result = ReportGenerator.generate({}, output_dir=str(tmp_path))
        assert "UNKNOWN" in result["report_content"]
        assert os.path.exists(result["report_path"])
