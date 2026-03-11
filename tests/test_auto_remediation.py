"""Unit tests for AWS Auto-Remediation Patching."""

from unittest.mock import MagicMock
import pytest
from src.core.auto_remediation import AutoRemediation


@pytest.fixture
def mock_ssm():
    client = MagicMock()
    client.send_command.return_value = {
        "Command": {"CommandId": "cmd-test-123"}
    }
    return client


@pytest.fixture
def remediation(mock_ssm):
    return AutoRemediation(client=mock_ssm)


class TestAutoRemediation:
    def test_patch_matching_packages(self, remediation, mock_ssm):
        result = remediation.patch_instance("i-abc123", ["openssl vulnerability", "curl exploit"])
        assert result["status"] == "sent"
        assert result["command_id"] == "cmd-test-123"
        assert "openssl" in result["packages_patched"]
        mock_ssm.send_command.assert_called_once()

    def test_patch_no_matching_packages(self, remediation):
        result = remediation.patch_instance("i-abc123", ["unknown-vuln"])
        assert result["status"] == "skipped"
        assert "No matching packages" in result["reason"]

    def test_patch_deduplication(self, remediation, mock_ssm):
        result = remediation.patch_instance("i-abc123", ["openssl", "OpenSSL CVE"])
        assert result["status"] == "sent"
        # Should deduplicate packages
        assert len(result["packages_patched"]) == len(set(result["packages_patched"]))

    def test_patch_ssm_error(self):
        client = MagicMock()
        from botocore.exceptions import ClientError
        client.send_command.side_effect = ClientError(
            {"Error": {"Code": "InvalidInstanceId", "Message": "not found"}},
            "SendCommand"
        )
        remediation = AutoRemediation(client=client)
        result = remediation.patch_instance("i-bad", ["openssl"])
        assert result["status"] == "error"
        assert "i-bad" in result["instance_id"]
