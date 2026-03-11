"""Tests for AWS Process Containment via SSM."""
import pytest
from unittest.mock import MagicMock, patch
from src.core.process_containment import ProcessContainment


class TestProcessContainment:
    @pytest.fixture
    def ssm_client(self):
        return MagicMock()

    @pytest.fixture
    def containment(self, ssm_client):
        return ProcessContainment(ssm_client)

    @pytest.fixture
    def mock_ps_output(self):
        return (
            "USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\n"
            "root         1  0.0  0.1  16968  3072 ?        Ss   00:00   0:01 /sbin/init\n"
            "evil      1337 95.0 10.0 999999 99999 ?        R    01:00   5:00 /tmp/xmrig --pool pool.minexmr.com\n"
            "www-data   500  2.0  1.0  50000  5000 ?        S    00:05   0:10 /usr/sbin/apache2\n"
        )

    def _setup_ssm_success(self, ssm_client, output):
        ssm_client.send_command.return_value = {
            "Command": {"CommandId": "cmd-123"}
        }
        ssm_client.get_command_invocation.return_value = {
            "Status": "Success",
            "StandardOutputContent": output,
        }

    def test_list_processes(self, containment, ssm_client, mock_ps_output):
        self._setup_ssm_success(ssm_client, mock_ps_output)
        processes = containment.list_processes("i-abc123")
        assert len(processes) == 3
        assert processes[1]["pid"] == "1337"
        assert "xmrig" in processes[1]["command"]

    def test_kill_process_success(self, containment, ssm_client):
        self._setup_ssm_success(ssm_client, "KILLED")
        result = containment.kill_process("i-abc123", "1337")
        assert result is True

    def test_kill_process_failure(self, containment, ssm_client):
        self._setup_ssm_success(ssm_client, "FAILED")
        result = containment.kill_process("i-abc123", "1337")
        assert result is False

    def test_kill_by_name(self, containment, ssm_client):
        self._setup_ssm_success(ssm_client, "KILLED")
        result = containment.kill_by_name("i-abc123", "xmrig")
        assert result is True

    def test_quarantine_file(self, containment, ssm_client):
        self._setup_ssm_success(ssm_client, "QUARANTINED")
        result = containment.quarantine_file("i-abc123", "/tmp/malware.bin")
        assert result is True

    def test_containment_report_detects_suspicious(self, containment, ssm_client, mock_ps_output):
        self._setup_ssm_success(ssm_client, mock_ps_output)
        report = containment.get_containment_report("i-abc123")
        assert report["instance_id"] == "i-abc123"
        assert report["suspicious_count"] == 1
        assert "xmrig" in report["suspicious_processes"][0]["command"]

    def test_ssm_command_timeout(self, containment, ssm_client):
        ssm_client.send_command.return_value = {
            "Command": {"CommandId": "cmd-timeout"}
        }
        ssm_client.get_command_invocation.return_value = {
            "Status": "InProgress",
        }
        with patch("src.core.process_containment.time.sleep"):
            result = containment._run_command("i-abc123", "echo test")
        assert result is None

    def test_ssm_exception_returns_none(self, containment, ssm_client):
        ssm_client.send_command.side_effect = Exception("SSM unavailable")
        result = containment._run_command("i-abc123", "echo test")
        assert result is None
