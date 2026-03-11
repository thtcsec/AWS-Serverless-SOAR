"""Tests for AWS Audit Logger."""
import pytest
from unittest.mock import MagicMock
from src.core.audit_logger import AuditLogger, AuditAction, AuditEntry


class TestAuditEntry:
    def test_entry_creation(self):
        entry = AuditEntry(
            action=AuditAction.ISOLATE_NETWORK,
            resource_id="i-abc123",
            actor="admin",
            details={"reason": "crypto miner"},
        )
        assert entry.action == AuditAction.ISOLATE_NETWORK
        assert entry.resource_id == "i-abc123"
        assert entry.success is True

    def test_entry_to_dict(self):
        entry = AuditEntry(
            action=AuditAction.KILL_PROCESS,
            resource_id="i-abc123",
        )
        d = entry.to_dict()
        assert d["action"] == "KILL_PROCESS"
        assert "timestamp" in d
        assert d["success"] is True


class TestAuditLogger:
    @pytest.fixture
    def audit_logger(self):
        return AuditLogger()

    def test_log_action(self, audit_logger):
        entry = audit_logger.log(
            AuditAction.PLAYBOOK_STARTED,
            resource_id="i-abc123",
        )
        assert entry.action == AuditAction.PLAYBOOK_STARTED
        assert len(audit_logger._entries) == 1

    def test_log_multiple_actions(self, audit_logger):
        audit_logger.log(AuditAction.PLAYBOOK_STARTED, "i-001")
        audit_logger.log(AuditAction.ISOLATE_NETWORK, "i-001")
        audit_logger.log(AuditAction.KILL_PROCESS, "i-001", success=False)
        audit_logger.log(AuditAction.PLAYBOOK_COMPLETED, "i-001")
        assert len(audit_logger._entries) == 4

    def test_get_entries_filter_by_resource(self, audit_logger):
        audit_logger.log(AuditAction.KILL_PROCESS, "i-001")
        audit_logger.log(AuditAction.KILL_PROCESS, "i-002")
        entries = audit_logger.get_entries(resource_id="i-001")
        assert len(entries) == 1

    def test_get_entries_filter_by_action(self, audit_logger):
        audit_logger.log(AuditAction.KILL_PROCESS, "i-001")
        audit_logger.log(AuditAction.ISOLATE_NETWORK, "i-001")
        entries = audit_logger.get_entries(action=AuditAction.KILL_PROCESS)
        assert len(entries) == 1

    def test_get_summary(self, audit_logger):
        audit_logger.log(AuditAction.PLAYBOOK_STARTED, "i-001")
        audit_logger.log(AuditAction.KILL_PROCESS, "i-001", success=False)
        summary = audit_logger.get_summary()
        assert summary["total_entries"] == 2
        assert summary["success_count"] == 1
        assert summary["failure_count"] == 1

    def test_export_to_s3(self, audit_logger):
        s3_mock = MagicMock()
        audit_logger._s3 = s3_mock
        audit_logger.log(AuditAction.PLAYBOOK_STARTED, "i-001")
        result = audit_logger.export_to_s3("my-bucket")
        assert result is True
        s3_mock.put_object.assert_called_once()

    def test_export_to_s3_no_client(self, audit_logger):
        result = audit_logger.export_to_s3("my-bucket")
        assert result is False

    def test_cloudwatch_integration(self):
        cw_mock = MagicMock()
        audit_logger = AuditLogger(cloudwatch_client=cw_mock)
        audit_logger.log(AuditAction.SCORING_DECISION, "i-001")
        cw_mock.put_log_events.assert_called_once()
