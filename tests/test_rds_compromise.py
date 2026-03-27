"""Tests for RDS Compromise playbook."""

from unittest.mock import MagicMock, patch

from moto import mock_aws


def make_rds_cloudtrail_event(event_name="ModifyDBInstance", db_id="mydb", source_ip="198.51.100.1"):
    return {
        "source": "aws.rds",
        "detail": {
            "eventSource": "rds.amazonaws.com",
            "eventName": event_name,
            "requestParameters": {"dBInstanceIdentifier": db_id},
            "userIdentity": {"userName": "attacker"},
            "sourceIPAddress": source_ip,
        },
    }


class TestRDSCompromiseCanHandle:
    def test_handles_modify_db_instance(self):
        from src.playbooks.rds_compromise import RDSCompromisePlaybook

        pb = RDSCompromisePlaybook.__new__(RDSCompromisePlaybook)
        assert pb.can_handle(make_rds_cloudtrail_event("ModifyDBInstance")) is True

    def test_handles_delete_db_instance(self):
        from src.playbooks.rds_compromise import RDSCompromisePlaybook

        pb = RDSCompromisePlaybook.__new__(RDSCompromisePlaybook)
        assert pb.can_handle(make_rds_cloudtrail_event("DeleteDBInstance")) is True

    def test_handles_restore_from_snapshot(self):
        from src.playbooks.rds_compromise import RDSCompromisePlaybook

        pb = RDSCompromisePlaybook.__new__(RDSCompromisePlaybook)
        assert pb.can_handle(make_rds_cloudtrail_event("RestoreDBInstanceFromDBSnapshot")) is True

    def test_rejects_non_risky_method(self):
        from src.playbooks.rds_compromise import RDSCompromisePlaybook

        pb = RDSCompromisePlaybook.__new__(RDSCompromisePlaybook)
        assert pb.can_handle(make_rds_cloudtrail_event("DescribeDBInstances")) is False

    def test_rejects_wrong_source(self):
        from src.playbooks.rds_compromise import RDSCompromisePlaybook

        pb = RDSCompromisePlaybook.__new__(RDSCompromisePlaybook)
        event = make_rds_cloudtrail_event("ModifyDBInstance")
        event["source"] = "aws.ec2"
        assert pb.can_handle(event) is False

    def test_rejects_malformed_event(self):
        from src.playbooks.rds_compromise import RDSCompromisePlaybook

        pb = RDSCompromisePlaybook.__new__(RDSCompromisePlaybook)
        assert pb.can_handle({"bad": "data"}) is False


class TestRDSCompromiseExecute:
    @mock_aws
    @patch("src.playbooks.rds_compromise.emit_metric")
    @patch("src.playbooks.rds_compromise.PlaybookTimer")
    def test_execute_auto_isolate(self, mock_timer, mock_emit):
        mock_timer.return_value.__enter__ = MagicMock(return_value=None)
        mock_timer.return_value.__exit__ = MagicMock(return_value=False)

        from src.playbooks.rds_compromise import RDSCompromisePlaybook

        pb = RDSCompromisePlaybook.__new__(RDSCompromisePlaybook)
        pb.rds = MagicMock()
        pb.ec2 = MagicMock()
        pb.isolation_sg_id = "sg-isolation123"
        pb.audit = MagicMock()
        pb.rds.create_db_snapshot.return_value = {}
        pb.rds.modify_db_instance.return_value = {}

        with (
            patch("src.playbooks.rds_compromise.RDSCompromisePlaybook._create_db_snapshot"),
            patch("src.playbooks.rds_compromise.RDSCompromisePlaybook._isolate_db_security_group"),
            patch("src.playbooks.rds_compromise.RDSCompromisePlaybook._notify_slack"),
        ):
            # Patch internal threat intel import to force AUTO_ISOLATE path
            import sys

            mock_intel = MagicMock()
            mock_intel.get_ip_report.return_value = {}
            mock_scoring = MagicMock()
            mock_scoring.calculate_risk_score.return_value = {"decision": "AUTO_ISOLATE", "risk_score": 80.0}

            mock_intel_module = MagicMock()
            mock_intel_module.ThreatIntelService.return_value = mock_intel
            mock_scoring_module = MagicMock()
            mock_scoring_module.ScoringEngine = mock_scoring

            with patch.dict(
                sys.modules,
                {
                    "src.integrations.intel": mock_intel_module,
                    "src.integrations.scoring": mock_scoring_module,
                },
            ):
                event = make_rds_cloudtrail_event("ModifyDBInstance", "prod-db", "203.0.113.5")
                result = pb.execute(event)

        assert result is True

    @mock_aws
    @patch("src.playbooks.rds_compromise.emit_metric")
    @patch("src.playbooks.rds_compromise.PlaybookTimer")
    def test_create_db_snapshot_called(self, mock_timer, mock_emit):
        mock_timer.return_value.__enter__ = MagicMock(return_value=None)
        mock_timer.return_value.__exit__ = MagicMock(return_value=False)

        from src.playbooks.rds_compromise import RDSCompromisePlaybook

        pb = RDSCompromisePlaybook.__new__(RDSCompromisePlaybook)
        pb.rds = MagicMock()
        pb.audit = MagicMock()
        pb.rds.create_db_snapshot.return_value = {}

        pb._create_db_snapshot("test-db", "ModifyDBInstance")

        pb.rds.create_db_snapshot.assert_called_once()
        call_kwargs = pb.rds.create_db_snapshot.call_args[1]
        assert "soar-forensic-test-db" in call_kwargs["DBSnapshotIdentifier"]
        assert call_kwargs["DBInstanceIdentifier"] == "test-db"

    @mock_aws
    @patch("src.playbooks.rds_compromise.emit_metric")
    @patch("src.playbooks.rds_compromise.PlaybookTimer")
    def test_isolate_db_security_group(self, mock_timer, mock_emit):
        mock_timer.return_value.__enter__ = MagicMock(return_value=None)
        mock_timer.return_value.__exit__ = MagicMock(return_value=False)

        from src.playbooks.rds_compromise import RDSCompromisePlaybook

        pb = RDSCompromisePlaybook.__new__(RDSCompromisePlaybook)
        pb.rds = MagicMock()
        pb.audit = MagicMock()
        pb.isolation_sg_id = "sg-isolation123"

        pb._isolate_db_security_group("test-db")

        pb.rds.modify_db_instance.assert_called_once_with(
            DBInstanceIdentifier="test-db",
            VpcSecurityGroupIds=["sg-isolation123"],
            ApplyImmediately=True,
        )

    def test_execute_returns_false_no_db_id(self):
        from src.playbooks.rds_compromise import RDSCompromisePlaybook

        pb = RDSCompromisePlaybook.__new__(RDSCompromisePlaybook)
        pb.rds = MagicMock()
        pb.ec2 = MagicMock()
        pb.isolation_sg_id = None
        pb.audit = MagicMock()

        event = {
            "source": "aws.rds",
            "detail": {
                "eventSource": "rds.amazonaws.com",
                "eventName": "ModifyDBInstance",
                "requestParameters": {},  # No db id
                "userIdentity": {},
                "sourceIPAddress": "1.2.3.4",
            },
        }

        with patch("src.playbooks.rds_compromise.PlaybookTimer") as mock_timer:
            mock_timer.return_value.__enter__ = MagicMock(return_value=None)
            mock_timer.return_value.__exit__ = MagicMock(return_value=False)
            result = pb.execute(event)

        assert result is False

    def test_risky_rds_methods_model(self):
        from src.models.events import RISKY_RDS_METHODS, RDSCloudTrailDetail

        for method in RISKY_RDS_METHODS:
            detail = RDSCloudTrailDetail(eventName=method)
            assert detail.is_risky is True

        safe = RDSCloudTrailDetail(eventName="DescribeDBInstances")
        assert safe.is_risky is False

    def test_audit_actions_exist(self):
        from src.core.audit_logger import AuditAction

        assert AuditAction.SNAPSHOT_DB == "SNAPSHOT_DB"
        assert AuditAction.ISOLATE_DB == "ISOLATE_DB"
        assert AuditAction.STOP_DB_INSTANCE == "STOP_DB_INSTANCE"
