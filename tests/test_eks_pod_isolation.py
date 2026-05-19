"""Tests for EKS Pod Isolation playbook."""

from unittest.mock import MagicMock, patch


def make_eks_guardduty_event(finding_type="EKS:Runtime/CryptoMinerExecuted", severity=8.0, cluster="my-cluster"):
    return {
        "version": "0",
        "id": "event-id-456",
        "detail-type": "GuardDuty Finding",
        "source": "aws.guardduty",
        "account": "123456789012",
        "time": "2026-03-01T00:00:00Z",
        "region": "us-east-1",
        "resources": [],
        "detail": {
            "schemaVersion": "2.0",
            "accountId": "123456789012",
            "region": "us-east-1",
            "partition": "aws",
            "id": "finding-eks-001",
            "arn": "arn:aws:guardduty:us-east-1:12345:finding/2",
            "type": finding_type,
            "service": {"resourceRole": "TARGET"},
            "severity": severity,
            "createdAt": "2026-03-01T00:00:00Z",
            "updatedAt": "2026-03-01T00:00:00Z",
            "title": "EKS Runtime Threat",
            "description": "EKS runtime threat detected",
            "resource": {
                "eksClusterDetails": {"name": cluster},
                "kubernetesDetails": {
                    "kubernetesWorkloadDetails": {
                        "namespace": "default",
                        "name": "compromised-pod",
                    }
                },
            },
        },
    }


class TestEKSPodIsolationCanHandle:
    def test_handles_eks_runtime_threat(self):
        from src.playbooks.eks_pod_isolation import EKSPodIsolationPlaybook

        pb = EKSPodIsolationPlaybook.__new__(EKSPodIsolationPlaybook)
        assert pb.can_handle(make_eks_guardduty_event("EKS:Runtime/CryptoMinerExecuted")) is True

    def test_handles_malicious_file(self):
        from src.playbooks.eks_pod_isolation import EKSPodIsolationPlaybook

        pb = EKSPodIsolationPlaybook.__new__(EKSPodIsolationPlaybook)
        assert pb.can_handle(make_eks_guardduty_event("EKS:Runtime/MaliciousFile")) is True

    def test_handles_threat_intel_indicator(self):
        from src.playbooks.eks_pod_isolation import EKSPodIsolationPlaybook

        pb = EKSPodIsolationPlaybook.__new__(EKSPodIsolationPlaybook)
        assert pb.can_handle(make_eks_guardduty_event("EKS:Runtime/ThreatIntelIndicator")) is True

    def test_rejects_non_eks_finding(self):
        from src.playbooks.eks_pod_isolation import EKSPodIsolationPlaybook

        pb = EKSPodIsolationPlaybook.__new__(EKSPodIsolationPlaybook)
        event = make_eks_guardduty_event("EC2/CryptoMining")
        assert pb.can_handle(event) is False

    def test_rejects_wrong_source(self):
        from src.playbooks.eks_pod_isolation import EKSPodIsolationPlaybook

        pb = EKSPodIsolationPlaybook.__new__(EKSPodIsolationPlaybook)
        event = make_eks_guardduty_event("EKS:Runtime/CryptoMinerExecuted")
        event["source"] = "aws.ec2"
        assert pb.can_handle(event) is False


class TestEKSPodIsolationExecute:
    def test_severity_decision_high(self):
        from src.playbooks.eks_pod_isolation import EKSPodIsolationPlaybook

        assert EKSPodIsolationPlaybook._severity_decision(8.0) == "AUTO_ISOLATE"

    def test_severity_decision_medium(self):
        from src.playbooks.eks_pod_isolation import EKSPodIsolationPlaybook

        assert EKSPodIsolationPlaybook._severity_decision(5.0) == "REQUIRE_APPROVAL"

    def test_severity_decision_low(self):
        from src.playbooks.eks_pod_isolation import EKSPodIsolationPlaybook

        assert EKSPodIsolationPlaybook._severity_decision(2.0) == "IGNORE"

    @patch("src.playbooks.eks_pod_isolation.PlaybookTimer")
    @patch("src.playbooks.eks_pod_isolation.emit_metric")
    def test_execute_ignore_low_severity(self, mock_emit, mock_timer):
        mock_timer.return_value.__enter__ = MagicMock(return_value=None)
        mock_timer.return_value.__exit__ = MagicMock(return_value=False)

        from src.playbooks.eks_pod_isolation import EKSPodIsolationPlaybook

        pb = EKSPodIsolationPlaybook.__new__(EKSPodIsolationPlaybook)
        pb.eks = MagicMock()
        pb.s3 = MagicMock()
        pb.evidence_bucket = ""
        pb.audit = MagicMock()

        event = make_eks_guardduty_event(severity=1.0)
        result = pb.execute(event)
        assert result is True
        # No kubectl called
        pb.eks.describe_cluster.assert_not_called()

    @patch("src.playbooks.eks_pod_isolation.PlaybookTimer")
    @patch("src.playbooks.eks_pod_isolation.emit_metric")
    def test_execute_no_cluster_returns_false(self, mock_emit, mock_timer):
        mock_timer.return_value.__enter__ = MagicMock(return_value=None)
        mock_timer.return_value.__exit__ = MagicMock(return_value=False)

        from src.playbooks.eks_pod_isolation import EKSPodIsolationPlaybook

        pb = EKSPodIsolationPlaybook.__new__(EKSPodIsolationPlaybook)
        pb.eks = MagicMock()
        pb.s3 = MagicMock()
        pb.evidence_bucket = ""
        pb.audit = MagicMock()

        event = make_eks_guardduty_event()
        # Remove cluster name
        event["detail"]["resource"]["eksClusterDetails"] = {}
        result = pb.execute(event)
        assert result is False

    @patch("src.playbooks.eks_pod_isolation.PlaybookTimer")
    @patch("src.playbooks.eks_pod_isolation.emit_metric")
    @patch("src.playbooks.eks_pod_isolation.EKSPodIsolationPlaybook._collect_pod_logs")
    @patch("src.playbooks.eks_pod_isolation.EKSPodIsolationPlaybook._apply_quarantine_label")
    def test_execute_auto_isolate_calls_helpers(self, mock_label, mock_logs, mock_emit, mock_timer):
        mock_timer.return_value.__enter__ = MagicMock(return_value=None)
        mock_timer.return_value.__exit__ = MagicMock(return_value=False)

        from src.playbooks.eks_pod_isolation import EKSPodIsolationPlaybook

        pb = EKSPodIsolationPlaybook.__new__(EKSPodIsolationPlaybook)
        pb.eks = MagicMock()
        pb.s3 = MagicMock()
        pb.evidence_bucket = "evidence-bucket"
        pb.audit = MagicMock()

        event = make_eks_guardduty_event(severity=9.0)
        result = pb.execute(event)

        assert result is True
        mock_label.assert_called_once()
        mock_logs.assert_called_once()

    def test_eks_guardduty_model_is_eks_runtime(self):
        from src.models.events import EKSGuardDutyEvent

        event = make_eks_guardduty_event("EKS:Runtime/CryptoMinerExecuted")
        ev = EKSGuardDutyEvent.model_validate(event)
        assert ev.is_eks_runtime_threat is True

    def test_eks_guardduty_model_non_eks(self):
        from src.models.events import EKSGuardDutyEvent

        event = make_eks_guardduty_event("EC2/CryptoMining")
        ev = EKSGuardDutyEvent.model_validate(event)
        assert ev.is_eks_runtime_threat is False

    def test_audit_actions_exist(self):
        from src.core.audit_logger import AuditAction

        assert AuditAction.EVICT_POD == "EVICT_POD"
        assert AuditAction.APPLY_NETWORK_POLICY == "APPLY_NETWORK_POLICY"
        assert AuditAction.COLLECT_POD_LOGS == "COLLECT_POD_LOGS"


class TestEKSPodIsolationDryRun:
    @patch("src.playbooks.eks_pod_isolation.PlaybookTimer")
    def test_execute_dry_run_preview(self, mock_timer):
        mock_timer.return_value.__enter__ = MagicMock(return_value=None)
        mock_timer.return_value.__exit__ = MagicMock(return_value=False)

        from src.playbooks.eks_pod_isolation import EKSPodIsolationPlaybook

        pb = EKSPodIsolationPlaybook.__new__(EKSPodIsolationPlaybook)
        event = make_eks_guardduty_event(severity=8.0)
        event["dry_run"] = True
        result = pb.execute(event)

        assert result["mode"] == "dry_run"
        assert result["playbook"] == "EKSPodIsolation"
        assert result["decision"] == "AUTO_ISOLATE"
        assert len(result["planned_actions"]) == 3
