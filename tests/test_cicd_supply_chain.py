"""Tests for CI/CD Supply Chain playbook (AWS)."""

from unittest.mock import MagicMock, patch


def make_codepipeline_event(event_name="UpdatePipeline", pipeline_name="my-pipeline", source_ip="203.0.113.10"):
    return {
        "source": "aws.codepipeline",
        "detail": {
            "eventSource": "codepipeline.amazonaws.com",
            "eventName": event_name,
            "userIdentity": {"arn": "arn:aws:iam::123456789012:user/attacker", "userName": "attacker"},
            "sourceIPAddress": source_ip,
            "requestParameters": {
                "name": pipeline_name,
                "pipeline": {"name": pipeline_name},
            },
        },
    }


def make_codebuild_event(event_name="StartBuild", build_id="build-123", source_ip="203.0.113.10"):
    return {
        "source": "aws.codebuild",
        "detail": {
            "eventSource": "codebuild.amazonaws.com",
            "eventName": event_name,
            "userIdentity": {"arn": "arn:aws:iam::123456789012:user/attacker", "userName": "attacker"},
            "sourceIPAddress": source_ip,
            "requestParameters": {"id": build_id},
        },
    }


class TestCICDSupplyChainCanHandle:
    def test_handles_update_pipeline(self):
        from src.playbooks.cicd_supply_chain import CICDSupplyChainPlaybook

        pb = CICDSupplyChainPlaybook.__new__(CICDSupplyChainPlaybook)
        assert pb.can_handle(make_codepipeline_event("UpdatePipeline")) is True

    def test_handles_put_job_success_result(self):
        from src.playbooks.cicd_supply_chain import CICDSupplyChainPlaybook

        pb = CICDSupplyChainPlaybook.__new__(CICDSupplyChainPlaybook)
        assert pb.can_handle(make_codepipeline_event("PutJobSuccessResult")) is True

    def test_handles_start_build(self):
        from src.playbooks.cicd_supply_chain import CICDSupplyChainPlaybook

        pb = CICDSupplyChainPlaybook.__new__(CICDSupplyChainPlaybook)
        assert pb.can_handle(make_codebuild_event("StartBuild")) is True

    def test_rejects_non_risky_method(self):
        from src.playbooks.cicd_supply_chain import CICDSupplyChainPlaybook

        pb = CICDSupplyChainPlaybook.__new__(CICDSupplyChainPlaybook)
        assert pb.can_handle(make_codepipeline_event("GetPipelineState")) is False

    def test_rejects_wrong_source(self):
        from src.playbooks.cicd_supply_chain import CICDSupplyChainPlaybook

        pb = CICDSupplyChainPlaybook.__new__(CICDSupplyChainPlaybook)
        event = make_codepipeline_event("UpdatePipeline")
        event["source"] = "aws.ec2"
        assert pb.can_handle(event) is False

    def test_rejects_malformed_event(self):
        from src.playbooks.cicd_supply_chain import CICDSupplyChainPlaybook

        pb = CICDSupplyChainPlaybook.__new__(CICDSupplyChainPlaybook)
        assert pb.can_handle({"bad": "data"}) is False


class TestCICDSupplyChainBehaviorScore:
    def test_external_ip_high_score(self):
        from src.playbooks.cicd_supply_chain import CICDSupplyChainPlaybook

        score = CICDSupplyChainPlaybook._behavior_score("203.0.113.10", "some-arn", "UpdatePipeline")
        assert score >= 60.0  # External IP (35) + UpdatePipeline (30)

    def test_internal_ip_lower_score(self):
        from src.playbooks.cicd_supply_chain import CICDSupplyChainPlaybook

        score = CICDSupplyChainPlaybook._behavior_score("10.0.0.1", "assumed-role/lambda", "UpdatePipeline")
        assert score < 60.0

    def test_put_job_success_result_score(self):
        from src.playbooks.cicd_supply_chain import CICDSupplyChainPlaybook

        score = CICDSupplyChainPlaybook._behavior_score("203.0.113.10", "some-arn", "PutJobSuccessResult")
        assert score >= 60.0

    def test_max_score_capped_at_100(self):
        from src.playbooks.cicd_supply_chain import CICDSupplyChainPlaybook

        score = CICDSupplyChainPlaybook._behavior_score("1.2.3.4", "unknown-actor", "UpdatePipeline")
        assert score <= 100.0


class TestCICDSupplyChainExecute:
    @patch("src.playbooks.cicd_supply_chain.PlaybookTimer")
    @patch("src.playbooks.cicd_supply_chain.emit_metric")
    @patch("src.playbooks.cicd_supply_chain.CICDSupplyChainPlaybook._disable_pipeline")
    @patch("src.playbooks.cicd_supply_chain.CICDSupplyChainPlaybook._notify_slack")
    def test_execute_auto_isolate_disables_pipeline(self, mock_slack, mock_disable, mock_emit, mock_timer):
        mock_timer.return_value.__enter__ = MagicMock(return_value=None)
        mock_timer.return_value.__exit__ = MagicMock(return_value=False)

        from src.playbooks.cicd_supply_chain import CICDSupplyChainPlaybook

        pb = CICDSupplyChainPlaybook.__new__(CICDSupplyChainPlaybook)
        pb.codepipeline = MagicMock()
        pb.codebuild = MagicMock()
        pb.s3 = MagicMock()
        pb.audit = MagicMock()

        # External IP + UpdatePipeline → AUTO_ISOLATE
        event = make_codepipeline_event("UpdatePipeline", "prod-pipeline", "203.0.113.10")
        result = pb.execute(event)

        assert result is True
        mock_disable.assert_called_once()
        mock_slack.assert_called_once()

    @patch("src.playbooks.cicd_supply_chain.PlaybookTimer")
    @patch("src.playbooks.cicd_supply_chain.emit_metric")
    @patch("src.playbooks.cicd_supply_chain.CICDSupplyChainPlaybook._notify_slack")
    def test_execute_ignore_internal_ip(self, mock_slack, mock_emit, mock_timer):
        mock_timer.return_value.__enter__ = MagicMock(return_value=None)
        mock_timer.return_value.__exit__ = MagicMock(return_value=False)

        from src.playbooks.cicd_supply_chain import CICDSupplyChainPlaybook

        pb = CICDSupplyChainPlaybook.__new__(CICDSupplyChainPlaybook)
        pb.codepipeline = MagicMock()
        pb.codebuild = MagicMock()
        pb.s3 = MagicMock()
        pb.audit = MagicMock()

        # Internal IP + assumed-role → low score → IGNORE
        event = make_codepipeline_event("BatchGetProjects", "test-pipeline", "10.0.0.1")
        event["detail"]["userIdentity"] = {"arn": "arn:aws:sts::123:assumed-role/lambda"}
        result = pb.execute(event)

        assert result is True
        mock_slack.assert_not_called()

    def test_quarantine_artifact_bucket(self):
        from src.playbooks.cicd_supply_chain import CICDSupplyChainPlaybook

        pb = CICDSupplyChainPlaybook.__new__(CICDSupplyChainPlaybook)
        pb.s3 = MagicMock()
        pb.audit = MagicMock()

        pb._quarantine_artifact_bucket("my-artifacts-bucket", "pipeline-123")

        pb.s3.put_bucket_policy.assert_called_once()
        call_args = pb.s3.put_bucket_policy.call_args[1]
        assert call_args["Bucket"] == "my-artifacts-bucket"
        import json

        policy = json.loads(call_args["Policy"])
        assert policy["Statement"][0]["Effect"] == "Deny"

    def test_code_pipeline_model(self):
        from src.models.events import CodePipelineEvent

        event = make_codepipeline_event("UpdatePipeline")
        ev = CodePipelineEvent.model_validate(event)
        assert ev.detail.is_supply_chain_risk is True

    def test_audit_actions_exist(self):
        from src.core.audit_logger import AuditAction

        assert AuditAction.DISABLE_PIPELINE == "DISABLE_PIPELINE"
        assert AuditAction.STOP_BUILD == "STOP_BUILD"
        assert AuditAction.QUARANTINE_ARTIFACT == "QUARANTINE_ARTIFACT"
