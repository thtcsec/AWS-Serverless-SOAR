"""Tests for IAM Compromise playbook."""
import pytest
from unittest.mock import patch, MagicMock
from tests.conftest import make_iam_cloudtrail_event


class TestIAMCompromiseCanHandle:
    def test_handles_create_access_key(self):
        from src.playbooks.iam_compromise import IAMCompromisePlaybook
        with patch.object(IAMCompromisePlaybook, '__init__', lambda self: None):
            pb = IAMCompromisePlaybook()
            pb.risky_actions = [
                'CreateUser', 'CreateAccessKey', 'AddUserToGroup',
                'AttachUserPolicy', 'AttachRolePolicy', 'CreateRole'
            ]
            assert pb.can_handle(make_iam_cloudtrail_event("CreateAccessKey")) is True

    def test_handles_create_user(self):
        from src.playbooks.iam_compromise import IAMCompromisePlaybook
        with patch.object(IAMCompromisePlaybook, '__init__', lambda self: None):
            pb = IAMCompromisePlaybook()
            pb.risky_actions = [
                'CreateUser', 'CreateAccessKey', 'AddUserToGroup',
                'AttachUserPolicy', 'AttachRolePolicy', 'CreateRole'
            ]
            assert pb.can_handle(make_iam_cloudtrail_event("CreateUser")) is True

    def test_handles_attach_role_policy(self):
        from src.playbooks.iam_compromise import IAMCompromisePlaybook
        with patch.object(IAMCompromisePlaybook, '__init__', lambda self: None):
            pb = IAMCompromisePlaybook()
            pb.risky_actions = [
                'CreateUser', 'CreateAccessKey', 'AddUserToGroup',
                'AttachUserPolicy', 'AttachRolePolicy', 'CreateRole'
            ]
            assert pb.can_handle(make_iam_cloudtrail_event("AttachRolePolicy")) is True

    def test_rejects_normal_action(self):
        from src.playbooks.iam_compromise import IAMCompromisePlaybook
        with patch.object(IAMCompromisePlaybook, '__init__', lambda self: None):
            pb = IAMCompromisePlaybook()
            pb.risky_actions = [
                'CreateUser', 'CreateAccessKey', 'AddUserToGroup',
                'AttachUserPolicy', 'AttachRolePolicy', 'CreateRole'
            ]
            assert pb.can_handle(make_iam_cloudtrail_event("GetUser")) is False

    def test_rejects_wrong_source(self):
        from src.playbooks.iam_compromise import IAMCompromisePlaybook
        with patch.object(IAMCompromisePlaybook, '__init__', lambda self: None):
            pb = IAMCompromisePlaybook()
            pb.risky_actions = ['CreateAccessKey']
            assert pb.can_handle({"source": "aws.ec2", "detail": {"eventName": "CreateAccessKey", "userIdentity": {}}}) is False

    def test_rejects_malformed_event(self):
        from src.playbooks.iam_compromise import IAMCompromisePlaybook
        with patch.object(IAMCompromisePlaybook, '__init__', lambda self: None):
            pb = IAMCompromisePlaybook()
            pb.risky_actions = ['CreateAccessKey']
            assert pb.can_handle({"bad": "data"}) is False


class TestIAMCompromiseExecute:

    @patch("src.playbooks.iam_compromise.IAMCompromisePlaybook._notify_slack")
    @patch("src.integrations.scoring.ScoringEngine")
    @patch("src.integrations.intel.ThreatIntelService")
    @patch("src.playbooks.iam_compromise.emit_metric")
    @patch("src.playbooks.iam_compromise.PlaybookTimer")
    def test_execute_auto_isolate(self, mock_timer, mock_emit, mock_intel, mock_scoring, mock_slack):
        mock_timer.return_value.__enter__ = MagicMock()
        mock_timer.return_value.__exit__ = MagicMock(return_value=False)

        mock_intel_inst = mock_intel.return_value
        mock_intel_inst.get_ip_report.return_value = {"vt": {"malicious": 10}, "abuse": {"score": 100}}

        mock_scoring_inst = mock_scoring.return_value
        mock_scoring_inst.calculate_risk_score.return_value = {"decision": "AUTO_ISOLATE", "risk_score": 95.0}

        from src.playbooks.iam_compromise import IAMCompromisePlaybook
        pb = IAMCompromisePlaybook.__new__(IAMCompromisePlaybook)
        pb.iam = MagicMock()
        pb.risky_actions = ['CreateAccessKey']
        pb.iam.list_access_keys.return_value = {
            'AccessKeyMetadata': [
                {'AccessKeyId': 'AKIA1234', 'Status': 'Active'},
                {'AccessKeyId': 'AKIA5678', 'Status': 'Inactive'},
            ]
        }

        event = make_iam_cloudtrail_event("CreateAccessKey", "compromised-user")
        result = pb.execute(event)

        assert result is True
        # Verify access keys disabled
        pb.iam.update_access_key.assert_called_once_with(
            UserName="compromised-user",
            AccessKeyId="AKIA1234",
            Status="Inactive"
        )
        # Verify denom all policy attached
        pb.iam.put_user_policy.assert_called_once()
        args, kwargs = pb.iam.put_user_policy.call_args
        assert kwargs["UserName"] == "compromised-user"
        assert kwargs["PolicyName"] == "SOAR_Auto_Deny_All"
        import json
        policy_doc = json.loads(kwargs["PolicyDocument"])
        assert policy_doc["Statement"][0]["Effect"] == "Deny"

        # Verify notify slack called
        mock_slack.assert_called_once()


    @patch("src.playbooks.iam_compromise.IAMCompromisePlaybook._notify_slack")
    @patch("src.integrations.scoring.ScoringEngine")
    @patch("src.integrations.intel.ThreatIntelService")
    @patch("src.playbooks.iam_compromise.emit_metric")
    @patch("src.playbooks.iam_compromise.PlaybookTimer")
    def test_execute_require_approval(self, mock_timer, mock_emit, mock_intel, mock_scoring, mock_slack):
        mock_timer.return_value.__enter__ = MagicMock()
        mock_timer.return_value.__exit__ = MagicMock(return_value=False)

        mock_scoring_inst = mock_scoring.return_value
        mock_scoring_inst.calculate_risk_score.return_value = {"decision": "REQUIRE_APPROVAL", "risk_score": 50.0}

        from src.playbooks.iam_compromise import IAMCompromisePlaybook
        pb = IAMCompromisePlaybook.__new__(IAMCompromisePlaybook)
        pb.iam = MagicMock()

        event = make_iam_cloudtrail_event("CreateAccessKey", "user1")
        result = pb.execute(event)

        assert result is True
        # Verify no remediation was done
        pb.iam.update_access_key.assert_not_called()
        pb.iam.put_user_policy.assert_not_called()
        # Ensure slack is notified for approval
        mock_slack.assert_called_once()

    @patch("src.playbooks.iam_compromise.IAMCompromisePlaybook._notify_slack")
    @patch("src.integrations.scoring.ScoringEngine")
    @patch("src.integrations.intel.ThreatIntelService")
    @patch("src.playbooks.iam_compromise.emit_metric")
    @patch("src.playbooks.iam_compromise.PlaybookTimer")
    def test_execute_ignore(self, mock_timer, mock_emit, mock_intel, mock_scoring, mock_slack):
        mock_timer.return_value.__enter__ = MagicMock()
        mock_timer.return_value.__exit__ = MagicMock(return_value=False)

        mock_scoring_inst = mock_scoring.return_value
        mock_scoring_inst.calculate_risk_score.return_value = {"decision": "IGNORE", "risk_score": 10.0}

        from src.playbooks.iam_compromise import IAMCompromisePlaybook
        pb = IAMCompromisePlaybook.__new__(IAMCompromisePlaybook)
        pb.iam = MagicMock()

        event = make_iam_cloudtrail_event("CreateAccessKey", "user1")
        result = pb.execute(event)

        assert result is True
        # Verify no remediation/notification was done
        pb.iam.update_access_key.assert_not_called()
        mock_slack.assert_not_called()

    @patch("src.playbooks.iam_compromise.emit_metric")
    @patch("src.playbooks.iam_compromise.PlaybookTimer")
    def test_execute_returns_false_missing_username(self, mock_timer, mock_emit):
        mock_timer.return_value.__enter__ = MagicMock()
        mock_timer.return_value.__exit__ = MagicMock(return_value=False)

        from src.playbooks.iam_compromise import IAMCompromisePlaybook
        pb = IAMCompromisePlaybook.__new__(IAMCompromisePlaybook)
        pb.iam = MagicMock()

        event = {
            "source": "aws.iam",
            "detail": {
                "eventName": "CreateAccessKey",
                "userIdentity": {},  # no userName
                "sourceIPAddress": "1.1.1.1"
            }
        }
        result = pb.execute(event)
        assert result is False
