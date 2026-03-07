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
    @patch("src.playbooks.iam_compromise.emit_metric")
    @patch("src.playbooks.iam_compromise.PlaybookTimer")
    def test_execute_disables_access_keys(self, mock_timer, mock_emit):
        mock_timer.return_value.__enter__ = MagicMock()
        mock_timer.return_value.__exit__ = MagicMock(return_value=False)

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
        # Only the active key should be deactivated
        pb.iam.update_access_key.assert_called_once_with(
            UserName="compromised-user",
            AccessKeyId="AKIA1234",
            Status="Inactive"
        )

    @patch("src.playbooks.iam_compromise.emit_metric")
    @patch("src.playbooks.iam_compromise.PlaybookTimer")
    def test_execute_returns_false_missing_username(self, mock_timer, mock_emit):
        mock_timer.return_value.__enter__ = MagicMock()
        mock_timer.return_value.__exit__ = MagicMock(return_value=False)

        from src.playbooks.iam_compromise import IAMCompromisePlaybook
        pb = IAMCompromisePlaybook.__new__(IAMCompromisePlaybook)
        pb.iam = MagicMock()
        pb.risky_actions = ['CreateAccessKey']

        event = {
            "source": "aws.iam",
            "detail": {
                "eventName": "CreateAccessKey",
                "userIdentity": {},  # no userName
            }
        }
        result = pb.execute(event)
        assert result is False

    @patch("src.playbooks.iam_compromise.emit_metric")
    @patch("src.playbooks.iam_compromise.PlaybookTimer")
    def test_execute_logs_key_disable_failure(self, mock_timer, mock_emit):
        """_disable_access_keys catches its own exceptions, so execute still returns True."""
        mock_timer.return_value.__enter__ = MagicMock()
        mock_timer.return_value.__exit__ = MagicMock(return_value=False)

        from src.playbooks.iam_compromise import IAMCompromisePlaybook
        pb = IAMCompromisePlaybook.__new__(IAMCompromisePlaybook)
        pb.iam = MagicMock()
        pb.risky_actions = ['CreateAccessKey']
        pb.iam.list_access_keys.side_effect = Exception("API Error")

        event = make_iam_cloudtrail_event("CreateAccessKey", "user1")
        result = pb.execute(event)
        # The inner method catches the exception — execute returns True
        assert result is True
