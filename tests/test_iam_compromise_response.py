import os
import json
import pytest
from unittest.mock import patch, MagicMock

# Set environment variables required for initialization
os.environ['SNS_TOPIC_ARN'] = 'arn:aws:sns:us-east-1:123456789012:security-alerts'

import src.iam_compromise_response as resp

def make_event(event_name, source_ip="198.51.100.1", error_code=None):
    detail = {
        "eventName": event_name,
        "userIdentity": {
            "arn": "arn:aws:iam::123456789012:user/testuser",
            "userName": "testuser"
        },
        "sourceIPAddress": source_ip
    }
    if error_code:
        detail["errorCode"] = error_code
        
    return {
        "detail": detail
    }

class TestIAMCompromiseResponse:

    @patch('src.iam_compromise_response.sns')
    @patch('src.iam_compromise_response.cloudtrail')
    @patch('src.iam_compromise_response.iam')
    def test_lambda_handler_ignored_event(self, mock_iam, mock_ct, mock_sns):
        event = make_event("DescribeInstances")
        res = resp.lambda_handler(event, {})
        assert res['statusCode'] == 200
        assert 'Non-IAM event ignored' in res['body']

    @patch('src.iam_compromise_response.sns')
    @patch('src.iam_compromise_response.cloudtrail')
    @patch('src.iam_compromise_response.iam')
    def test_lambda_handler_low_risk(self, mock_iam, mock_ct, mock_sns):
        # CreateUser is +3. If timing not suspicious, risk < 7
        event = make_event("CreateUser", source_ip="known_ip")
        
        # Format for lookup_events is list of objects with CloudTrailEvent as string
        ct_event = {'sourceIPAddress': 'known_ip'}
        mock_ct.lookup_events.return_value = {
            'Events': [{'CloudTrailEvent': json.dumps(ct_event)}]
        }
        res = resp.lambda_handler(event, {})
        assert res['statusCode'] == 200
        assert 'Low-risk' in res['body']

    @patch('src.iam_compromise_response.is_suspicious_timing')
    @patch('src.iam_compromise_response.sns')
    @patch('src.iam_compromise_response.cloudtrail')
    @patch('src.iam_compromise_response.iam')
    def test_lambda_handler_high_risk(self, mock_iam, mock_ct, mock_sns, mock_timing):
        mock_timing.return_value = True # +2
        # DeleteUser (Admin) +5, error_code +2, unknown IP +3, timing +2 = 12 capped at 10
        event = make_event("DeleteUser", source_ip="unknown_ip", error_code="AccessDenied")
        
        # mock cloudtrail so it looks like "unknown_ip" is not in history
        ct_event = {'sourceIPAddress': 'known_ip', 'errorCode': 'AccessDenied'}
        mock_ct.lookup_events.return_value = {
            'Events': [{'CloudTrailEvent': json.dumps(ct_event)}]
        }
        
        mock_iam.list_access_keys.return_value = {
            'AccessKeyMetadata': [{'AccessKeyId': 'AKIA123', 'Status': 'Active'}]
        }
        mock_iam.list_groups_for_user.return_value = {
            'Groups': [{'GroupName': 'Administrators'}]
        }
        mock_iam.list_mfa_devices.return_value = {'MFADevices': []}

        res = resp.lambda_handler(event, {})
        assert res['statusCode'] == 200
        assert 'response executed' in res['body']
        
        # Verify quarantine actions
        mock_iam.update_access_key.assert_called_once_with(
            UserName="testuser", AccessKeyId="AKIA123", Status="Inactive"
        )
        mock_iam.remove_user_from_group.assert_called_once_with(
            GroupName="Administrators", UserName="testuser"
        )
        mock_sns.publish.assert_called_once()

    def test_lambda_handler_exception(self):
        with patch('src.iam_compromise_response.calculate_risk_score', side_effect=Exception("Test Error")):
            res = resp.lambda_handler(make_event("CreateUser"), {})
            assert res['statusCode'] == 500
            assert 'Test Error' in res['body']

    @patch('src.iam_compromise_response.datetime')
    def test_timing_suspicious(self, mock_dt):
        mock_dt.now.return_value.hour = 2
        assert resp.is_suspicious_timing() is True
        mock_dt.now.return_value.hour = 12
        assert resp.is_suspicious_timing() is False

    @patch('src.iam_compromise_response.cloudtrail')
    def test_investigate_and_cloudtrail_exceptions(self, mock_ct):
        mock_ct.lookup_events.side_effect = Exception("API")
        
        # investigate_compromise catches exceptions but sub-methods suppress them and return defaults
        res = resp.investigate_compromise("user", "arn", "evt", "1.1")
        assert res['concurrent_sessions'] == 0
        assert res['failed_login_attempts'] == 0
        assert res['recent_activity_count'] == 0
        
        assert resp.is_unusual_source_ip("ip", {}) is False
        assert resp.get_user_recent_activity("u") == []
        assert resp.count_failed_logins("u") == 0
        assert resp.check_concurrent_sessions("u") == 0
        
        # Test investigate_compromise exception explicitly
        with patch('src.iam_compromise_response.get_user_recent_activity', side_effect=Exception("API")):
            assert resp.investigate_compromise("user", "arn", "evt", "1.1") == {}

    @patch('src.iam_compromise_response.get_user_recent_activity', side_effect=Exception("ConcErr"))
    def test_check_concurrent_sessions_exception(self, mock_get):
        assert resp.check_concurrent_sessions("u") == 0

    @patch('src.iam_compromise_response.iam')
    @patch('src.iam_compromise_response.cloudtrail')
    @patch('src.iam_compromise_response.sns')
    def test_lambda_handler_privilege_escalation(self, mock_sns, mock_ct, mock_iam):
        # AttachRolePolicy is privilege escalation (+4) and risky (+3). Risk = 7.
        event = make_event("AttachRolePolicy", source_ip="known_ip")
        
        ct_event = {'sourceIPAddress': 'known_ip'}
        mock_ct.lookup_events.return_value = {
            'Events': [{'CloudTrailEvent': json.dumps(ct_event)}]
        }
        res = resp.lambda_handler(event, {})
        assert res['statusCode'] == 200
        assert 'response executed' in res['body']

    @patch('src.iam_compromise_response.iam')
    def test_quarantine_exceptions(self, mock_iam):
        mock_iam.list_access_keys.side_effect = Exception("K")
        resp.disable_user_access_keys("u") # shouldn't raise
        
        mock_iam.list_groups_for_user.side_effect = Exception("G")
        resp.remove_from_privileged_groups("u") # shouldn't raise
        
        mock_iam.list_mfa_devices.side_effect = Exception("M")
        resp.enforce_mfa("u") # shouldn't raise

    @patch('src.iam_compromise_response.sns')
    def test_sns_exception(self, mock_sns):
        mock_sns.publish.side_effect = Exception("S")
        resp.send_security_alert("u", "a", "e", "i", 10) # shouldn't raise
        
    @patch('src.iam_compromise_response.disable_user_access_keys', side_effect=Exception("Q"))
    def test_quarantine_if_needed_exception(self, mock_disable):
        resp.quarantine_if_needed("u", "a", 10) # shouldn't raise

    def test_is_privilege_escalation(self):
        assert resp.is_privilege_escalation("AttachUserPolicy") is True
        assert resp.is_privilege_escalation("CreateUser") is False
