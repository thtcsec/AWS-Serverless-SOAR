import os
import json
import pytest
from unittest.mock import patch, MagicMock

# Set environment variables required for initialization
os.environ['SNS_TOPIC_ARN'] = 'arn:aws:sns:us-east-1:123456789012:security-alerts'

import src.iam_compromise_response as resp

class TestIAMCompromiseResponse:

    @patch('src.iam_compromise_response.integrations.ScoringEngine')
    @patch('src.iam_compromise_response.integrations.ThreatIntelService')
    @patch('src.iam_compromise_response.sns')
    @patch('src.iam_compromise_response.cloudtrail')
    @patch('src.iam_compromise_response.iam')
    def test_lambda_handler_ignored_event(self, mock_iam, mock_ct, mock_sns, mock_intel, mock_scoring):
        mock_intel.return_value.get_ip_report.return_value = {"vt": {"malicious": 0}, "abuse": {"score": 0}}
        mock_scoring.return_value.calculate_risk_score.return_value = {"decision": "IGNORE", "risk_score": 0}
        
        event = {"detail": {"eventName": "DescribeInstances"}}
        res = resp.lambda_handler(event, {})
        assert res['statusCode'] == 200
        assert 'Non-IAM event ignored' in res['body']

    @patch('src.iam_compromise_response.integrations.ScoringEngine')
    @patch('src.iam_compromise_response.integrations.ThreatIntelService')
    @patch('src.iam_compromise_response.sns')
    @patch('src.iam_compromise_response.cloudtrail')
    @patch('src.iam_compromise_response.iam')
    def test_lambda_handler_low_risk(self, mock_iam, mock_ct, mock_sns, mock_intel, mock_scoring):
        mock_intel.return_value.get_ip_report.return_value = {"vt": {"malicious": 0}, "abuse": {"score": 0}}
        mock_scoring.return_value.calculate_risk_score.return_value = {"decision": "IGNORE", "risk_score": 1.0}
        
        detail = {
            "eventName": "CreateUser",
            "userIdentity": {"userName": "testuser", "arn": "arn:user"},
            "sourceIPAddress": "1.1.1.1"
        }
        mock_ct.lookup_events.return_value = {'Events': []}
        
        res = resp.lambda_handler({"detail": detail}, {})
        assert res['statusCode'] == 200
        assert 'Ignored low risk' in res['body']

    @patch('src.iam_compromise_response.integrations.ScoringEngine')
    @patch('src.iam_compromise_response.integrations.ThreatIntelService')
    @patch('src.iam_compromise_response.is_suspicious_timing')
    @patch('src.iam_compromise_response.sns')
    @patch('src.iam_compromise_response.cloudtrail')
    @patch('src.iam_compromise_response.iam')
    def test_lambda_handler_high_risk(self, mock_iam, mock_ct, mock_sns, mock_timing, mock_intel, mock_scoring):
        mock_intel.return_value.get_ip_report.return_value = {"vt": {"malicious": 10}}
        mock_scoring.return_value.calculate_risk_score.return_value = {"decision": "AUTO_ISOLATE", "risk_score": 90.0}
        mock_timing.return_value = True
        
        detail = {
            "eventName": "DeleteUser",
            "userIdentity": {"userName": "testuser", "arn": "arn:user"},
            "sourceIPAddress": "9.9.9.9",
            "errorCode": "AccessDenied"
        }
        mock_ct.lookup_events.return_value = {'Events': []}
        mock_iam.list_access_keys.return_value = {'AccessKeyMetadata': [{'AccessKeyId': 'K1', 'Status': 'Active'}]}
        mock_iam.list_groups_for_user.return_value = {'Groups': [{'GroupName': 'Administrators'}]}
        mock_iam.list_mfa_devices.return_value = {'MFADevices': []}

        res = resp.lambda_handler({"detail": detail}, {})
        assert res['statusCode'] == 200
        assert 'response executed' in res['body']
        
        assert mock_iam.update_access_key.called
        assert mock_iam.remove_user_from_group.called
        assert mock_sns.publish.called

    @patch('src.iam_compromise_response.sns')
    def test_sns_exception_handled(self, mock_sns):
        mock_sns.publish.side_effect = Exception("SNS Error")
        # Testing send_security_alert directly
        resp.send_security_alert("u", "arn", "event", "ip", approved=False)
        # Should NOT raise exception if handled
