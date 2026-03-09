import os
import json
import pytest
from unittest.mock import patch, MagicMock

os.environ['SNS_TOPIC_ARN'] = 'arn:aws:sns:us-east-1:123456789012:security-alerts'

import src.s3_exfiltration_response as resp

if 'SNS_TOPIC_ARN' in os.environ:
    del os.environ['SNS_TOPIC_ARN']

def make_event(event_name="GetObject", bucket_name="test-bucket", user_arn="arn:aws:iam::123:user/test"):
    return {
        "detail": {
            "eventName": event_name,
            "requestParameters": {
                "bucketName": bucket_name
            },
            "userIdentity": {
                "arn": user_arn
            },
            "sourceIPAddress": "198.51.100.1"
        }
    }

class TestS3ExfiltrationResponse:

    @patch('src.s3_exfiltration_response.integrations.ScoringEngine')
    @patch('src.s3_exfiltration_response.integrations.ThreatIntelService')
    @patch('src.s3_exfiltration_response.sns')
    @patch('src.s3_exfiltration_response.s3')
    def test_lambda_handler_ignored_event(self, mock_s3, mock_sns, mock_intel, mock_scoring):
        mock_intel.return_value.get_ip_report.return_value = {}
        mock_scoring.return_value.calculate_risk_score.return_value = {"decision": "IGNORE", "risk_score": 0, "breakdown": {}}
        # Missing bucket name
        res = resp.lambda_handler({"detail": {"eventName": "GetObject"}}, {})
        assert res['statusCode'] == 200
        assert 'Ignored non-critical event' in res['body']

        # Non S3 data event
        res = resp.lambda_handler(make_event("CreateBucket"), {})
        assert res['statusCode'] == 200

    @patch('src.s3_exfiltration_response.integrations.ScoringEngine')
    @patch('src.s3_exfiltration_response.integrations.ThreatIntelService')
    @patch('src.s3_exfiltration_response.is_exfiltration_detected')
    @patch('src.s3_exfiltration_response.get_recent_s3_access')
    @patch('src.s3_exfiltration_response.sns')
    @patch('src.s3_exfiltration_response.s3')
    def test_lambda_handler_no_exfiltration(self, mock_s3, mock_sns, mock_recent, mock_detect, mock_intel, mock_scoring):
        mock_intel.return_value.get_ip_report.return_value = {}
        mock_scoring.return_value.calculate_risk_score.return_value = {"decision": "IGNORE", "risk_score": 0, "breakdown": {}}
        mock_recent.return_value = {}
        mock_detect.return_value = False
        res = resp.lambda_handler(make_event(), {})
        assert res['statusCode'] == 200
        assert 'No exfiltration detected' in res['body']

    @patch('src.s3_exfiltration_response.integrations.ScoringEngine')
    @patch('src.s3_exfiltration_response.integrations.ThreatIntelService')
    @patch('src.s3_exfiltration_response.is_exfiltration_detected')
    @patch('src.s3_exfiltration_response.get_recent_s3_access')
    @patch('src.s3_exfiltration_response.sns')
    @patch('src.s3_exfiltration_response.s3')
    def test_lambda_handler_exfiltration_detected(self, mock_s3, mock_sns, mock_recent, mock_detect, mock_intel, mock_scoring):
        mock_intel.return_value.get_ip_report.return_value = {"vt": {"malicious": 10}}
        mock_detect.return_value = True
        mock_recent.return_value = {'access_count': 500, 'total_bytes_downloaded': 500}
        
        mock_scoring.return_value.calculate_risk_score.return_value = {
            "risk_score": 90.0,
            "decision": "AUTO_ISOLATE",
            "breakdown": {"vt_malicious": 20}
        }
        
        # Policy mock
        mock_s3.get_bucket_policy.return_value = {'Policy': json.dumps({'Statement': []})}

        res = resp.lambda_handler(make_event(), {})
        assert res['statusCode'] == 200
        assert 'response executed' in res['body']

        mock_s3.put_bucket_policy.assert_called_once()
        mock_s3.put_bucket_versioning.assert_called_once()
        mock_s3.put_object_lock_configuration.assert_called_once()
        mock_sns.publish.assert_called_once()

    @patch('src.s3_exfiltration_response.integrations.ScoringEngine')
    @patch('src.s3_exfiltration_response.integrations.ThreatIntelService')
    def test_lambda_handler_exception(self, mock_intel, mock_scoring):
        with patch('src.s3_exfiltration_response.get_recent_s3_access', side_effect=Exception("Test Err")):
            res = resp.lambda_handler(make_event(), {})
            assert res['statusCode'] == 500
            assert 'Test Err' in res['body']

    @patch('boto3.client')
    def test_get_recent_s3_access(self, mock_boto):
        mock_ct = MagicMock()
        mock_boto.return_value = mock_ct
        events = [{'Username': 'test', 'EventName': 'GetObject'}, {'Username': 'other'}]
        mock_ct.lookup_events.return_value = {'Events': events}
        
        res = resp.get_recent_s3_access("test", "test-bucket")
        assert res['access_count'] == 1
        assert res['total_bytes_downloaded'] == 1024 * 1024
