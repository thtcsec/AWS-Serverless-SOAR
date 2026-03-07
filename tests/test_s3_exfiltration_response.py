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

    @patch('src.s3_exfiltration_response.sns')
    @patch('src.s3_exfiltration_response.s3')
    def test_lambda_handler_ignored_event(self, mock_s3, mock_sns):
        # Missing bucket name
        res = resp.lambda_handler({"detail": {"eventName": "GetObject"}}, {})
        assert res['statusCode'] == 200
        assert 'Ignored non-critical event' in res['body']

        # Non S3 data event
        res = resp.lambda_handler(make_event("CreateBucket"), {})
        assert res['statusCode'] == 200

    @patch('src.s3_exfiltration_response.is_exfiltration_detected')
    @patch('src.s3_exfiltration_response.get_recent_s3_access')
    @patch('src.s3_exfiltration_response.sns')
    @patch('src.s3_exfiltration_response.s3')
    def test_lambda_handler_no_exfiltration(self, mock_s3, mock_sns, mock_recent, mock_detect):
        mock_recent.return_value = {}
        mock_detect.return_value = False
        res = resp.lambda_handler(make_event(), {})
        assert res['statusCode'] == 200
        assert 'No exfiltration detected' in res['body']

    @patch('src.s3_exfiltration_response.is_exfiltration_detected')
    @patch('src.s3_exfiltration_response.get_recent_s3_access')
    @patch('src.s3_exfiltration_response.sns')
    @patch('src.s3_exfiltration_response.s3')
    def test_lambda_handler_exfiltration_detected(self, mock_s3, mock_sns, mock_recent, mock_detect):
        mock_detect.return_value = True
        mock_recent.return_value = {'access_count': 500, 'total_bytes_downloaded': 500}
        
        # Policy mock
        mock_s3.get_bucket_policy.return_value = {'Policy': json.dumps({'Statement': []})}

        res = resp.lambda_handler(make_event(), {})
        assert res['statusCode'] == 200
        assert 'response executed' in res['body']

        mock_s3.put_bucket_policy.assert_called_once()
        mock_s3.put_bucket_versioning.assert_called_once()
        mock_s3.put_object_lock_configuration.assert_called_once()
        mock_sns.publish.assert_called_once()

    def test_lambda_handler_exception(self):
        with patch('src.s3_exfiltration_response.get_recent_s3_access', side_effect=Exception("Test Err")):
            res = resp.lambda_handler(make_event(), {})
            assert res['statusCode'] == 500
            assert 'Test Err' in res['body']

    @patch('boto3.client')
    def test_get_recent_s3_access(self, mock_boto):
        mock_ct = MagicMock()
        mock_boto.return_value = mock_ct
        
        # 1 user event matching
        events = [{'Username': 'test', 'EventName': 'GetObject'}, {'Username': 'other'}]
        mock_ct.lookup_events.return_value = {'Events': events}
        
        res = resp.get_recent_s3_access("test", "test-bucket")
        assert res['access_count'] == 1
        assert res['total_bytes_downloaded'] == 1024 * 1024
        assert len(res['events']) == 2

    @patch('boto3.client')
    def test_get_recent_s3_access_error(self, mock_boto):
        mock_boto.return_value.lookup_events.side_effect = Exception("API")
        res = resp.get_recent_s3_access("user", "bucket")
        assert res['access_count'] == 0
        assert res['total_bytes_downloaded'] == 0

    def test_estimate_download_size(self):
        assert resp.estimate_download_size([{'EventName': 'GetObject'}]) == 1024 * 1024
        assert resp.estimate_download_size([{'EventName': 'ListObjects'}]) == 0

    @patch('src.s3_exfiltration_response.datetime')
    def test_is_exfiltration_detected(self, mock_dt):
        mock_dt.now.return_value.hour = 12
        # Rule 1
        assert resp.is_exfiltration_detected({'total_bytes_downloaded': 11000000000}, 'GetObject') is True
        # Rule 2
        assert resp.is_exfiltration_detected({'access_count': 1001}, 'GetObject') is True
        # Neither (normal)
        assert resp.is_exfiltration_detected({'access_count': 10, 'total_bytes_downloaded': 100}, 'GetObject') is False
        
        # Rule 3
        mock_dt.now.return_value.hour = 2
        assert resp.is_exfiltration_detected({'access_count': 10}, 'GetObject') is True
        mock_dt.now.return_value.hour = 23
        assert resp.is_exfiltration_detected({'access_count': 10}, 'GetObject') is True

    @patch('src.s3_exfiltration_response.s3')
    def test_block_user_access_no_policy(self, mock_s3):
        import botocore.exceptions
        
        # Simulate NoSuchBucketPolicy
        err_response = {'Error': {'Code': 'NoSuchBucketPolicy', 'Message': 'Not Found'}}
        mock_s3.exceptions.ClientError = botocore.exceptions.ClientError
        mock_s3.get_bucket_policy.side_effect = botocore.exceptions.ClientError(err_response, 'GetBucketPolicy')
        
        resp.block_user_access("user_arn", "bucket_name")
        mock_s3.put_bucket_policy.assert_called_once()
        args = mock_s3.put_bucket_policy.call_args[1]
        policy = json.loads(args['Policy'])
        assert policy['Statement'][0]['Effect'] == 'Deny'
        assert policy['Statement'][0]['Principal']['AWS'] == 'user_arn'

        # Simulate existing policy WITHOUT 'Statement' key
        mock_s3.get_bucket_policy.side_effect = None
        mock_s3.get_bucket_policy.return_value = {'Policy': json.dumps({"Version": "2012-10-17"})}
        resp.block_user_access("user_arn2", "bucket_name2")

    @patch('src.s3_exfiltration_response.s3')
    def test_block_user_access_other_error(self, mock_s3):
        import botocore.exceptions
        err_response = {'Error': {'Code': 'InternalError', 'Message': 'Server Error'}}
        mock_s3.exceptions.ClientError = botocore.exceptions.ClientError
        mock_s3.get_bucket_policy.side_effect = botocore.exceptions.ClientError(err_response, 'GetBucketPolicy')
        
        # Will be caught by outer Exception handler and logged, not raised
        resp.block_user_access("u", "b")
        mock_s3.put_bucket_policy.assert_not_called()

    @patch('src.s3_exfiltration_response.s3')
    def test_enable_s3_protection(self, mock_s3):
        import botocore.exceptions
        err_response = {'Error': {'Code': 'ObjectLockConfigurationNotSupported', 'Message': 'Not Supported'}}
        mock_s3.exceptions.ClientError = botocore.exceptions.ClientError
        mock_s3.put_object_lock_configuration.side_effect = botocore.exceptions.ClientError(err_response, 'PutObjLock')
        
        resp.enable_s3_protection("bucket")
        mock_s3.put_bucket_versioning.assert_called_once()
        # Exception should be caught and logged
        
    @patch('src.s3_exfiltration_response.s3')
    def test_enable_s3_protection_other_error(self, mock_s3):
        import botocore.exceptions
        err_response = {'Error': {'Code': 'InternalError', 'Message': 'Server Error'}}
        mock_s3.exceptions.ClientError = botocore.exceptions.ClientError
        mock_s3.put_object_lock_configuration.side_effect = botocore.exceptions.ClientError(err_response, 'PutObjLock')
        
        # The inner try-except only catches ObjectLockConfigurationNotSupported, 
        # so this bubbles to outer try-except which logs it
        resp.enable_s3_protection("bucket")

    @patch('src.s3_exfiltration_response.sns')
    def test_send_alert(self, mock_sns):
        resp.send_exfiltration_alert("b", "u", "ip", {})
        mock_sns.publish.assert_called_once()
        
        mock_sns.publish.side_effect = Exception("S")
        resp.send_exfiltration_alert("b", "u", "ip", {}) # shouldn't raise
