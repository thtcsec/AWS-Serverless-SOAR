from unittest.mock import MagicMock, patch

import pytest

from src.playbooks.api_gateway_abuse import APIGatewayAbusePlaybook


@pytest.fixture
def waf_abuse_event():
    return {
        "version": "0",
        "id": "12345678-1234-1234-1234-123456789012",
        "account": "123456789012",
        "time": "2023-01-01T00:00:00Z",
        "region": "us-east-1",
        "resources": [],
        "source": "aws.waf",
        "detail": {"action": "BLOCK", "httpRequest": {"clientIp": "192.168.1.100"}, "sampledRequests": []},
    }


def test_can_handle_waf_abuse(waf_abuse_event):
    playbook = APIGatewayAbusePlaybook()
    assert playbook.can_handle(waf_abuse_event) is True


def test_can_handle_invalid_source(waf_abuse_event):
    playbook = APIGatewayAbusePlaybook()
    waf_abuse_event["source"] = "aws.ec2"
    assert playbook.can_handle(waf_abuse_event) is False


def test_can_handle_invalid_event():
    playbook = APIGatewayAbusePlaybook()
    assert playbook.can_handle({"invalid": "data"}) is False


@patch("src.playbooks.api_gateway_abuse.AWSClientFacade.wafv2")
@patch.dict("os.environ", {"WAF_BLOCKLIST_IPSET_ID": "ip-set-123", "WAF_BLOCKLIST_IPSET_NAME": "soar-blocklist"})
def test_execute_success(mock_waf, waf_abuse_event):
    mock_waf_client = MagicMock()
    mock_waf.return_value = mock_waf_client

    mock_waf_client.get_ip_set.return_value = {"IPSet": {"Addresses": ["10.0.0.1/32"]}, "LockToken": "token123"}

    playbook = APIGatewayAbusePlaybook()
    playbook.wafv2 = mock_waf_client
    result = playbook.execute(waf_abuse_event)

    assert result is True
    mock_waf_client.get_ip_set.assert_called_once()
    mock_waf_client.update_ip_set.assert_called_once_with(
        Name="soar-blocklist",
        Scope="REGIONAL",
        Id="ip-set-123",
        Addresses=["10.0.0.1/32", "192.168.1.100/32"],
        LockToken="token123",
        Description="Updated by SOAR API Gateway Abuse Playbook",
    )


@patch.dict("os.environ", {"WAF_BLOCKLIST_IPSET_ID": "", "WAF_BLOCKLIST_IPSET_NAME": ""})
def test_execute_no_config(waf_abuse_event):
    playbook = APIGatewayAbusePlaybook()
    result = playbook.execute(waf_abuse_event)
    assert result is False


def test_execute_dry_run_preview(waf_abuse_event):
    waf_abuse_event["dry_run"] = True
    playbook = APIGatewayAbusePlaybook()
    result = playbook.execute(waf_abuse_event)

    assert result["mode"] == "dry_run"
    assert result["playbook"] == "APIGatewayAbuse"
    assert result["target_resource"] == "192.168.1.100"
    assert len(result["planned_actions"]) == 3
