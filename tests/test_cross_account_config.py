import os
from unittest.mock import MagicMock, patch

import pytest

from src.cross_account.cross_account_responder import CrossAccountResponder


@patch("src.cross_account.cross_account_responder.boto3.client")
def test_cross_account_map_from_json(mock_boto_client):
    mock_boto_client.return_value = MagicMock()
    payload = '{"prod":{"account_id":"123456789012","role_name":"soar-role-prod"}}'
    with patch.dict(
        os.environ,
        {
            "CROSS_ACCOUNT_MAP": payload,
            "CROSS_ACCOUNT_STRICT_CONFIG": "true",
        },
        clear=False,
    ):
        responder = CrossAccountResponder()
    assert responder.account_configs["prod"]["account_id"] == "123456789012"
    assert responder.account_configs["prod"]["role_name"] == "soar-role-prod"


@patch("src.cross_account.cross_account_responder.boto3.client")
def test_cross_account_strict_validation_raises(mock_boto_client):
    mock_boto_client.return_value = MagicMock()
    payload = '{"dev":{"account_id":"bad-id","role_name":"soar-role"}}'
    with patch.dict(
        os.environ,
        {
            "CROSS_ACCOUNT_MAP": payload,
            "CROSS_ACCOUNT_STRICT_CONFIG": "true",
        },
        clear=False,
    ):
        with pytest.raises(ValueError):
            CrossAccountResponder()
