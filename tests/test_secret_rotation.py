"""Tests for AWS Secret Rotation Manager."""
import pytest
from unittest.mock import MagicMock
from datetime import datetime, timezone, timedelta
from src.core.secret_rotation import SecretRotationManager


class TestSecretRotationManager:
    @pytest.fixture
    def ssm_client(self):
        return MagicMock()

    @pytest.fixture
    def manager(self, ssm_client):
        return SecretRotationManager(ssm_client=ssm_client)

    def test_check_key_age_fresh(self, manager, ssm_client):
        ssm_client.get_parameter.return_value = {
            "Parameter": {
                "LastModifiedDate": datetime.now(timezone.utc) - timedelta(days=10),
                "Version": 3,
            }
        }
        result = manager.check_key_age("/soar/virustotal/api_key")
        assert result["age_days"] == 10
        assert result["needs_rotation"] is False

    def test_check_key_age_stale(self, manager, ssm_client):
        ssm_client.get_parameter.return_value = {
            "Parameter": {
                "LastModifiedDate": datetime.now(timezone.utc) - timedelta(days=100),
                "Version": 1,
            }
        }
        result = manager.check_key_age("/soar/virustotal/api_key")
        assert result["age_days"] == 100
        assert result["needs_rotation"] is True

    def test_rotate_parameter(self, manager, ssm_client):
        result = manager.rotate_parameter("/soar/virustotal/api_key", "new-key-123")
        assert result is True
        ssm_client.put_parameter.assert_called_once()

    def test_rotate_parameter_failure(self, manager, ssm_client):
        ssm_client.put_parameter.side_effect = Exception("Access denied")
        result = manager.rotate_parameter("/soar/test", "value")
        assert result is False

    def test_get_rotation_report(self, manager, ssm_client):
        ssm_client.get_parameter.return_value = {
            "Parameter": {
                "LastModifiedDate": datetime.now(timezone.utc) - timedelta(days=50),
                "Version": 2,
            }
        }
        report = manager.get_rotation_report(["/soar/key1", "/soar/key2"])
        assert report["total_secrets"] == 2
        assert report["needs_rotation"] == 0

    def test_no_client_returns_error(self):
        manager = SecretRotationManager()
        result = manager.check_key_age("/soar/test")
        assert "error" in result

    def test_get_monitored_parameters(self):
        params = SecretRotationManager.get_monitored_parameters()
        assert len(params) == 5
        assert "/soar/virustotal/api_key" in params
