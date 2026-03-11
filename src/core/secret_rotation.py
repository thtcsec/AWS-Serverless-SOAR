"""
AWS SOAR — Secret Rotation Manager
Manages automatic rotation of API keys used by the SOAR platform,
including Threat Intelligence keys (VirusTotal, AbuseIPDB)
and integration secrets (Slack webhooks, Jira tokens).
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger("aws-soar.secret_rotation")


class SecretRotationManager:
    """
    Manages API key rotation via AWS Systems Manager Parameter Store
    or AWS Secrets Manager.
    """

    # Maximum age in days before a key should be rotated
    DEFAULT_MAX_AGE_DAYS = 90

    def __init__(
        self,
        ssm_client: Any = None,
        secrets_client: Any = None,
    ) -> None:
        self._ssm = ssm_client
        self._secrets = secrets_client

    def check_key_age(self, parameter_name: str) -> Dict[str, Any]:
        """Check the age of a parameter in SSM Parameter Store."""
        if not self._ssm:
            return {"error": "SSM client not configured"}

        try:
            response = self._ssm.get_parameter(
                Name=parameter_name,
                WithDecryption=False,
            )
            param = response.get("Parameter", {})
            last_modified = param.get("LastModifiedDate")

            if last_modified:
                age_days = (datetime.now(timezone.utc) - last_modified).days
            else:
                age_days = -1

            return {
                "parameter_name": parameter_name,
                "last_modified": str(last_modified),
                "age_days": age_days,
                "needs_rotation": age_days > self.DEFAULT_MAX_AGE_DAYS,
                "version": param.get("Version", 0),
            }
        except Exception as e:
            logger.error(f"Failed to check key age for {parameter_name}: {e}")
            return {"parameter_name": parameter_name, "error": str(e)}

    def rotate_parameter(
        self, parameter_name: str, new_value: str
    ) -> bool:
        """Rotate a secret in SSM Parameter Store."""
        if not self._ssm:
            return False

        try:
            self._ssm.put_parameter(
                Name=parameter_name,
                Value=new_value,
                Type="SecureString",
                Overwrite=True,
            )
            logger.info(f"Rotated parameter: {parameter_name}")
            return True
        except Exception as e:
            logger.error(f"Failed to rotate {parameter_name}: {e}")
            return False

    def get_rotation_report(
        self, parameter_names: List[str]
    ) -> Dict[str, Any]:
        """Generate a rotation status report for all monitored secrets."""
        results: List[Dict[str, Any]] = []
        needs_rotation_count = 0

        for name in parameter_names:
            status = self.check_key_age(name)
            results.append(status)
            if status.get("needs_rotation", False):
                needs_rotation_count += 1

        return {
            "total_secrets": len(parameter_names),
            "needs_rotation": needs_rotation_count,
            "max_age_policy_days": self.DEFAULT_MAX_AGE_DAYS,
            "secrets": results,
        }

    @staticmethod
    def get_monitored_parameters() -> List[str]:
        """Return the list of SOAR parameter names that should be monitored."""
        return [
            "/soar/virustotal/api_key",
            "/soar/abuseipdb/api_key",
            "/soar/slack/webhook_url",
            "/soar/jira/api_token",
            "/soar/siem/api_key",
        ]
