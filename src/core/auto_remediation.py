"""
AWS SOAR — Auto-Remediation Patching
Automatically patches vulnerable packages on compromised EC2 instances
via SSM Run Command after containment is complete.
"""

import logging
from typing import Any, Dict, List, Optional

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)

# Known CVE → package mappings for auto-remediation
VULNERABILITY_PATCH_MAP: Dict[str, List[str]] = {
    "openssl": ["openssl", "libssl-dev"],
    "log4j": ["liblog4j2-java"],
    "curl": ["curl", "libcurl4"],
    "sudo": ["sudo"],
    "polkit": ["policykit-1"],
    "apache": ["apache2"],
    "nginx": ["nginx"],
    "ssh": ["openssh-server", "openssh-client"],
}


class AutoRemediation:
    """Automated vulnerability patching via SSM Run Command."""

    def __init__(self, client: Optional[Any] = None):
        self.ssm = client or boto3.client("ssm")

    def patch_instance(
        self,
        instance_id: str,
        vulnerability_keywords: List[str],
    ) -> Dict[str, Any]:
        """
        Patch an EC2 instance by upgrading packages related to
        detected vulnerabilities.

        Args:
            instance_id: The EC2 instance to patch.
            vulnerability_keywords: List of keywords from
                the vulnerability scan (e.g. ["openssl", "curl"]).

        Returns:
            Dict with patch results.
        """
        packages_to_patch: List[str] = []
        for keyword in vulnerability_keywords:
            kw = keyword.lower()
            for vuln_key, pkgs in VULNERABILITY_PATCH_MAP.items():
                if vuln_key in kw:
                    packages_to_patch.extend(pkgs)

        packages_to_patch = list(set(packages_to_patch))

        if not packages_to_patch:
            return {
                "status": "skipped",
                "instance_id": instance_id,
                "reason": "No matching packages found for given keywords.",
            }

        patch_cmd = (
            "apt-get update -qq && "
            f"apt-get install -y --only-upgrade {' '.join(packages_to_patch)}"
        )

        try:
            response = self.ssm.send_command(
                InstanceIds=[instance_id],
                DocumentName="AWS-RunShellScript",
                Parameters={"commands": [patch_cmd]},
                TimeoutSeconds=120,
                Comment=f"SOAR Auto-Remediation: patching {', '.join(packages_to_patch)}",
            )

            command_id = response["Command"]["CommandId"]
            logger.info(
                "Auto-remediation command %s sent to %s: %s",
                command_id,
                instance_id,
                packages_to_patch,
            )

            return {
                "status": "sent",
                "instance_id": instance_id,
                "command_id": command_id,
                "packages_patched": packages_to_patch,
            }

        except ClientError as exc:
            logger.error("SSM patch command failed: %s", exc)
            return {
                "status": "error",
                "instance_id": instance_id,
                "error": str(exc),
            }
