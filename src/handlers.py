"""
AWS SOAR Engine — Single Production Entry Point

All security events MUST flow through handle_event().
Lambda transport adapters may live in entrypoint.py or call handle_event directly.
"""

from __future__ import annotations

import logging
from typing import Any

from src.core.pipeline import IncidentPipeline
from src.playbooks.api_gateway_abuse import APIGatewayAbusePlaybook
from src.playbooks.cicd_supply_chain import CICDSupplyChainPlaybook
from src.playbooks.ec2_containment import EC2ContainmentPlaybook
from src.playbooks.eks_pod_isolation import EKSPodIsolationPlaybook
from src.playbooks.iam_compromise import IAMCompromisePlaybook
from src.playbooks.ransomware_response import RansomwareResponsePlaybook
from src.playbooks.rds_compromise import RDSCompromisePlaybook
from src.playbooks.registry import PlaybookRegistry
from src.playbooks.s3_exfiltration import S3ExfiltrationPlaybook

logger = logging.getLogger("aws-soar.handlers")

registry = PlaybookRegistry()
registry.register(EC2ContainmentPlaybook())
registry.register(S3ExfiltrationPlaybook())
registry.register(IAMCompromisePlaybook())
registry.register(RDSCompromisePlaybook())
registry.register(EKSPodIsolationPlaybook())
registry.register(CICDSupplyChainPlaybook())
registry.register(APIGatewayAbusePlaybook())
registry.register(RansomwareResponsePlaybook())

pipeline = IncidentPipeline(registry=registry)


def handle_event(event_data: dict[str, Any]) -> dict[str, Any]:
    """
    Canonical SOAR entry point.

    Pipeline: Event → Normalize → Correlate → Score → Decision → Playbook → Audit
    """
    logger.info("Processing event through unified incident pipeline")
    return pipeline.process(event_data)


def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """AWS Lambda transport adapter — delegates to handle_event()."""
    try:
        return handle_event(event)
    except Exception as exc:
        logger.error(f"Critical Engine Failure: {exc}")
        return {"statusCode": 500, "body": "Internal Server Error"}
