from typing import Any

from src.core.logger import logger
from src.playbooks.api_gateway_abuse import APIGatewayAbusePlaybook
from src.playbooks.cicd_supply_chain import CICDSupplyChainPlaybook
from src.playbooks.ec2_containment import EC2ContainmentPlaybook
from src.playbooks.eks_pod_isolation import EKSPodIsolationPlaybook
from src.playbooks.iam_compromise import IAMCompromisePlaybook
from src.playbooks.ransomware_response import RansomwareResponsePlaybook
from src.playbooks.rds_compromise import RDSCompromisePlaybook
from src.playbooks.registry import registry
from src.playbooks.s3_exfiltration import S3ExfiltrationPlaybook

# Register all playbooks on startup
registry.register(EC2ContainmentPlaybook())
registry.register(S3ExfiltrationPlaybook())
registry.register(IAMCompromisePlaybook())
registry.register(RDSCompromisePlaybook())
registry.register(EKSPodIsolationPlaybook())
registry.register(CICDSupplyChainPlaybook())
registry.register(APIGatewayAbusePlaybook())
registry.register(RansomwareResponsePlaybook())


def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """Entry point for AWS Lambda to trigger the SOAR Engine."""
    logger.info("Initializing SOAR Engine processing...")

    try:
        # Pass the raw event dict to the registry.
        # The registry will let each Playbook determine if it can `can_handle` the event
        # and validate the schema using Pydantic implicitly.
        result = registry.dispatch(event)

        if isinstance(result, dict):
            logger.info("SOAR Playbook preview generated successfully.")
            return {"statusCode": 200, "body": result}

        if result:
            logger.info("SOAR Playbook executed successfully.")
            return {"statusCode": 200, "body": "Remediation Successful"}

        logger.info("Event ignored or no applicable playbook found.")
        return {"statusCode": 200, "body": "Event Ignored"}

    except Exception as e:
        logger.error(f"Critical Engine Failure: {str(e)}")
        return {"statusCode": 500, "body": "Internal Server Error"}
