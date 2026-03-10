from typing import Dict, Any
from src.core.logger import logger
from src.playbooks.registry import registry
from src.playbooks.ec2_containment import EC2ContainmentPlaybook
from src.playbooks.s3_exfiltration import S3ExfiltrationPlaybook
from src.playbooks.iam_compromise import IAMCompromisePlaybook

# Register all playbooks on startup
registry.register(EC2ContainmentPlaybook())
registry.register(S3ExfiltrationPlaybook())
registry.register(IAMCompromisePlaybook())

def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """Entry point for AWS Lambda to trigger the SOAR Engine."""
    logger.info("Initializing SOAR Engine processing...")
    
    try:
        # Pass the raw event dict to the registry. 
        # The registry will let each Playbook determine if it can `can_handle` the event
        # and validate the schema using Pydantic implicitly.
        success = registry.dispatch(event)
        
        if success:
            logger.info("SOAR Playbook executed successfully.")
            return {"statusCode": 200, "body": "Remediation Successful"}
        else:
            logger.info("Event ignored or no applicable playbook found.")
            return {"statusCode": 200, "body": "Event Ignored"}
            
    except Exception as e:
        logger.error(f"Critical Engine Failure: {str(e)}")
        return {"statusCode": 500, "body": "Internal Server Error"}
