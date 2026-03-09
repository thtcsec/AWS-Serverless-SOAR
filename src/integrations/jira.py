import os
import json
import logging
import base64
import urllib.request

logger = logging.getLogger(__name__)

# Fetch Jira settings from environment variables
JIRA_URL = os.environ.get('JIRA_URL')
JIRA_USER = os.environ.get('JIRA_USER')
JIRA_API_TOKEN = os.environ.get('JIRA_API_TOKEN')
JIRA_PROJECT_KEY = os.environ.get('JIRA_PROJECT_KEY', 'SEC')


def create_jira_issue(instance_id: str, finding_type: str, severity: float, action_taken: str):
    """
    Creates an incident tracking ticket in Jira to document the SOAR finding.
    Returns the Jira Issue Key if successful, else None.
    """
    jira_url = JIRA_URL
    jira_user = JIRA_USER
    jira_token = JIRA_API_TOKEN
    
    if not jira_url or not jira_user or not jira_token:
        logger.warning("Jira config incomplete (missing JIRA_URL, JIRA_USER, JIRA_API_TOKEN). Skipping Jira Ticket.")
        return None

    # We assume Jira Cloud API v2
    url = f"{jira_url.rstrip('/')}/rest/api/2/issue"
    
    # HTTP Basic Authentication encoding
    auth_str = f"{jira_user}:{jira_token}"
    base64_auth = base64.b64encode(auth_str.encode('ascii')).decode('ascii')
    
    headers = {
        "Authorization": f"Basic {base64_auth}",
        "Content-Type": "application/json",
        "Accept": "application/json"
    }
    
    description = (
        f"Automated Security Incident Response triggered by Serverless SOAR.\n\n"
        f"*Instance ID:* {instance_id}\n"
        f"*Finding Type:* {finding_type}\n"
        f"*Severity Score:* {severity}\n\n"
        f"*Response Actions Initiated Automatically:*\n{action_taken}\n\n"
        f"Please review the forensic snapshots for further investigation."
    )
    
    payload = {
        "fields": {
            "project": {"key": JIRA_PROJECT_KEY},
            "summary": f"[SOAR Alert] Threat Detected on {instance_id}",
            "description": description,
            "issuetype": {"name": "Bug"}
        }
    }
    
    req = urllib.request.Request(
        url, 
        data=json.dumps(payload).encode('utf-8'), 
        headers=headers, 
        method='POST'
    )
    
    try:
        with urllib.request.urlopen(req) as response:  # nosec B310
            res_data = response.read().decode('utf-8')
            res_json = json.loads(res_data)
            issue_key = res_json.get('key')
            logger.info(f"Successfully created Jira Issue: {issue_key}")
            return issue_key
    except Exception as e:
        logger.error(f"Failed to create Jira Issue: {str(e)}")
        return None
