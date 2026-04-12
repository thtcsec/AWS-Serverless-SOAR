import json
import argparse
from datetime import UTC, datetime

from src.handlers import lambda_handler

def simulate_event(scenario: str):
    print(f"Simulating event for scenario: {scenario}")
    
    mock_event = {
        "version": "0",
        "id": "simulated-event-id",
        "detail-type": "GuardDuty Finding",
        "source": "aws.guardduty",
        "account": "123456789012",
        "time": datetime.now(UTC).isoformat() + "Z",
        "region": "us-east-1",
        "resources": [],
        "detail": {
            "schemaVersion": "2.0",
            "accountId": "123456789012",
            "region": "us-east-1",
            "partition": "aws",
            "id": "1234567890",
            "arn": "arn:aws:guardduty:us-east-1:12345:finding/1",
            "severity": 8.0,
            "createdAt": datetime.now(UTC).isoformat() + "Z",
            "updatedAt": datetime.now(UTC).isoformat() + "Z",
            "title": f"Simulated {scenario} detected",
            "description": f"Simulated {scenario} detected on resource",
        },
    }

    if scenario == "ransomware":
        mock_event["detail"]["type"] = "CryptoCurrency:EC2/BitcoinTool.B!DNS"
        mock_event["detail"]["title"] = "Crypto mining / Ransomware detected"
        mock_event["detail"]["resources"] = [{"instanceDetails": {"instanceId": "i-1234567890abcdef0"}}]
    
    elif scenario == "exfiltration":
        mock_event["detail"]["type"] = "Exfiltration:S3/AnomalousBehavior"
        mock_event["detail"]["title"] = "S3 Data Exfiltration detected"
        mock_event["detail"]["resources"] = [] # usually S3 info is in resource Role
    
    elif scenario == "apigateway_abuse":
        mock_event["source"] = "aws.apigateway"
        mock_event["detail"]["eventName"] = "Invoke"
        mock_event["detail"]["sourceIPAddress"] = "198.51.100.123"
        mock_event["detail"]["requestParameters"] = {"apiId": "mock-api"}

    elif scenario == "eks_compromise":
        mock_event["detail"]["type"] = "Execution:Kubernetes/MaliciousImage"
        mock_event["detail"]["resource"] = {
            "eksClusterDetails": {"name": "mock-cluster"},
            "kubernetesDetails": {"kubernetesWorkloadDetails": {"namespace": "default", "name": "mock-pod"}}
        }
        
    print("Simulating event submission to Lambda Handler...")
    response = lambda_handler(mock_event, None)
    print(f"Lambda Response: {json.dumps(response, indent=2)}")
    
    # Write mock audit to local file for dashboard
    log_file = "audit.log"
    with open(log_file, "a") as f:
        f.write(json.dumps({
            "timestamp": datetime.now(UTC).isoformat(),
            "action": f"PLAYBOOK_TRIGGERED: {scenario}",
            "resource_id": mock_event["detail"]["resources"][0]["instanceDetails"]["instanceId"] if mock_event["detail"]["resources"] else "N/A",
            "actor": "AWS_SIMULATOR",
            "success": response.get("statusCode") == 200,
            "details": response
        }) + "\n")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--scenario", type=str, default="ransomware", help="Scenario to simulate")
    args = parser.parse_args()
    simulate_event(args.scenario)
