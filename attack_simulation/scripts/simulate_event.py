import json
import argparse
from datetime import UTC, datetime

from src.handlers import handle_event


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
            "service": {"resourceRole": "TARGET", "action": {}},
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
        mock_event = {
            "source": "aws.s3",
            "detail": {
                "eventName": "GetObject",
                "requestParameters": {"bucketName": "simulated-bucket"},
                "userIdentity": {"arn": "arn:aws:iam::123456789012:user/attacker"},
                "sourceIPAddress": "198.51.100.1",
            },
        }

    elif scenario == "apigateway_abuse":
        mock_event = {
            "source": "aws.waf",
            "time": datetime.now(UTC).isoformat() + "Z",
            "detail": {
                "clientIp": "198.51.100.123",
                "eventName": "WAFBlock",
                "sampledRequests": [
                    {"request": {"method": "GET", "uri": "/api/admin", "headers": [{"name": "user-agent", "value": "bot"}]}}
                ],
            },
        }

    elif scenario == "eks_compromise":
        mock_event["detail"]["type"] = "EKS:Runtime/CryptoMinerExecuted"
        mock_event["detail"]["resource"] = {
            "eksClusterDetails": {"name": "mock-cluster"},
            "kubernetesDetails": {"kubernetesWorkloadDetails": {"namespace": "default", "name": "mock-pod"}},
        }

    elif scenario == "iam_compromise":
        mock_event = {
            "source": "aws.iam",
            "detail": {
                "eventName": "CreateAccessKey",
                "userIdentity": {"userName": "compromised-user"},
                "sourceIPAddress": "198.51.100.1",
            },
        }

    print("Simulating event submission to unified pipeline...")
    response = handle_event(mock_event)
    print(f"Pipeline Response: {json.dumps(response, indent=2)}")

    resource_id = "N/A"
    detail = mock_event.get("detail", {})
    if detail.get("resources"):
        resource_id = detail["resources"][0].get("instanceDetails", {}).get("instanceId", "N/A")
    elif detail.get("requestParameters", {}).get("bucketName"):
        resource_id = detail["requestParameters"]["bucketName"]
    elif detail.get("userIdentity", {}).get("userName"):
        resource_id = detail["userIdentity"]["userName"]
    elif detail.get("clientIp"):
        resource_id = detail["clientIp"]

    log_file = "audit.log"
    with open(log_file, "a", encoding="utf-8") as f:
        f.write(
            json.dumps(
                {
                    "timestamp": datetime.now(UTC).isoformat(),
                    "action": f"PLAYBOOK_TRIGGERED: {scenario}",
                    "resource_id": resource_id,
                    "actor": "AWS_SIMULATOR",
                    "success": response.get("statusCode") == 200,
                    "details": response,
                }
            )
            + "\n"
        )

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--scenario", type=str, default="ransomware", help="Scenario to simulate")
    args = parser.parse_args()
    simulate_event(args.scenario)
