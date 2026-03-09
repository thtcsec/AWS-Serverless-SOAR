import json
import boto3
from datetime import datetime, timezone
from src.handlers import lambda_handler

def simulate_guardduty_event():
    """Simulate a GuardDuty finding event structure."""
    
    mock_event = {
        "version": "0",
        "id": "simulated-event-id",
        "detail-type": "GuardDuty Finding",
        "source": "aws.guardduty",
        "account": "123456789012",
        "time": datetime.now(timezone.utc).isoformat() + "Z",
        "region": "us-east-1",
        "resources": [],
        "detail": {
            "schemaVersion": "2.0",
            "accountId": "123456789012",
            "region": "us-east-1",
            "partition": "aws",
            "id": "1234567890",
            "arn": "arn:aws:guardduty:us-east-1:12345:finding/1",
            "type": "CryptoCurrency:EC2/BitcoinTool.B!DNS",
            "service": {"resourceRole": "TARGET"},
            "severity": 8.0,
            "createdAt": datetime.now(timezone.utc).isoformat() + "Z",
            "updatedAt": datetime.now(timezone.utc).isoformat() + "Z",
            "title": "Crypto mining detected",
            "description": "Simulated bitcoin mining detected",
            "resources": [{"instanceDetails": {"instanceId": "i-1234567890abcdef0"}}]
        }
    }
    
    print("Simulating event submission to Lambda Handler...")
    response = lambda_handler(mock_event, None)
    print(f"Lambda Response: {json.dumps(response, indent=2)}")

if __name__ == "__main__":
    simulate_guardduty_event()
