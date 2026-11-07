"""Backend state conditions must prevent a second execution claim."""

import boto3
from moto import mock_aws

from src.core.approval_store import DynamoApprovalStore


@mock_aws
def test_dynamo_rejects_repeated_claims(monkeypatch):
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    boto3.resource("dynamodb").create_table(
        TableName="approvals",
        KeySchema=[{"AttributeName": "incident_id", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "incident_id", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )
    store = DynamoApprovalStore("approvals")
    store.put({"incident_id": "one", "status": "pending", "risk_score": 55.5, "snapshot": {"severity": 7.2}})
    assert store.get("one")["risk_score"] == 55.5
    assert store.get("one")["snapshot"]["severity"] == 7.2
    results = [store.transition("one", "pending", "executing") for _ in range(4)]
    assert results.count(True) == 1
    assert store.get("one")["status"] == "executing"
    assert store.transition("missing", "pending", "executing") is False
