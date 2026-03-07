# AWS Serverless SOAR — API & Event Reference

## Table of Contents

- [Overview](#overview)
- [Event Sources & Triggers](#event-sources--triggers)
- [Lambda Event Schemas](#lambda-event-schemas)
- [Playbook Reference](#playbook-reference)
- [Configuration Reference](#configuration-reference)
- [Custom Metrics Reference](#custom-metrics-reference)
- [Integration Endpoints](#integration-endpoints)
- [Error Codes & Responses](#error-codes--responses)

---

## Overview

The AWS Serverless SOAR Engine is an event-driven remediation platform triggered by AWS security services. It receives events via **EventBridge → SQS → Lambda** and dispatches them to the appropriate playbook for automated incident response.

**Architecture Flow:**
```
GuardDuty/CloudTrail → EventBridge → SQS → Lambda (SOAR Engine) → Playbook Execution
                                        ↓
                                      DLQ (failed events)
```

---

## Event Sources & Triggers

| Source Service | EventBridge Source | Event Type | Target Playbook |
|---|---|---|---|
| AWS GuardDuty | `aws.guardduty` | `GuardDuty Finding` | EC2ContainmentPlaybook |
| AWS CloudTrail (S3) | `aws.s3` | `GetObject`, `ListObjects`, `DownloadFile` | S3ExfiltrationPlaybook |
| AWS CloudTrail (IAM) | `aws.iam` | `CreateUser`, `CreateAccessKey`, `AddUserToGroup`, `AttachUserPolicy`, `AttachRolePolicy`, `CreateRole` | IAMCompromisePlaybook |

---

## Lambda Event Schemas

### GuardDuty Finding Event

```json
{
  "version": "0",
  "id": "event-uuid",
  "detail-type": "GuardDuty Finding",
  "source": "aws.guardduty",
  "account": "123456789012",
  "time": "2026-03-01T00:00:00Z",
  "region": "us-east-1",
  "resources": [],
  "detail": {
    "schemaVersion": "2.0",
    "accountId": "123456789012",
    "region": "us-east-1",
    "partition": "aws",
    "id": "finding-id",
    "arn": "arn:aws:guardduty:us-east-1:123456789012:finding/id",
    "type": "CryptoCurrency:EC2/BitcoinTool.B!DNS",
    "service": { "resourceRole": "TARGET" },
    "severity": 8.0,
    "createdAt": "2026-03-01T00:00:00Z",
    "updatedAt": "2026-03-01T00:00:00Z",
    "title": "Finding Title",
    "description": "Finding Description",
    "resources": [
      { "instanceDetails": { "instanceId": "i-0123456789abcdef0" } }
    ]
  }
}
```

### S3 CloudTrail Event

```json
{
  "source": "aws.s3",
  "detail": {
    "eventName": "GetObject",
    "requestParameters": {
      "bucketName": "target-bucket"
    },
    "userIdentity": {
      "arn": "arn:aws:iam::123456789012:user/attacker"
    },
    "sourceIPAddress": "198.51.100.1"
  }
}
```

### IAM CloudTrail Event

```json
{
  "source": "aws.iam",
  "detail": {
    "eventName": "CreateAccessKey",
    "userIdentity": {
      "userName": "compromised-user"
    },
    "sourceIPAddress": "198.51.100.1",
    "errorCode": null
  }
}
```

---

## Playbook Reference

### EC2ContainmentPlaybook

**Trigger:** GuardDuty finding with `EC2` in type or `resourceRole == "TARGET"`

**Actions Performed:**
1. **Network Isolation** — Swaps instance security groups to an isolation SG (no inbound/outbound)
2. **IMDSv2 Enforcement** — Sets `HttpTokens=required` to prevent SSRF via metadata
3. **Forensic Snapshot** — Creates EBS snapshots of all attached volumes with forensic tags
4. **Evidence Upload** — Uploads snapshot metadata to S3 evidence bucket (AES-KMS encrypted)
5. **Instance Stop** — Stops the compromised instance

**Required Environment Variables:**
| Variable | Description |
|---|---|
| `ISOLATION_SG_ID` | Security Group ID for network isolation |
| `EVIDENCE_BUCKET` | S3 bucket for forensic evidence (optional) |

---

### S3ExfiltrationPlaybook

**Trigger:** CloudTrail S3 event with `eventName` in `[GetObject, ListObjects, DownloadFile]`

**Actions Performed:**
1. **Block User Access** — Appends a `Deny s3:*` statement to the bucket policy for the offending user ARN
2. **Enable Protection** — Enables S3 versioning and Object Lock (Governance mode, 30-day retention)

---

### IAMCompromisePlaybook

**Trigger:** CloudTrail IAM event with `eventName` in `[CreateUser, CreateAccessKey, AddUserToGroup, AttachUserPolicy, AttachRolePolicy, CreateRole]`

**Actions Performed:**
1. **Disable Access Keys** — Iterates all access keys for the compromised user and sets `Status=Inactive`

---

## Configuration Reference

Configuration is managed via **pydantic-settings** (`SOARConfig`), reading environment variables automatically.

| Variable | Type | Default | Description |
|---|---|---|---|
| `SNS_TOPIC_ARN` | `str` | `""` | SNS topic ARN for alert notifications |
| `EXFILTRATION_THRESHOLD` | `int` | `10737418240` (10 GB) | S3 exfiltration threshold in bytes |
| `LOG_LEVEL` | `str` | `"INFO"` | Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL) |
| `EVIDENCE_BUCKET` | `str` | `""` | S3 bucket for forensic evidence storage |
| `METRICS_NAMESPACE` | `str` | `"SOAR/IncidentResponse"` | CloudWatch custom metrics namespace |

---

## Custom Metrics Reference

All metrics are emitted to **CloudWatch** under the namespace `SOAR/IncidentResponse`.

| Metric Name | Unit | Dimensions | Description |
|---|---|---|---|
| `FindingsProcessed` | Count | `Playbook` | Number of findings processed per playbook |
| `PlaybookSuccess` | Count | `Playbook` | Successful playbook executions |
| `PlaybookFailure` | Count | `Playbook` | Failed playbook executions |
| `PlaybookDuration` | Milliseconds | `Playbook` | Execution time of each playbook run |

---

## Integration Endpoints

### Slack Notifier
- **Purpose:** Sends incident alerts to a Slack channel
- **Configuration:** `SLACK_WEBHOOK_URL` environment variable
- **Payload:** JSON with incident details, severity, and remediation status

### Jira Manager
- **Purpose:** Creates Jira tickets for security incidents
- **Configuration:** `JIRA_URL`, `JIRA_PROJECT_KEY`, `JIRA_API_TOKEN` environment variables
- **Ticket Fields:** Summary, description, priority (mapped from severity), labels

### SIEM Forwarder
- **Purpose:** Forwards enriched events to external SIEM (Splunk, ELK, etc.)
- **Configuration:** `SIEM_ENDPOINT`, `SIEM_API_KEY` environment variables
- **Format:** JSON with original event + remediation actions + timestamps

---

## Error Codes & Responses

### Lambda Response Format

```json
{
  "statusCode": 200,
  "body": "Remediation Successful"
}
```

| Status Code | Body | Description |
|---|---|---|
| `200` | `Remediation Successful` | Playbook matched and executed successfully |
| `200` | `Event Ignored` | No playbook matched the event (normal for non-security events) |
| `500` | `Internal Server Error` | Unhandled exception in the SOAR engine |

### Playbook Return Values

| Return Value | Meaning |
|---|---|
| `True` | Playbook executed all remediation steps successfully |
| `False` | Playbook failed or event data was incomplete |
