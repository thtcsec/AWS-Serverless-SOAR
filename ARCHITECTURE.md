# 🧠 Internal Architecture: AWS Serverless SOAR

This system implements a **Decision-Based Orchestration** flow with multi-layer intelligence, AI/ML anomaly detection, and granular containment strategy.

## 1. Core Components

*   **Detection Layer (GuardDuty, CloudTrail, Security Hub, Inspector, Macie, VPC Flow Logs):** Telemetry sources providing real-time security findings and API audit logs.
*   **Intelligence & Scoring Layer:**
    *   **VirusTotal:** Aggregates ~70 malware engines and sandbox reports for IP reputation.
    *   **AbuseIPDB:** Real-time crowd-sourced reports on brute-force, botnets, and scanning activity.
    *   **ML Anomaly Detection (Isolation Forest):** Behavioral analysis using feature vectors (`hour_of_day`, `day_of_week`, `ip_reputation_score`, `action_risk_level`, `request_frequency`) with Z-Score fallback.
    *   **Scoring Engine (0-100):** Dynamically calculates `risk_score` combining threat intel confidence, finding severity, and anomaly boost (+15). Outputs: `IGNORE (<40)`, `REQUIRE_APPROVAL (40-70)`, `AUTO_ISOLATE (>70)`.
*   **SOAR Platform:**
    *   **Event Routing:** EventBridge → SQS (optional buffer + DLQ) for resilient event delivery.
    *   **Unified Pipeline:** AWS Lambda (`src.handlers.lambda_handler` → `handle_event()` → `IncidentPipeline`) — normalize, correlate, score, dispatch playbook, audit.
    *   **Human Approval:** Slack/Jira integration when `PolicyEngine` returns `REQUIRE_APPROVAL`. Pending incidents are persisted (`APPROVAL_STORE=memory|dynamodb`) and resumed via Slack Block Kit buttons (`soar_approve` / `soar_reject`) or API envelope `{"approval_action":"approve","incident_id":"..."}`. Interactivity URL → `slack_interactions` handler (+ `SLACK_SIGNING_SECRET`).
    *   **Event Normalization:** Converts native events into `UnifiedIncident` schema for cross-cloud compatibility.
    *   **Incident Correlator:** Groups related alerts by shared IOCs (IP, actor, ±5 min window) to detect multi-stage campaigns.
    *   **Legacy:** Step Functions Terraform modules (if present) are transport/wiring only — not the business spine. `queue_processor` now routes SQS → `handle_event()` (no `start_execution`).
*   **Containment Hierarchy (Function > Process > Container > Permission > Network):**
    *   **Process-Level:** Kill malicious processes and quarantine files via SSM Run Command.
    *   **Container-Level:** Evict compromised EKS pods and apply quarantine network labels.
    *   **Database-Level:** Initiate RDS forensic snapshots and isolate DB security groups.
    *   **Permissions-Level:** Disable access keys, revoke sessions, attach DenyAll policy.
    *   **Network-Level:** Isolate EC2 instance via Security Group lockdown (last resort).

## 2. Response Flow

1.  **Enrichment:** On receiving an alert, the system queries multiple Threat Intel sources and runs ML anomaly detection.
2.  **Scoring:** The Scoring Engine evaluates all signals and calculates the risk score with anomaly boost.
    *   Low risk → **Logged & Ignored**.
    *   Medium risk → **Alert Sent (Awaiting Human Approval)**.
    *   High risk → **Automated Containment** (process kill → credential revocation → network isolation).
3.  **Remediation:**
    *   **Process Containment:** Kill suspicious processes (xmrig, cryptominer) via SSM.
    *   **Credential Revocation:** IAM keys deactivated, sessions revoked.
    *   **Network Isolation:** Security Groups locked down.
    *   **Evidence Collection:** EBS Snapshots captured for forensics.
4.  **Audit & Compliance:** All actions logged to immutable audit trail (CloudWatch Logs → S3 archival). Full trace sent to Jira for verification.

## 3. Observability & Security Hardening

*   **CloudWatch Dashboard (Terraform):** Incident volume, error rate, MTTR, SQS depth, Lambda errors, SLO/SLI metrics.
*   **CloudWatch Alarms:** Auto-alert on Lambda errors and DLQ backlogs.
*   **Secret Rotation:** 90-day rotation policy for all API keys via SSM Parameter Store.
*   **Audit Logger:** Structured audit trail for every SOAR action with CloudWatch + S3 archival.

## 4. Why Serverless?
*   **Cost:** You don't pay for idle. The platform only costs ~$5-15/month for low/moderate traffic.
*   **Speed:** It reacts in milliseconds, far faster than any human operator.
*   **Scale:** Whether 1 or 1,000 incidents, AWS auto-scales Lambda and Fargate to handle them all simultaneously.

---
**Summary:** A "Self-Healing Infrastructure" with multi-layer intelligence, ML anomaly detection, and granular containment — from killing a single process to full network isolation. 🚀
