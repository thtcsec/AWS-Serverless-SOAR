# 🧠 Internal Architecture: AWS Serverless SOAR

This system implements a **Decision-Based Orchestration** flow, moving beyond simple static rules to intelligent risk assessment.

## 1. Core Components

*   **GuardDuty & CloudTrail:** Telemetry sources providing security findings and API audit logs.
*   **Intelligence Layer (Multi-Intel):**
    *   **VirusTotal:** Aggregates ~70 malware engines and sandbox reports for IP reputation.
    *   **AbuseIPDB:** Real-time crowd-sourced reports on brute-force, botnets, and scanning activity.
*   **The Brain: Scoring Engine:**
    *   Dynamically calculates a `risk_score` (0-100) based on intel confidence, finding severity, and historical context.
    *   Outputs a `decision`: `IGNORE`, `REQUIRE_APPROVAL`, or `AUTO_ISOLATE`.
*   **Lambda Responders:** Stateless Python functions that execute playbooks based on the engine's decision.
*   **Integrations:** Automatic **Jira** ticket creation and **SNS** alerting for human-in-the-loop oversight.

## 2. Advanced Mitigation Flow

1.  **Enrichment:** On receiving an alert, the system immediately queries multiple Threat Intel sources.
2.  **Scoring:** The **Scoring Engine** evaluates the data. 
    *   Low risk (e.g., internal scanner) -> **Logged & Ignored**.
    *   Medium risk -> **Alert Sent (Awaiting Approval)**.
    *   High risk (e.g., verified malicious IP) -> **Automated Lockdown**.
3.  **Remediation (Auto-Isolate):**
    *   **Network Isolation:** Security Groups are locked down.
    *   **Credential Revocation:** IAM keys are deactivated instantly.
    *   **Evidence Collection:** EBS Snapshots are captured for forensics.
4.  **Audit:** A full trace is sent to Jira with the attached Intel reports for verification.

## 3. Why Serverless?
*   **Cost:** You don't pay for these "Robots" monthly. They only exist for a few seconds when a threat is detected. You only pay for those seconds.
*   **Speed:** It reacts in milliseconds, far faster than any human operator could.

---
**Summary:** You don't need to know every line of Terraform or Python code. Just understand this flow, and you can confidently explain the power of this "Self-Healing Infrastructure" to anyone! 🚀
