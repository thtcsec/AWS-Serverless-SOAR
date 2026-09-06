# Changelog

All notable changes to **AWS Serverless SOAR** are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] — 2026-09-06

### Added
- Unified `IncidentPipeline` spine: normalize → correlate → score → decision → playbook → audit
- Slack **interactive approval** (Block Kit Approve/Reject) with pending-approval store (`memory` / `dynamodb`)
- Resume API envelope: `{"approval_action":"approve|reject","incident_id":"..."}`
- `slack_interactions` Lambda handler for Slack Interactivity Request URL
- Lab Lambda packaging (`scripts/build_lambda_package.ps1`) with handler `src.handlers.lambda_handler`
- Master multi-cloud architecture diagram (`images/master_architecture.png`)
- CloudWatch `PutMetricData` IAM for SOAR namespace; `LAB_MOCK_INTEL` for deterministic lab scoring
- SQS `queue_processor` routes to `handle_event()` (no Step Functions fan-out)

### Changed
- Scoring decision bands remain canonical: IGNORE &lt;40, REQUIRE_APPROVAL 40–69, AUTO_ISOLATE ≥70
- CI/CD playbook thresholds read from `ScoringEngine` constants
- Architecture docs aligned to pipeline spine; Step Functions marked legacy wiring only

### Removed / Deprecated
- Step Functions–centric hot path (modules may remain as optional infra)
- Monolith responders remain as deprecated re-exports only
- Unused deprecated diagram variants purged; legacy diagram kept for reference

### Migration
See [MIGRATION_v2.md](./MIGRATION_v2.md).

## [1.0.0] — 2026-03-11

### Added
- Initial public release: GuardDuty/CloudTrail responders, Terraform lab, playbooks, attack simulator
