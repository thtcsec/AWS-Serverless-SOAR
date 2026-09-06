# Migration guide — v1 → v2 (AWS Serverless SOAR)

## Breaking changes

| Area | v1 | v2 |
|------|----|----|
| Lambda handler (lab zip) | `handlers.lambda_handler` | `src.handlers.lambda_handler` |
| Package layout | often `src/` flat zip | `src/` package inside zip + pip deps (`build_lambda_package.ps1`) |
| SQS buffer | may start Step Functions | calls `handlers.handle_event()` / pipeline |
| Mid-risk incidents | notify only | persist pending + Slack buttons / API resume |

## Upgrade steps

1. Pull tag `v2.0.0` (or download release assets).
2. Rebuild Lambda package:
   ```powershell
   .\scripts\build_lambda_package.ps1
   ```
3. `terraform apply` (lab) — confirm handler and `LAB_MOCK_INTEL` / Slack webhook SSM.
4. (Optional production) Set:
   - `APPROVAL_STORE=dynamodb` + `APPROVAL_TABLE=...`
   - `SLACK_SIGNING_SECRET` + Interactivity URL → `slack_interactions.lambda_handler`
5. Re-test dry-run GuardDuty event, then mid-score path with:
   ```json
   {"approval_action":"approve","incident_id":"<id>"}
   ```

## Compatibility

- Playbook names and scoring formula are unchanged for high-severity auto-isolate paths.
- Legacy Step Functions Terraform modules, if present, are **not** the business spine — leave disabled unless you know you need them.
