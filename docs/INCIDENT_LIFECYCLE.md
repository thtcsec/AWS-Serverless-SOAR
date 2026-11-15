# Event Deduplication and Approval Lifecycle

## Behavior

The pipeline claims an event before normalization, notification, or remediation.
The key is `event:` followed by SHA-256 of its canonical JSON payload (sorted keys).
Redelivery of the same payload returns `200 / duplicate` after successful processing.
Concurrent delivery returns `503 / event_in_progress` while the first worker is active.
Failed or stalled claims return `409 / event_requires_review`; they never automatically
replay a possibly partially executed containment action.

Different payloads are independent events. Producers must preserve their source event IDs
and timestamps across redelivery and provide distinct IDs or timestamps for new occurrences.
This is event-level deduplication, not a transaction across cloud remediation APIs.
Dry-run and preview requests do not consume live event claims.

Claims use the configured approval store under a separate `event:` key namespace.
DynamoDB uses conditional writes and strongly consistent reads; Firestore uses document
creation preconditions and transactions. Production must configure `APPROVAL_STORE`
to a durable backend. In memory mode, event claims last only for one pipeline instance.
Event claims have no automatic deletion; deleting them removes deduplication protection.

## Approval Deadlines and Execution Status

- `APPROVAL_TTL_SECONDS`: positive integer, default `3600`. Stored as an immutable
  Unix `expires_at` deadline when creating each pending approval.
- `EXECUTION_TIMEOUT_SECONDS`: positive integer, default `900`. Used to report
  an active event or approval as stalled based on its last update.

Expired approval requests cannot start remediation. The deadline is checked again
inside the atomic claim operation. Legacy records without a deadline are treated as
expired; review and create a fresh approval instead of reviving an old request.

Inspect an approval through the canonical handler:

```json
{"approval_action": "status", "incident_id": "<incident-id>"}
```

The result includes `status`, `expires_at`, and `requires_review`. Stalled status
is observational: it does not reclaim ownership from a worker that might still be running.
Failed or stalled executions require checking the audit trail, source resource, and
provider operation status. Preserve the original records. Resume remaining actions through
a reviewed response plan, not by blindly retrying the original event.

The stalled threshold should exceed the maximum expected execution duration.
There is no background sweeper or heartbeat in this version; status is evaluated on query
or redelivery. Queue retry and DLQ policies remain responsible for delivery scheduling.

## Validation

Regression tests cover concurrent delivery, duplicate pending approvals, changed events,
preview isolation, failed and stalled claims, approval expiry, and backend preconditions.
Run `scripts/check.ps1` or `bash scripts/check.sh` with the configured virtualenv.
