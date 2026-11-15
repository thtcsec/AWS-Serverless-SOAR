"""Durable event claims. Uncertain executions require review instead of automatic replay."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from .approval_store import ApprovalStore, positive_seconds


def elapsed_seconds(record: dict[str, Any]) -> float:
    try:
        updated = datetime.fromisoformat(record["updated_at"])
        return (datetime.now(UTC) - updated).total_seconds()
    except (KeyError, ValueError, TypeError):
        return float("inf")


class EventGuard:
    def __init__(self, store: ApprovalStore) -> None:
        self.store = store

    def run(self, event: dict[str, Any], process: Callable[[dict[str, Any]], dict[str, Any]]) -> dict[str, Any]:
        if (
            event.get("dry_run")
            or event.get("preview_only")
            or event.get("execution_mode") == "dry_run"
            or str(event.get("approval_action", "")).lower() in {"approve", "reject", "status"}
        ):
            return process(event)
        payload = json.dumps(event, sort_keys=True, separators=(",", ":"), allow_nan=False)
        key = "event:" + hashlib.sha256(payload.encode()).hexdigest()
        now = datetime.now(UTC).isoformat()
        if not self.store.create_once(
            {
                "incident_id": key,
                "status": "processing",
                "created_at": now,
                "updated_at": now,
            }
        ):
            record = self.store.get(key) or {}
            status = record.get("status", "unknown")
            if status == "completed":
                return {"statusCode": 200, "body": {"status": "duplicate", "event_key": key}}
            stalled = elapsed_seconds(record) >= positive_seconds("EXECUTION_TIMEOUT_SECONDS", 900)
            return {
                "statusCode": 503 if status == "processing" and not stalled else 409,
                "body": {
                    "error": "event_in_progress" if status == "processing" and not stalled else "event_requires_review",
                    "event_key": key,
                    "execution_status": "stalled" if status == "processing" and stalled else status,
                },
            }
        try:
            result = process(event)
        except Exception:
            self.store.transition(key, "processing", "failed")
            raise
        status = "completed" if result.get("statusCode", 500) < 400 else "failed"
        if not self.store.transition(key, "processing", status):
            raise RuntimeError("Unable to finalize event claim; inspect its state before retrying")
        return result
