"""
Durable pending-approval records for human-in-the-loop remediation.

Backends:
  APPROVAL_STORE=memory     (default — tests / single warm instance)
  APPROVAL_STORE=dynamodb   (AWS — set APPROVAL_TABLE)
  APPROVAL_STORE=firestore  (GCP — set APPROVAL_FIRESTORE_COLLECTION)
"""

from __future__ import annotations

import logging
import os
from datetime import UTC, datetime
from typing import Any

logger = logging.getLogger(__name__)

_MEMORY: dict[str, dict[str, Any]] = {}


def _now() -> str:
    return datetime.now(UTC).isoformat()


class ApprovalStore:
    """Interface for pending approval persistence."""

    def put(self, record: dict[str, Any]) -> None:
        raise NotImplementedError

    def get(self, incident_id: str) -> dict[str, Any] | None:
        raise NotImplementedError

    def update_status(self, incident_id: str, status: str, *, actor: str = "") -> dict[str, Any] | None:
        raise NotImplementedError


class MemoryApprovalStore(ApprovalStore):
    def put(self, record: dict[str, Any]) -> None:
        _MEMORY[record["incident_id"]] = dict(record)

    def get(self, incident_id: str) -> dict[str, Any] | None:
        rec = _MEMORY.get(incident_id)
        return dict(rec) if rec else None

    def update_status(self, incident_id: str, status: str, *, actor: str = "") -> dict[str, Any] | None:
        rec = _MEMORY.get(incident_id)
        if not rec:
            return None
        rec["status"] = status
        rec["updated_at"] = _now()
        if actor:
            rec["actor"] = actor
        return dict(rec)


class DynamoApprovalStore(ApprovalStore):
    def __init__(self, table_name: str) -> None:
        import boto3

        self._table = boto3.resource("dynamodb").Table(table_name)

    def put(self, record: dict[str, Any]) -> None:
        self._table.put_item(Item=record)

    def get(self, incident_id: str) -> dict[str, Any] | None:
        resp = self._table.get_item(Key={"incident_id": incident_id})
        return resp.get("Item")

    def update_status(self, incident_id: str, status: str, *, actor: str = "") -> dict[str, Any] | None:
        expr = "SET #s = :s, updated_at = :u"
        values: dict[str, Any] = {":s": status, ":u": _now()}
        names = {"#s": "status"}
        if actor:
            expr += ", actor = :a"
            values[":a"] = actor
        resp = self._table.update_item(
            Key={"incident_id": incident_id},
            UpdateExpression=expr,
            ExpressionAttributeNames=names,
            ExpressionAttributeValues=values,
            ReturnValues="ALL_NEW",
        )
        return resp.get("Attributes")


class FirestoreApprovalStore(ApprovalStore):
    def __init__(self, collection: str) -> None:
        from google.cloud import firestore  # type: ignore

        self._col = firestore.Client().collection(collection)

    def put(self, record: dict[str, Any]) -> None:
        self._col.document(record["incident_id"]).set(record)

    def get(self, incident_id: str) -> dict[str, Any] | None:
        snap = self._col.document(incident_id).get()
        return snap.to_dict() if snap.exists else None

    def update_status(self, incident_id: str, status: str, *, actor: str = "") -> dict[str, Any] | None:
        ref = self._col.document(incident_id)
        payload: dict[str, Any] = {"status": status, "updated_at": _now()}
        if actor:
            payload["actor"] = actor
        ref.update(payload)
        snap = ref.get()
        return snap.to_dict() if snap.exists else None


def get_approval_store() -> ApprovalStore:
    backend = os.environ.get("APPROVAL_STORE", "memory").lower()
    if backend == "dynamodb":
        table = os.environ.get("APPROVAL_TABLE", "")
        if not table:
            logger.warning("APPROVAL_STORE=dynamodb but APPROVAL_TABLE unset — falling back to memory")
            return MemoryApprovalStore()
        return DynamoApprovalStore(table)
    if backend == "firestore":
        collection = os.environ.get("APPROVAL_FIRESTORE_COLLECTION", "soar_pending_approvals")
        return FirestoreApprovalStore(collection)
    return MemoryApprovalStore()


def build_pending_record(
    *,
    incident_id: str,
    raw_event: dict[str, Any],
    incident_snapshot: dict[str, Any],
    score_result: dict[str, Any],
) -> dict[str, Any]:
    now = _now()
    return {
        "incident_id": incident_id,
        "status": "pending",
        "raw_event": raw_event,
        "incident_snapshot": incident_snapshot,
        "score_result": score_result,
        "created_at": now,
        "updated_at": now,
        "actor": "",
    }
