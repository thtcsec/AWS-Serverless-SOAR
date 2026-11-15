"""Redelivery must not replay containment or overwrite pending approvals."""

from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from threading import Event
from unittest.mock import Mock

import pytest

from src.core.approval_store import MemoryApprovalStore
from src.core.event_guard import EventGuard


def test_redelivery_across_workers_is_suppressed():
    store = MemoryApprovalStore(records={})
    first, second = EventGuard(store), EventGuard(store)
    process = Mock(return_value={"statusCode": 200, "body": {"status": "pending_approval"}})
    event = {"id": "finding-1", "nested": {"severity": 8}}
    assert first.run(event, process)["statusCode"] == 200
    assert second.run({"nested": {"severity": 8}, "id": "finding-1"}, process)["body"]["status"] == "duplicate"
    process.assert_called_once()


def test_simultaneous_delivery_cannot_execute_twice():
    store = MemoryApprovalStore(records={})
    started, release = Event(), Event()

    def execute(_):
        started.set()
        assert release.wait(5)
        return {"statusCode": 200}

    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(EventGuard(store).run, {"id": "one"}, execute)
        try:
            assert started.wait(5)
            assert EventGuard(store).run({"id": "one"}, execute)["statusCode"] == 503
        finally:
            release.set()
        assert first.result()["statusCode"] == 200


@pytest.mark.parametrize("throws", [False, True])
def test_uncertain_execution_requires_review(throws):
    guard = EventGuard(MemoryApprovalStore(records={}))
    process = Mock(return_value={"statusCode": 500})
    if throws:
        process.side_effect = RuntimeError("provider timeout")
        with pytest.raises(RuntimeError):
            guard.run({"id": "failed"}, process)
    else:
        assert guard.run({"id": "failed"}, process)["statusCode"] == 500
    result = guard.run({"id": "failed"}, process)
    assert result["statusCode"] == 409
    assert result["body"]["error"] == "event_requires_review"
    process.assert_called_once()


def test_stalled_claim_is_observed_without_reclaiming():
    store = MemoryApprovalStore(records={})
    guard = EventGuard(store)
    process = Mock(return_value={"statusCode": 200})
    guard.run({"id": "stalled"}, process)
    key = next(iter(store._records))
    record = store.get(key)
    record["status"] = "processing"
    record["updated_at"] = (datetime.now(UTC) - timedelta(hours=1)).isoformat()
    store.put(record)
    result = guard.run({"id": "stalled"}, process)
    assert result["body"]["execution_status"] == "stalled"
    assert store.get(key)["status"] == "processing"
    process.assert_called_once()


@pytest.mark.parametrize("options", [{"dry_run": True}, {"preview_only": True}, {"execution_mode": "dry_run"}])
def test_preview_does_not_consume_live_event(options):
    guard = EventGuard(MemoryApprovalStore(records={}))
    process = Mock(return_value={"statusCode": 200})
    guard.run({"id": "preview", **options}, process)
    guard.run({"id": "preview", **options}, process)
    guard.run({"id": "preview"}, process)
    assert process.call_count == 3


def test_changed_source_event_is_processed_independently():
    guard = EventGuard(MemoryApprovalStore(records={}))
    process = Mock(return_value={"statusCode": 200})
    guard.run({"id": "one", "severity": 7}, process)
    guard.run({"id": "one", "severity": 9}, process)
    assert process.call_count == 2
