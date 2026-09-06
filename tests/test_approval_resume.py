"""Human approval persist + resume path."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from src.core.approval_store import MemoryApprovalStore, build_pending_record
from src.core.event_normalizer import UnifiedIncident
from src.core.pipeline import IncidentPipeline
from src.playbooks.registry import PlaybookRegistry


def _incident() -> UnifiedIncident:
    return UnifiedIncident(
        incident_id="inc-approve-1",
        platform="aws",
        severity="MEDIUM",
        action="CreateAccessKey",
        resource="arn:aws:iam::123:user/alice",
        resource_type="iam_user",
        raw_event_type="IAMCloudTrailEvent",
        decision="REQUIRE_APPROVAL",
        risk_score=55.0,
        raw_event={"source": "aws.iam", "detail": {"eventName": "CreateAccessKey"}},
    )


@patch("src.core.pipeline.SlackNotifier")
def test_request_approval_persists_and_notifies(mock_slack_cls):
    store = MemoryApprovalStore()
    registry = PlaybookRegistry()
    pipe = IncidentPipeline(registry=registry, approval_store=store)
    mock_slack_cls.return_value.send_interactive_approval.return_value = {"notification_sent": True}

    inc = _incident()
    pipe._request_approval(inc, {"summary": "needs review", "decision": "REQUIRE_APPROVAL"})

    pending = store.get("inc-approve-1")
    assert pending is not None
    assert pending["status"] == "pending"
    mock_slack_cls.return_value.send_interactive_approval.assert_called_once()


def test_resume_reject():
    store = MemoryApprovalStore()
    store.put(
        build_pending_record(
            incident_id="inc-approve-1",
            raw_event={"source": "aws.iam"},
            incident_snapshot=_incident().model_dump(exclude={"raw_event"}),
            score_result={},
        )
    )
    pipe = IncidentPipeline(registry=PlaybookRegistry(), approval_store=store)
    result = pipe.resume_approval(incident_id="inc-approve-1", action="reject", actor="analyst")
    assert result["statusCode"] == 200
    assert result["body"]["status"] == "rejected"
    assert store.get("inc-approve-1")["status"] == "rejected"


def test_resume_approve_dispatches_playbook():
    store = MemoryApprovalStore()
    inc = _incident()
    store.put(
        build_pending_record(
            incident_id=inc.incident_id,
            raw_event=inc.raw_event,
            incident_snapshot=inc.model_dump(exclude={"raw_event"}),
            score_result={},
        )
    )

    playbook = MagicMock()
    playbook.can_handle.return_value = True
    playbook.execute.return_value = {"status": "ok", "mode": "dry_run"}

    registry = PlaybookRegistry()
    registry.register(playbook)
    # PlaybookRegistry may use different API — check dispatch
    pipe = IncidentPipeline(registry=registry, approval_store=store)

    with patch.object(pipe._registry, "dispatch", return_value={"status": "executed", "ok": True}) as mock_dispatch:
        result = pipe.resume_approval(incident_id=inc.incident_id, action="approve", actor="slack:alice")
        assert result["statusCode"] == 200
        mock_dispatch.assert_called_once()
        called_incident = mock_dispatch.call_args[0][0]
        assert called_incident.decision == "AUTO_ISOLATE"
        assert called_incident.pipeline_options.get("approved_by") == "slack:alice"
    assert store.get(inc.incident_id)["status"] == "executed"


def test_process_approval_action_envelope():
    store = MemoryApprovalStore()
    store.put(
        build_pending_record(
            incident_id="inc-approve-1",
            raw_event={"source": "aws.iam"},
            incident_snapshot=_incident().model_dump(exclude={"raw_event"}),
            score_result={},
        )
    )
    pipe = IncidentPipeline(registry=PlaybookRegistry(), approval_store=store)
    result = pipe.process({"approval_action": "reject", "incident_id": "inc-approve-1", "actor": "api"})
    assert result["body"]["status"] == "rejected"
