"""Shared helpers for playbook implementations."""

from __future__ import annotations

from typing import Any

from src.core.event_normalizer import EventNormalizer, UnifiedIncident


def coerce_incident(incident: UnifiedIncident | dict[str, Any]) -> UnifiedIncident:
    return EventNormalizer.ensure(incident)


def is_dry_run(incident: UnifiedIncident) -> bool:
    opts = incident.pipeline_options
    return bool(
        opts.get("dry_run") or opts.get("preview_only") or opts.get("execution_mode") == "dry_run"
    )
