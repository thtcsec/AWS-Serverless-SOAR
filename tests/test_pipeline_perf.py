"""Lightweight pipeline performance smoke tests (local logic only)."""

from __future__ import annotations

import statistics
import time
from unittest.mock import patch

from src.core.pipeline import IncidentPipeline
from src.core.policy import PolicyEngine
from src.handlers import registry
from tests.conftest import make_guardduty_event

# Generous ceiling so CI runners stay green; local dry-run is typically << 50ms.
_AVG_MS_BUDGET = 250.0
_P95_MS_BUDGET = 500.0
_RUNS = 15


class TestPipelinePerf:
    @patch("src.core.pipeline.emit_metric")
    @patch("src.core.pipeline.SlackNotifier")
    def test_ignore_path_avg_latency(self, _slack, _metric):
        pipeline = IncidentPipeline(registry=registry, policy=PolicyEngine())
        event = make_guardduty_event()
        event["detail"]["severity"] = 0.5

        times_ms: list[float] = []
        # Warmup
        pipeline.process(event)
        for _ in range(_RUNS):
            t0 = time.perf_counter()
            result = pipeline.process(event)
            times_ms.append((time.perf_counter() - t0) * 1000)
            assert result["statusCode"] == 200
            assert result["body"]["decision"] == "IGNORE"

        avg = statistics.fmean(times_ms)
        p95 = sorted(times_ms)[int(0.95 * (len(times_ms) - 1))]
        assert avg < _AVG_MS_BUDGET, f"avg={avg:.2f}ms exceeds {_AVG_MS_BUDGET}ms"
        assert p95 < _P95_MS_BUDGET, f"p95={p95:.2f}ms exceeds {_P95_MS_BUDGET}ms"
