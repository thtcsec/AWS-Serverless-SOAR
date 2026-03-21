import time
from contextlib import contextmanager
from datetime import UTC, datetime

from src.clients.aws import AWSClientFacade
from src.core.config import config
from src.core.logger import logger


def emit_metric(
    metric_name: str,
    value: float = 1.0,
    unit: str = "Count",
    dimensions: dict | None = None,
) -> None:
    """Emit a custom CloudWatch metric for SOAR observability."""
    try:
        cw = AWSClientFacade.cloudwatch()
        metric_data = {
            "MetricName": metric_name,
            "Value": value,
            "Unit": unit,
            "Timestamp": datetime.now(UTC),
        }
        if dimensions:
            metric_data["Dimensions"] = [{"Name": k, "Value": v} for k, v in dimensions.items()]
        cw.put_metric_data(
            Namespace=config.metrics_namespace,
            MetricData=[metric_data],
        )
    except Exception as e:
        logger.warning(f"Failed to emit metric {metric_name}: {e}")


class PlaybookTimer:
    """Context manager to measure and emit playbook execution duration."""

    def __init__(self, playbook_name: str):
        self.playbook_name = playbook_name
        self._start: float = 0

    def __enter__(self):
        self._start = time.monotonic()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        duration_ms = (time.monotonic() - self._start) * 1000
        dims = {"Playbook": self.playbook_name}
        emit_metric("PlaybookDuration", duration_ms, "Milliseconds", dims)
        if exc_type is None:
            emit_metric("PlaybookSuccess", 1.0, "Count", dims)
        else:
            emit_metric("PlaybookFailure", 1.0, "Count", dims)
        return False


@contextmanager
def aws_xray_segment(name: str):
    """Context manager that wraps a code block in an X-Ray subsegment (Nhóm 4).

    Falls back to a no-op if aws_xray_sdk is unavailable or not configured.
    """
    try:
        from aws_xray_sdk.core import xray_recorder  # type: ignore

        with xray_recorder.in_subsegment(name):
            yield
    except Exception:
        # Graceful degradation — X-Ray not configured or not available
        yield


def emit_step_metric(playbook_name: str, step_name: str, duration_ms: float) -> None:
    """Emit per-step timing metric for detailed playbook observability (Nhóm 4)."""
    try:
        metric_name = f"{playbook_name.lower()}.{step_name}_duration_ms"
        emit_metric(metric_name, duration_ms, "Milliseconds", {"Playbook": playbook_name, "Step": step_name})
    except Exception as e:
        logger.warning(f"Failed to emit step metric {step_name}: {e}")
