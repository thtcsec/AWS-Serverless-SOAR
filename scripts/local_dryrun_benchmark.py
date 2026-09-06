"""Local dry-run benchmark for thesis table 4.3 (logic only, not cloud latency)."""
from __future__ import annotations

import time
from unittest.mock import patch

from src.handlers import handle_event
from tests.conftest import make_guardduty_event

INTEL_AUTO_ISOLATE = {
    "virustotal": {"malicious": 20},
    "abuseipdb": {"abuseConfidenceScore": 80},
}


def main() -> None:
    event = make_guardduty_event()
    event["dry_run"] = True
    event["detail"]["service"] = {
        "resourceRole": "TARGET",
        "action": {
            "networkConnectionAction": {
                "remoteIpDetails": {"ipAddressV4": "203.0.113.10"},
            }
        },
    }
    times: list[float] = []
    result = None

    with (
        patch(
            "src.integrations.intel.ThreatIntelService.get_ip_report",
            return_value=INTEL_AUTO_ISOLATE,
        ),
        patch("src.core.pipeline.SlackNotifier"),
    ):
        for _ in range(10):
            t0 = time.perf_counter()
            result = handle_event(event)
            times.append((time.perf_counter() - t0) * 1000)

    body = result["body"] if result else {}
    print("statusCode", result.get("statusCode") if result else None)
    print("mode", body.get("mode"))
    print("playbook", body.get("playbook"))
    print("planned_actions_count", len(body.get("planned_actions", [])))
    for i, ms in enumerate(times, 1):
        print("run_%d_ms=%.2f" % (i, ms))
    print("avg_ms=%.2f" % (sum(times) / len(times)))


if __name__ == "__main__":
    main()
