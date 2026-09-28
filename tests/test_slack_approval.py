"""Slack approval payload includes scoring context."""

from unittest.mock import patch

from src.integrations.slack_notifier import SlackNotifier


def test_interactive_approval_includes_anomaly_and_mitre():
    notifier = SlackNotifier.__new__(SlackNotifier)
    with patch.object(notifier, "_send_slack_message", return_value={"ok": True}) as send:
        notifier.send_interactive_approval(
            {
                "incident_id": "inc-1",
                "severity": "HIGH",
                "risk_score": 62,
                "resource": "i-abc",
                "anomaly_score": -0.8,
                "mitre_ttps": ["T1496", "T1078"],
                "description": "review",
            }
        )

    blocks = send.call_args[0][0]["blocks"]
    fields = blocks[1]["fields"]
    rendered = " ".join(field["text"] for field in fields)
    assert "*Anomaly*" in rendered
    assert "-0.8" in rendered
    assert "T1496" in rendered
    assert "T1078" in rendered
