"""
Slack Interactivity Request URL handler (Approve / Reject buttons).

Configure Slack App → Interactivity Request URL to this Lambda Function URL
(or API Gateway). Requires SLACK_SIGNING_SECRET.

Falls back to allowing unsigned payloads only when SLACK_SIGNING_SECRET is unset
(local lab). Production must set the secret.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import time
from typing import Any
from urllib.parse import parse_qs

from src.handlers import pipeline

logger = logging.getLogger(__name__)


def _verify_slack_signature(headers: dict[str, str], body: bytes) -> bool:
    secret = os.environ.get("SLACK_SIGNING_SECRET", "")
    if not secret:
        logger.warning("SLACK_SIGNING_SECRET unset — skipping signature verification (lab only)")
        return True

    ts = headers.get("x-slack-request-timestamp") or headers.get("X-Slack-Request-Timestamp") or ""
    sig = headers.get("x-slack-signature") or headers.get("X-Slack-Signature") or ""
    if not ts or not sig:
        return False
    if abs(time.time() - int(ts)) > 60 * 5:
        return False
    basestring = f"v0:{ts}:{body.decode('utf-8')}".encode()
    digest = "v0=" + hmac.new(secret.encode(), basestring, hashlib.sha256).hexdigest()
    return hmac.compare_digest(digest, sig)


def _normalize_headers(event: dict[str, Any]) -> dict[str, str]:
    raw = event.get("headers") or {}
    return {str(k): str(v) for k, v in raw.items()}


def handle_slack_interaction(event: dict[str, Any], context: Any = None) -> dict[str, Any]:
    """
    AWS Lambda / Function URL entry for Slack interactive payloads.

    Slack sends application/x-www-form-urlencoded with a `payload` JSON field.
    """
    headers = _normalize_headers(event)
    body_raw = event.get("body") or ""
    if event.get("isBase64Encoded"):
        import base64

        body_bytes = base64.b64decode(body_raw)
    else:
        body_bytes = body_raw.encode("utf-8") if isinstance(body_raw, str) else body_raw

    if not _verify_slack_signature(headers, body_bytes):
        return {"statusCode": 401, "body": "invalid signature"}

    form = parse_qs(body_bytes.decode("utf-8"))
    payload_list = form.get("payload") or []
    if not payload_list:
        # Also accept direct JSON for lab invokes
        try:
            payload = json.loads(body_bytes.decode("utf-8"))
        except json.JSONDecodeError:
            return {"statusCode": 400, "body": "missing payload"}
    else:
        payload = json.loads(payload_list[0])

    # URL verification challenge (rare for interactivity, but harmless)
    if payload.get("type") == "url_verification":
        return {"statusCode": 200, "body": payload.get("challenge", "")}

    actions = payload.get("actions") or []
    if not actions:
        return {"statusCode": 200, "body": ""}

    action = actions[0]
    action_id = action.get("action_id", "")
    incident_id = action.get("value", "")
    user = (payload.get("user") or {}).get("username") or (payload.get("user") or {}).get("id") or "slack"

    if action_id == "soar_approve":
        result = pipeline.resume_approval(incident_id=incident_id, action="approve", actor=f"slack:{user}")
        text = f":white_check_mark: Approved `{incident_id}` by {user}"
    elif action_id == "soar_reject":
        result = pipeline.resume_approval(incident_id=incident_id, action="reject", actor=f"slack:{user}")
        text = f":no_entry: Rejected `{incident_id}` by {user}"
    else:
        return {"statusCode": 200, "body": ""}

    logger.info("Slack interaction handled: %s", result)
    # Replace original message with outcome (Slack expects JSON body for response_url style;
    # Function URL can return message update payload when response_type used via response_url —
    # simplest: return ephemeral replacement text).
    return {
        "statusCode": 200,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps({"replace_original": True, "text": text}),
    }


# Alias used by Terraform handler wiring
lambda_handler = handle_slack_interaction
