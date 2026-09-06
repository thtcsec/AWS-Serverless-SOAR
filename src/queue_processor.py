"""
SQS transport adapter — routes buffered events into the unified IncidentPipeline.

DEPRECATED path: Step Functions fan-out. Application spine is handlers.handle_event().
"""

from __future__ import annotations

import contextlib
import json
import logging
import os
from datetime import UTC, datetime
from typing import Any

import boto3

from src.handlers import handle_event

logger = logging.getLogger()
logger.setLevel(getattr(logging, os.environ.get("LOG_LEVEL", "INFO")))


def lambda_handler(event, context):
    """Process SQS batch records and delegate each payload to handle_event()."""
    try:
        records = event.get("Records", [])
        logger.info("Processing %s SQS messages via unified pipeline", len(records))

        dlq_url = os.environ.get("DLQ_URL")
        processed_messages = 0
        failed_messages = 0
        pipeline_results: list[dict[str, Any]] = []

        for record in records:
            message_id = record.get("messageId", "unknown")
            try:
                message_body = _parse_record_body(record)
                event_data = _to_pipeline_event(message_body)

                if not event_data:
                    logger.warning("Unable to map message %s to pipeline event", message_id)
                    failed_messages += 1
                    continue

                result = handle_event(event_data)
                pipeline_results.append(
                    {
                        "message_id": message_id,
                        "status": "ok" if isinstance(result, dict) else "processed",
                        "result_keys": sorted(result.keys()) if isinstance(result, dict) else [],
                    }
                )
                processed_messages += 1
                logger.info("Pipeline handled message %s", message_id)

            except Exception as exc:
                logger.error("Error processing message %s: %s", message_id, exc)
                failed_messages += 1
                if dlq_url:
                    try:
                        send_to_dlq(record, dlq_url)
                    except Exception as dlq_error:
                        logger.error("Failed to send message to DLQ: %s", dlq_error)

        response = {
            "processed_messages": processed_messages,
            "failed_messages": failed_messages,
            "total_messages": len(records),
            "pipeline_results": pipeline_results,
            "processing_timestamp": datetime.now(UTC).isoformat(),
            "lambda_request_id": getattr(context, "aws_request_id", None),
            "spine": "handlers.handle_event",
        }
        logger.info(
            "Queue processing complete: %s processed, %s failed",
            processed_messages,
            failed_messages,
        )
        return response

    except Exception as exc:
        logger.error("Critical error in queue processor: %s", exc)
        raise


def _parse_record_body(record: dict[str, Any]) -> dict[str, Any]:
    body = record.get("body", "{}")
    payload = body if isinstance(body, dict) else json.loads(body)

    # SNS → SQS envelope
    if isinstance(payload.get("Message"), str):
        with contextlib.suppress(json.JSONDecodeError):
            payload = json.loads(payload["Message"])
    return payload


def _to_pipeline_event(message_body: dict[str, Any]) -> dict[str, Any] | None:
    """Normalize SQS payloads (EventBridge, custom envelopes, or raw findings)."""
    if not isinstance(message_body, dict):
        return None

    # Already an EventBridge / pipeline-ready event
    if "detail" in message_body or "source" in message_body:
        return message_body

    event_source = message_body.get("event_source") or message_body.get("source")
    if event_source == "aws.guardduty" or "finding" in message_body:
        finding = message_body.get("finding") or message_body.get("detail") or {}
        return {
            "source": "aws.guardduty",
            "detail-type": "GuardDuty Finding",
            "detail": finding if isinstance(finding, dict) else {},
            "id": message_body.get("event_id") or message_body.get("id"),
            "account": message_body.get("account"),
            "region": message_body.get("region"),
            "time": message_body.get("event_time") or message_body.get("time"),
        }

    if event_source in ("aws.iam", "aws.s3", "aws.cloudtrail") or "event" in message_body:
        detail = message_body.get("event") or message_body.get("detail") or message_body
        return {
            "source": event_source or "aws.cloudtrail",
            "detail-type": message_body.get("event_type") or "AWS API Call via CloudTrail",
            "detail": detail if isinstance(detail, dict) else {},
            "id": message_body.get("event_id") or message_body.get("id"),
            "account": message_body.get("account"),
            "region": message_body.get("region"),
            "time": message_body.get("event_time") or message_body.get("time"),
        }

    # Last resort: pass through if it looks like a security event
    if any(k in message_body for k in ("protoPayload", "finding", "Records")):
        return message_body

    return None


def send_to_dlq(record: dict[str, Any], dlq_url: str) -> None:
    """Send failed message to Dead Letter Queue (best-effort)."""
    sqs_client = boto3.client("sqs")
    try:
        original = json.loads(record["body"]) if isinstance(record.get("body"), str) else record.get("body")
    except (json.JSONDecodeError, TypeError, KeyError):
        original = record.get("body")

    enhanced_message = {
        "original_message": original,
        "error_info": {
            "failed_timestamp": datetime.now(UTC).isoformat(),
            "failure_reason": "queue_processing_error",
            "original_message_id": record.get("messageId"),
        },
    }
    sqs_client.send_message(
        QueueUrl=dlq_url,
        MessageBody=json.dumps(enhanced_message),
        MessageAttributes={
            "OriginalMessageId": {
                "DataType": "String",
                "StringValue": str(record.get("messageId", "unknown")),
            },
            "FailureReason": {"DataType": "String", "StringValue": "queue_processing_error"},
        },
    )
    logger.info("Sent message %s to DLQ", record.get("messageId"))
