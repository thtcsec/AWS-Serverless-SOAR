"""
AWS SOAR — AI Incident Summarizer (Amazon Bedrock)
Uses a foundation model to generate human-readable incident summaries
from raw UnifiedIncident data, enriching Slack alerts with actionable context.
"""

import json
import logging
import os
from typing import Any, Dict, Optional

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)

# Default model — Claude 3 Haiku is fast & cheap for summarization
DEFAULT_MODEL_ID = "anthropic.claude-3-haiku-20240307-v1:0"
DEFAULT_REGION = os.environ.get("BEDROCK_REGION", "us-east-1")


SYSTEM_PROMPT = (
    "You are a senior Security Operations Center (SOC) analyst. "
    "Given the structured JSON of a security incident, produce a concise, "
    "actionable summary in 3-5 sentences suitable for a Slack alert. "
    "Include: what happened, which resource is affected, severity assessment, "
    "and your recommended immediate next step. "
    "Do NOT use markdown formatting. Keep it plain text."
)


class AISummarizer:
    """Generate human-readable incident summaries via Amazon Bedrock."""

    def __init__(
        self,
        model_id: str = DEFAULT_MODEL_ID,
        region: str = DEFAULT_REGION,
        client: Optional[Any] = None,
    ):
        self.model_id = model_id
        self.client = client or boto3.client(
            "bedrock-runtime", region_name=region
        )

    def summarize_incident(
        self, incident_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Summarize an incident using Amazon Bedrock.

        Args:
            incident_data: UnifiedIncident dict or raw finding data.

        Returns:
            Dict with 'summary' (str) and 'model_id' (str).
            On failure returns 'summary' with a fallback message.
        """
        try:
            user_message = (
                "Summarize the following security incident:\n\n"
                + json.dumps(incident_data, indent=2, default=str)
            )

            body = json.dumps({
                "anthropic_version": "bedrock-2023-05-31",
                "max_tokens": 512,
                "system": SYSTEM_PROMPT,
                "messages": [
                    {"role": "user", "content": user_message}
                ],
            })

            response = self.client.invoke_model(
                modelId=self.model_id,
                contentType="application/json",
                accept="application/json",
                body=body,
            )

            result = json.loads(response["body"].read())
            summary_text = (
                result.get("content", [{}])[0].get("text", "")
            )

            logger.info("AI summary generated successfully.")
            return {
                "summary": summary_text,
                "model_id": self.model_id,
                "tokens_used": result.get("usage", {}),
            }

        except ClientError as exc:
            logger.error("Bedrock API error: %s", exc)
            return self._fallback_summary(incident_data)
        except Exception as exc:  # noqa: BLE001
            logger.error("AI summarizer error: %s", exc)
            return self._fallback_summary(incident_data)

    # ------------------------------------------------------------------
    # Fallback: deterministic template when AI is unavailable
    # ------------------------------------------------------------------
    @staticmethod
    def _fallback_summary(
        incident_data: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Return a rule-based summary when Bedrock is unreachable."""
        severity = incident_data.get("severity", "UNKNOWN")
        resource = incident_data.get("resource", "N/A")
        action = incident_data.get("action", "N/A")
        source_ip = incident_data.get("source_ip", "N/A")
        risk_score = incident_data.get("risk_score", 0)
        decision = incident_data.get("decision", "N/A")

        summary = (
            f"[AUTO] {severity} severity incident detected on resource "
            f"'{resource}'. Action: {action}. Source IP: {source_ip}. "
            f"Risk score: {risk_score}/100 → Decision: {decision}. "
            f"AI summary unavailable — review raw finding for details."
        )
        return {"summary": summary, "model_id": "fallback"}
