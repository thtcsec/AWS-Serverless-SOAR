"""Unit tests for AWS AI Summarizer (Amazon Bedrock)."""

import json
from unittest.mock import MagicMock, patch
import pytest
from src.integrations.ai_summarizer import AISummarizer


@pytest.fixture
def mock_bedrock_client():
    """Create a mock Bedrock runtime client."""
    client = MagicMock()
    body_mock = MagicMock()
    body_mock.read.return_value = json.dumps({
        "content": [{"text": "A crypto miner was detected on i-abc123. Severity is CRITICAL. Recommend immediate isolation and forensic snapshot."}],
        "usage": {"input_tokens": 150, "output_tokens": 40},
    }).encode()
    client.invoke_model.return_value = {"body": body_mock}
    return client


@pytest.fixture
def sample_incident():
    return {
        "incident_id": "abc123",
        "platform": "aws",
        "severity": "CRITICAL",
        "source_ip": "198.51.100.10",
        "actor": "unknown",
        "action": "CryptoCurrency:EC2/BitcoinTool.B",
        "resource": "i-abc123",
        "resource_type": "ec2",
        "risk_score": 85.0,
        "decision": "AUTO_ISOLATE",
    }


class TestAISummarizer:
    def test_summarize_success(self, mock_bedrock_client, sample_incident):
        summarizer = AISummarizer(client=mock_bedrock_client)
        result = summarizer.summarize_incident(sample_incident)

        assert "crypto miner" in result["summary"].lower()
        assert result["model_id"] == "anthropic.claude-3-haiku-20240307-v1:0"
        assert "tokens_used" in result
        mock_bedrock_client.invoke_model.assert_called_once()

    def test_summarize_fallback_on_error(self, sample_incident):
        client = MagicMock()
        client.invoke_model.side_effect = Exception("Service unavailable")

        summarizer = AISummarizer(client=client)
        result = summarizer.summarize_incident(sample_incident)

        assert result["model_id"] == "fallback"
        assert "[AUTO]" in result["summary"]
        assert "i-abc123" in result["summary"]

    def test_fallback_summary_content(self, sample_incident):
        result = AISummarizer._fallback_summary(sample_incident)

        assert result["model_id"] == "fallback"
        assert "CRITICAL" in result["summary"]
        assert "i-abc123" in result["summary"]
        assert "AUTO_ISOLATE" in result["summary"]
        assert "85.0" in result["summary"]

    def test_fallback_with_empty_data(self):
        result = AISummarizer._fallback_summary({})

        assert result["model_id"] == "fallback"
        assert "UNKNOWN" in result["summary"]
