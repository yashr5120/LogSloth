"""
tests/test_schemas.py — Tests for AI response validation.
tests/test_analyzer.py — Tests for Ollama unavailability and timeout handling.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import json
import pytest
from unittest.mock import MagicMock, patch
from logsloth.schemas import validate_ai_response
from logsloth.analyzer import OllamaClient, analyse_incident
from logsloth.models import Incident, Severity
from datetime import datetime


# ============================================================
# Schema / validation tests
# ============================================================

VALID_RESPONSE = {
    "title": "Database Connection Failure",
    "summary": "The application cannot reach the database server. Multiple retries failed.",
    "probable_causes": ["Database server is down", "Network partition"],
    "evidence": ["OperationalError: could not connect to server"],
    "suggested_checks": ["Check db server status", "Check network connectivity"],
    "confidence": "high",
    "limitations": "Cannot determine root cause without server-side logs.",
}


class TestAIResponseValidation:
    def test_valid_json_accepted(self):
        result = validate_ai_response(json.dumps(VALID_RESPONSE))
        assert result.success is True
        assert result.title == "Database Connection Failure"
        assert result.confidence == "high"

    def test_json_in_code_fence(self):
        fenced = f"```json\n{json.dumps(VALID_RESPONSE)}\n```"
        result = validate_ai_response(fenced)
        assert result.success is True

    def test_missing_summary_rejected(self):
        bad = dict(VALID_RESPONSE)
        bad["summary"] = ""
        result = validate_ai_response(json.dumps(bad))
        assert result.success is False
        assert "summary" in result.error.lower()

    def test_invalid_json_rejected(self):
        result = validate_ai_response("this is not json at all")
        assert result.success is False
        assert "JSON" in result.error

    def test_invalid_confidence_coerced_to_low(self):
        bad = dict(VALID_RESPONSE)
        bad["confidence"] = "very_sure"
        result = validate_ai_response(json.dumps(bad))
        assert result.success is True
        assert result.confidence == "low"

    def test_non_object_json_rejected(self):
        result = validate_ai_response(json.dumps([1, 2, 3]))
        assert result.success is False

    def test_empty_response_rejected(self):
        result = validate_ai_response("")
        assert result.success is False

    def test_raw_response_stored(self):
        raw = json.dumps(VALID_RESPONSE)
        result = validate_ai_response(raw)
        assert result.raw_response  # should be non-empty


# ============================================================
# Analyzer / Ollama tests (no network calls)
# ============================================================

def _make_incident() -> Incident:
    return Incident(
        fingerprint="abc123def456",
        severity=Severity.ERROR,
        title="DB Connection Error",
        representative_message="OperationalError: could not connect",
        representative_stack="",
        source_files=["test.log"],
        first_seen=datetime(2024, 1, 15, 10, 0),
        last_seen=datetime(2024, 1, 15, 10, 5),
        occurrence_count=8,
    )


class TestOllamaUnavailable:
    def test_connection_refused_returns_failure(self):
        import requests

        client = OllamaClient(base_url="http://localhost:19999", model="nonexistent")

        # Simulate connection refused
        with patch("logsloth.analyzer.requests.post") as mock_post:
            mock_post.side_effect = requests.ConnectionError("Connection refused")
            result = analyse_incident(_make_incident(), [], client=client, max_retries=1)

        assert result.success is False
        assert "connection" in result.error.lower()

    def test_timeout_returns_failure(self):
        import requests

        client = OllamaClient(base_url="http://localhost:11434", model="gemma3:1b", timeout=1)

        with patch("logsloth.analyzer.requests.post") as mock_post:
            mock_post.side_effect = requests.Timeout("Request timed out")
            result = analyse_incident(_make_incident(), [], client=client, max_retries=1)

        assert result.success is False
        assert "timed out" in result.error.lower()

    def test_malformed_json_response_returns_failure(self):
        mock_resp = MagicMock()
        mock_resp.raise_for_status.return_value = None
        mock_resp.json.return_value = {"response": "not valid json output {{{"}

        with patch("logsloth.analyzer.requests.post", return_value=mock_resp):
            client = OllamaClient()
            result = analyse_incident(_make_incident(), [], client=client, max_retries=1)

        assert result.success is False

    def test_valid_response_returns_success(self):
        mock_resp = MagicMock()
        mock_resp.raise_for_status.return_value = None
        mock_resp.json.return_value = {"response": json.dumps(VALID_RESPONSE)}

        with patch("logsloth.analyzer.requests.post", return_value=mock_resp):
            client = OllamaClient()
            result = analyse_incident(_make_incident(), ["sample log line"], client=client)

        assert result.success is True
        assert result.summary != ""

    def test_deterministic_data_unaffected_by_ai_failure(self):
        """Incident data must be unchanged when AI fails."""
        import requests

        inc = _make_incident()
        original_count = inc.occurrence_count

        with patch("logsloth.analyzer.requests.post") as mock_post:
            mock_post.side_effect = requests.ConnectionError("Connection refused")
            result = analyse_incident(inc, [], client=OllamaClient(), max_retries=1)

        # Deterministic fields unchanged
        assert inc.occurrence_count == original_count
        assert inc.fingerprint == "abc123def456"
        assert result.success is False
