"""
logsloth/schemas.py — Validation for AI model JSON responses.

The Ollama model is asked to return a specific JSON structure.
This module validates and coerces the response into an AnalysisResult,
rejecting or partially accepting malformed output.
"""
from __future__ import annotations

import json
from typing import Any

from logsloth.models import AnalysisResult

_VALID_CONFIDENCE = {"low", "medium", "high"}


def _to_str_list(value: Any, max_items: int = 10, max_len: int = 300) -> list[str]:
    """Coerce *value* to a list of short strings."""
    if isinstance(value, list):
        return [str(item)[:max_len] for item in value[:max_items]]
    if isinstance(value, str) and value.strip():
        return [value[:max_len]]
    return []


def validate_ai_response(raw: str) -> AnalysisResult:
    """
    Parse and validate the raw string returned by the AI model.

    Returns a populated AnalysisResult with success=True on valid input,
    or success=False with an error message on invalid input.
    Never raises.
    """
    result = AnalysisResult(raw_response=raw[:4000])

    # --- Attempt JSON extraction ---
    # The model sometimes wraps JSON in a markdown code fence
    text = raw.strip()
    if text.startswith("```"):
        lines = text.splitlines()
        # Drop first and last fence lines
        inner = "\n".join(lines[1:-1] if lines[-1].strip().startswith("```") else lines[1:])
        text = inner.strip()

    try:
        data: dict[str, Any] = json.loads(text)
    except (json.JSONDecodeError, ValueError) as exc:
        result.error = f"JSON parse error: {exc}"
        result.success = False
        return result

    if not isinstance(data, dict):
        result.error = "Response is not a JSON object."
        result.success = False
        return result

    # --- Field extraction with coercion ---
    result.title = str(data.get("title", ""))[:200]
    result.summary = str(data.get("summary", ""))[:2000]
    result.probable_causes = _to_str_list(data.get("probable_causes", []))
    result.evidence = _to_str_list(data.get("evidence", []))
    result.suggested_checks = _to_str_list(data.get("suggested_checks", []))
    result.limitations = str(data.get("limitations", ""))[:500]

    raw_conf = str(data.get("confidence", "low")).lower().strip()
    result.confidence = raw_conf if raw_conf in _VALID_CONFIDENCE else "low"

    # Require at minimum a non-empty summary
    if not result.summary.strip():
        result.error = "Response missing required 'summary' field."
        result.success = False
        return result

    result.success = True
    return result
