"""
logsloth/analyzer.py — Ollama integration and local AI analysis.

SECURITY RULES:
- Only sanitised, bounded evidence is sent to the model.
- Model-generated text is treated as UNTRUSTED content — it is NEVER executed.
- Log content is never allowed to inject instructions into the model prompt
  beyond the strictly templated evidence block.
- The model is never invoked with the full raw log file.
- Network calls are bounded by a configurable timeout.
"""
from __future__ import annotations

import json
import logging
import time
from typing import Optional

import requests

from config import Config
from logsloth.models import AnalysisResult, Incident
from logsloth.schemas import validate_ai_response

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Prompt template
# ---------------------------------------------------------------------------

_SYSTEM_PROMPT = """\
You are a senior software reliability engineer. You will be given sanitised \
log evidence about an application error incident. Your job is to provide a \
structured diagnostic analysis.

RULES:
- Base your analysis ONLY on the evidence provided. Do not fabricate details.
- Clearly distinguish between observed facts and hypotheses.
- If evidence is insufficient, say so in the limitations field.
- Output ONLY valid JSON matching the schema below. No prose outside the JSON.
- Never include shell commands, file paths, or executable instructions.

OUTPUT SCHEMA (JSON):
{
  "title": "Short descriptive title (≤80 chars)",
  "summary": "2-4 sentence plain-language explanation of what the logs show",
  "probable_causes": ["cause 1", "cause 2"],
  "evidence": ["specific log line or pattern that supports the analysis"],
  "suggested_checks": ["actionable investigation step 1", "step 2"],
  "confidence": "low | medium | high",
  "limitations": "What evidence is missing or what cannot be determined from these logs"
}
"""


def _build_evidence_block(incident: Incident, entries_sample: list[str]) -> str:
    """Construct the bounded evidence block sent to the model."""
    lines = [
        f"## Incident: {incident.title}",
        f"Severity: {incident.severity.value}",
        f"Occurrences: {incident.occurrence_count}",
        f"First seen: {incident.first_seen}",
        f"Last seen: {incident.last_seen}",
        "",
        "### Representative message (sanitised)",
        incident.representative_message[:500],
    ]

    if incident.representative_stack:
        lines += [
            "",
            "### Stack trace (sanitised)",
            incident.representative_stack[:1000],
        ]

    if entries_sample:
        lines += ["", "### Sample log lines (sanitised)"]
        lines.extend(entries_sample[: Config.MAX_EVIDENCE_LINES])

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Ollama client
# ---------------------------------------------------------------------------

class OllamaClient:
    """Thin wrapper around the Ollama local HTTP API."""

    def __init__(
        self,
        base_url: str = Config.OLLAMA_BASE_URL,
        model: str = Config.OLLAMA_MODEL,
        timeout: int = Config.OLLAMA_TIMEOUT,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.timeout = timeout

    def is_available(self) -> tuple[bool, str]:
        """Check whether the Ollama server and model are reachable."""
        try:
            resp = requests.get(f"{self.base_url}/api/tags", timeout=5)
            resp.raise_for_status()
            data = resp.json()
            models = [m.get("name", "") for m in data.get("models", [])]
            if self.model not in models:
                return (
                    False,
                    f"Model '{self.model}' not found. Available: {models or ['none']}",
                )
            return True, "OK"
        except requests.ConnectionError:
            return False, f"Ollama not reachable at {self.base_url}"
        except requests.Timeout:
            return False, "Ollama health check timed out"
        except Exception as exc:  # noqa: BLE001
            return False, f"Unexpected error: {exc}"

    def generate(self, prompt: str) -> tuple[str, Optional[str]]:
        """
        Send *prompt* to the Ollama generate endpoint.

        Returns (raw_text, error_message). error_message is None on success.
        """
        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "options": {"temperature": 0.1, "num_predict": 1024},
        }
        try:
            resp = requests.post(
                f"{self.base_url}/api/generate",
                json=payload,
                timeout=self.timeout,
            )
            resp.raise_for_status()
            data = resp.json()
            return data.get("response", ""), None
        except requests.ConnectionError:
            return "", f"Ollama connection refused at {self.base_url}"
        except requests.Timeout:
            return "", f"Ollama request timed out after {self.timeout}s"
        except requests.HTTPError as exc:
            return "", f"HTTP error from Ollama: {exc}"
        except (json.JSONDecodeError, KeyError) as exc:
            return "", f"Malformed response from Ollama: {exc}"
        except Exception as exc:  # noqa: BLE001
            return "", f"Unexpected error calling Ollama: {exc}"


# ---------------------------------------------------------------------------
# High-level analysis function
# ---------------------------------------------------------------------------

def analyse_incident(
    incident: Incident,
    entries_sample: list[str],
    *,
    client: Optional[OllamaClient] = None,
    max_retries: int = 2,
) -> AnalysisResult:
    """
    Run AI analysis on *incident* using up to *max_retries* attempts.

    Evidence is bounded and sanitised before being sent.
    If Ollama is unavailable or the response is invalid, returns a failed
    AnalysisResult — the deterministic incident data is never affected.
    """
    if client is None:
        client = OllamaClient()

    evidence = _build_evidence_block(incident, entries_sample)
    full_prompt = f"{_SYSTEM_PROMPT}\n\n{evidence}\n\nAnalysis (JSON only):"

    last_error = "No attempts made."
    for attempt in range(1, max_retries + 1):
        raw, error = client.generate(full_prompt)
        if error:
            last_error = error
            logger.warning("Ollama attempt %d/%d failed: %s", attempt, max_retries, error)
            time.sleep(1)
            continue

        result = validate_ai_response(raw)
        if result.success:
            return result

        last_error = f"Validation failed: {result.error}"
        logger.warning("AI response validation failed (attempt %d): %s", attempt, result.error)

    failed = AnalysisResult(success=False, error=last_error)
    return failed


def apply_analysis_to_incident(incident: Incident, result: AnalysisResult) -> None:
    """Merge a successful AnalysisResult into the Incident (in-place)."""
    if not result.success:
        incident.ai_error = result.error
        incident.ai_analyzed = False
        return

    incident.ai_title = result.title
    incident.ai_summary = result.summary
    incident.ai_probable_causes = result.probable_causes
    incident.ai_evidence = result.evidence
    incident.ai_suggested_checks = result.suggested_checks
    incident.ai_confidence = result.confidence
    incident.ai_limitations = result.limitations
    incident.ai_analyzed = True
    incident.ai_error = ""
