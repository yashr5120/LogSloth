"""
logsloth/redactor.py — Sensitive-data redaction before AI prompt construction.

LIMITATION: Regex-based redaction catches common patterns but is NOT
comprehensive. Custom secret formats, obfuscated values, or unusual
encoding may bypass these rules. Never rely solely on this module to
guarantee privacy.
"""
from __future__ import annotations

import re
from typing import Optional

from config import Config

# ---------------------------------------------------------------------------
# Pattern registry — order matters; more specific patterns first
# ---------------------------------------------------------------------------

_REDACTION_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    # Authorization / Bearer tokens
    (
        Config.REDACTION_PLACEHOLDER,
        re.compile(r"(Authorization\s*:\s*(?:Bearer|Basic|Token)\s+)\S+", re.IGNORECASE),
    ),
    # Generic API / secret / token keys in key=value or key: value style
    (
        Config.REDACTION_PLACEHOLDER,
        re.compile(
            r"""(?i)(?:api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token|
                        password|passwd|pwd|private[_-]?key|client[_-]?secret|
                        x-api-key|token)
                \s*[=:]\s*["']?([^\s"',&;]{4,})["']?""",
            re.VERBOSE,
        ),
    ),
    # URL-embedded credentials — scheme://user:password@host
    (
        Config.REDACTION_PLACEHOLDER,
        re.compile(r"([a-zA-Z][a-zA-Z0-9+\-.]*://)([^:@\s]+:[^:@\s]+@)", re.IGNORECASE),
    ),
    # AWS-style access keys
    (
        Config.REDACTION_PLACEHOLDER,
        re.compile(r"(?<![A-Z0-9])(AKIA[0-9A-Z]{16})(?![A-Z0-9])"),
    ),
    # JWT-looking tokens (three base64url segments)
    (
        Config.REDACTION_PLACEHOLDER,
        re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
    ),
    # Sensitive URL query parameters
    (
        Config.REDACTION_PLACEHOLDER,
        re.compile(
            r"([?&](?:token|key|secret|password|auth|apikey|api_key)=)[^&\s#]+",
            re.IGNORECASE,
        ),
    ),
    # IPv4 addresses (optional — useful for privacy, disabled by default here)
    # (Config.REDACTION_PLACEHOLDER, re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")),
]


def redact(text: str, extra_patterns: Optional[list[re.Pattern[str]]] = None) -> str:
    """
    Return *text* with all recognised sensitive strings replaced by the
    redaction placeholder.

    Parameters
    ----------
    text:
        The raw log line or message to sanitise.
    extra_patterns:
        Optional additional compiled patterns to apply after the defaults.
    """
    if not text:
        return text

    result = text
    for placeholder, pattern in _REDACTION_PATTERNS:
        try:
            if pattern.groups == 1:
                # Keep prefix (group 0 minus group 1), replace group 1 with placeholder
                result = pattern.sub(
                    lambda m, p=placeholder: m.group(0).replace(m.group(1), p),
                    result,
                )
            elif pattern.groups == 2:
                # Keep group 1 (scheme/prefix), replace group 2 (secret) with placeholder
                result = pattern.sub(
                    lambda m, p=placeholder: m.group(1) + p,
                    result,
                )
            else:
                result = pattern.sub(placeholder, result)
        except re.error:
            # Never crash on a bad regex; just skip
            pass

    if extra_patterns:
        for pattern in extra_patterns:
            try:
                result = pattern.sub(Config.REDACTION_PLACEHOLDER, result)
            except re.error:
                pass

    return result


def redact_entry_inplace(entry: "LogEntry") -> "LogEntry":  # type: ignore[name-defined]  # noqa: F821
    """Redact message and stack_trace fields of a LogEntry in place."""
    from logsloth.models import LogEntry  # local import to avoid circular

    entry.message = redact(entry.message)
    entry.stack_trace = redact(entry.stack_trace)
    entry.raw = redact(entry.raw)
    entry.redacted = True
    return entry
