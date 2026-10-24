"""
logsloth/fingerprint.py — Deterministic error fingerprinting.

A fingerprint uniquely identifies an incident group by combining:
  1. Normalised exception/error type extracted from the message or stack trace.
  2. The deepest application stack frame (if available).
  3. A normalised version of the error message with variable parts stripped.

Two entries with the same fingerprint are considered the same incident.
Two entries with different error types or different code locations must
NEVER share a fingerprint, even if their messages look similar.
"""
from __future__ import annotations

import hashlib
import re

from logsloth.models import LogEntry, Severity

# ---------------------------------------------------------------------------
# Normalisation helpers
# ---------------------------------------------------------------------------

# Remove quoted strings, hex addresses, UUIDs, numbers — they vary per-request
_VAR_PATTERNS = [
    re.compile(r'"[^"]{0,120}"'),          # double-quoted values
    re.compile(r"'[^']{0,120}'"),           # single-quoted values
    re.compile(r"\b0x[0-9a-fA-F]+\b"),     # hex addresses
    re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b"),  # UUID
    re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"),  # IPv4
    re.compile(r"\b\d+\b"),                # bare integers
    re.compile(r"\s+"),                    # collapse whitespace
]

# Extract "ExceptionType: " from message or stack
_EXC_TYPE_RE = re.compile(
    r"(?:^|\s)([A-Za-z_][A-Za-z0-9_.]*(?:Error|Exception|Fault|Warning|Failure|Timeout|Refused))"
)

# Extract deepest File frame from Python tracebacks
_PY_FRAME_RE = re.compile(r'File "([^"]+)", line \d+, in (\S+)')

# DB / network error patterns
_DB_CONN_RE = re.compile(
    r"(?i)(connection\s+(?:refused|reset|timed?\s+out|failed|error)|"
    r"could\s+not\s+connect|operationalerror|too\s+many\s+connections)"
)

_HTTP_5XX_RE = re.compile(r"\b5\d{2}\b")


def _normalise_message(msg: str) -> str:
    result = msg.lower()
    for pat in _VAR_PATTERNS:
        result = pat.sub(" ", result)
    return result.strip()


def _extract_exception_type(message: str, stack: str) -> str:
    """Best-effort extraction of the exception class name."""
    for text in (stack, message):
        m = _EXC_TYPE_RE.search(text)
        if m:
            return m.group(1).lower()
    return ""


def _extract_code_location(stack: str) -> str:
    """Return the deepest app frame from a Python traceback."""
    frames = _PY_FRAME_RE.findall(stack)
    if not frames:
        return ""
    # Prefer the last frame that is not from site-packages / stdlib
    for filepath, funcname in reversed(frames):
        if "site-packages" not in filepath and "lib/python" not in filepath.lower():
            # Keep only basename to avoid machine-specific paths
            basename = re.sub(r".*[/\\]", "", filepath)
            return f"{basename}:{funcname}"
    # Fallback: last frame
    filepath, funcname = frames[-1]
    basename = re.sub(r".*[/\\]", "", filepath)
    return f"{basename}:{funcname}"


def compute_fingerprint(entry: LogEntry) -> str:
    """
    Return a stable hex fingerprint for the given log entry.

    The fingerprint is an 8-character prefix of a SHA-256 hash of:
      "<exception_type>|<code_location>|<normalised_message>"
    """
    exc_type = _extract_exception_type(entry.message, entry.stack_trace)
    code_loc = _extract_code_location(entry.stack_trace)
    norm_msg = _normalise_message(entry.message)

    # For DB connection errors, anchor to the error class regardless of details
    if _DB_CONN_RE.search(entry.message + entry.stack_trace):
        norm_msg = "db_connection_error"
        exc_type = exc_type or "connectionerror"

    # For HTTP 5xx, anchor to status code class
    m5 = _HTTP_5XX_RE.search(entry.message)
    if m5 and not exc_type:
        exc_type = f"http_{m5.group()}"

    key = f"{exc_type}|{code_loc}|{norm_msg}"
    digest = hashlib.sha256(key.encode("utf-8")).hexdigest()
    return digest[:12]


def representative_title(entry: LogEntry) -> str:
    """Generate a human-readable title for an incident group."""
    exc_type = _extract_exception_type(entry.message, entry.stack_trace)
    if exc_type:
        return exc_type.replace("error", " Error").replace("exception", " Exception").title()

    msg = entry.message[:80].strip()
    if not msg:
        msg = entry.raw[:80].strip()
    return msg or "Unknown Incident"
