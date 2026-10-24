"""
logsloth/parser.py — Log parsing and multiline stack-trace assembly.

Supports common timestamped log formats:
  [TIMESTAMP] SEVERITY logger: message
  TIMESTAMP - SEVERITY - logger - message
  SEVERITY: message  (no timestamp)
  Plain lines (stored as UNKNOWN severity)

Multiline Python-style stack traces are accumulated into the preceding entry.
"""
from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path
from typing import Iterator

from logsloth.models import LogEntry, Severity
from logsloth.redactor import redact_entry_inplace

# ---------------------------------------------------------------------------
# Timestamp patterns
# ---------------------------------------------------------------------------

_TS_FORMATS = [
    "%Y-%m-%dT%H:%M:%S.%f%z",
    "%Y-%m-%dT%H:%M:%S%z",
    "%Y-%m-%dT%H:%M:%S.%f",
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%d %H:%M:%S,%f",
    "%Y-%m-%d %H:%M:%S.%f",
    "%Y-%m-%d %H:%M:%S",
    "%d/%b/%Y:%H:%M:%S",
    "%b %d %H:%M:%S",
]


def _parse_timestamp(raw_ts: str) -> datetime | None:
    raw_ts = raw_ts.strip()
    for fmt in _TS_FORMATS:
        try:
            return datetime.strptime(raw_ts, fmt)
        except ValueError:
            continue
    return None


# ---------------------------------------------------------------------------
# Line matchers
# ---------------------------------------------------------------------------

# Bracket-style:  [2024-01-15T12:00:00] ERROR app.module: message
_BRACKET_RE = re.compile(
    r"^\[(?P<ts>[^\]]+)\]\s+"
    r"(?P<sev>[A-Z]+)\s+"
    r"(?P<logger>\S+):\s*(?P<msg>.*)$"
)

# Dash-style:  2024-01-15 12:00:00,123 - ERROR - app.module - message
_DASH_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}[.,\d+Z-]*)\s*-\s*"
    r"(?P<sev>[A-Z]+)\s*-\s*(?P<logger>\S+)\s*-\s*(?P<msg>.*)$"
)

# ISO inline:  2024-01-15T12:00:00.123+00:00 ERROR app.module message
_ISO_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[^\s]*)\s+"
    r"(?P<sev>CRITICAL|ERROR|WARNING|WARN|INFO|DEBUG|TRACE)\s+"
    r"(?P<logger>\S+)\s+(?P<msg>.*)$",
    re.IGNORECASE,
)

# Severity-only (no timestamp):  ERROR: message
_SEV_ONLY_RE = re.compile(
    r"^(?P<sev>CRITICAL|ERROR|WARNING|WARN|INFO|DEBUG|TRACE)\s*:\s*(?P<msg>.*)$",
    re.IGNORECASE,
)

_STACK_CONTINUATION_RE = re.compile(
    r"^(?:\s+at\s|\s+File\s|\s+Traceback|\s+During\s|\s+The\s|\s{2,}|>>> )"
)

_TRACEBACK_START_RE = re.compile(r"^Traceback \(most recent call last\):")


def _try_parse_line(
    line: str, source_file: str, lineno: int
) -> LogEntry:
    """Attempt to parse *line* into a structured LogEntry."""

    for pattern in (_BRACKET_RE, _DASH_RE, _ISO_RE):
        m = pattern.match(line)
        if m:
            gd = m.groupdict()
            return LogEntry(
                raw=line,
                source_file=source_file,
                line_number=lineno,
                timestamp=_parse_timestamp(gd["ts"]),
                severity=Severity.from_string(gd.get("sev", "")),
                logger_name=gd.get("logger", ""),
                message=gd.get("msg", "").strip(),
                parsed=True,
            )

    m = _SEV_ONLY_RE.match(line)
    if m:
        gd = m.groupdict()
        return LogEntry(
            raw=line,
            source_file=source_file,
            line_number=lineno,
            severity=Severity.from_string(gd["sev"]),
            message=gd["msg"].strip(),
            parsed=True,
        )

    # Unparsed — preserve as-is
    return LogEntry(
        raw=line,
        source_file=source_file,
        line_number=lineno,
        message=line.strip(),
        parsed=False,
    )


def parse_lines(
    lines: list[str],
    source_file: str,
    *,
    redact: bool = True,
) -> list[LogEntry]:
    """
    Parse *lines* into a list of LogEntry objects.

    Multiline stack traces are accumulated into the immediately preceding entry.
    """
    entries: list[LogEntry] = []
    pending: LogEntry | None = None
    in_traceback = False

    for lineno, raw_line in enumerate(lines, start=1):
        line = raw_line.rstrip("\n").rstrip("\r")

        if not line.strip():
            # Blank line ends a traceback accumulation
            if pending is not None:
                entries.append(pending)
                pending = None
            in_traceback = False
            continue

        if _TRACEBACK_START_RE.match(line):
            in_traceback = True
            if pending is not None:
                pending.stack_trace += line + "\n"
            continue

        if in_traceback or _STACK_CONTINUATION_RE.match(line):
            if pending is not None:
                pending.stack_trace += line + "\n"
                continue
            # Orphaned continuation — treat as new unparsed entry
            in_traceback = False

        # New log line: flush the previous pending entry
        if pending is not None:
            entries.append(pending)

        in_traceback = False
        pending = _try_parse_line(line, source_file, lineno)

    if pending is not None:
        entries.append(pending)

    if redact:
        for entry in entries:
            redact_entry_inplace(entry)

    return entries


def parse_file(path: Path, *, redact: bool = True) -> list[LogEntry]:
    """Read and parse a single log file."""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return [
            LogEntry(
                raw=f"<unreadable: {exc}>",
                source_file=str(path),
                line_number=0,
                message=f"Could not read file: {exc}",
                parsed=False,
            )
        ]

    return parse_lines(text.splitlines(keepends=True), str(path), redact=redact)
