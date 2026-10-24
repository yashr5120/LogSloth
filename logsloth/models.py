"""
logsloth/models.py — Internal data models for log entries and incidents.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    ERROR = "ERROR"
    WARNING = "WARNING"
    INFO = "INFO"
    DEBUG = "DEBUG"
    UNKNOWN = "UNKNOWN"

    @classmethod
    def from_string(cls, value: str) -> "Severity":
        """Normalise a raw severity string to a known Severity level."""
        mapping = {
            "critical": cls.CRITICAL,
            "crit": cls.CRITICAL,
            "error": cls.ERROR,
            "err": cls.ERROR,
            "fatal": cls.CRITICAL,
            "warning": cls.WARNING,
            "warn": cls.WARNING,
            "info": cls.INFO,
            "information": cls.INFO,
            "debug": cls.DEBUG,
            "dbg": cls.DEBUG,
            "trace": cls.DEBUG,
        }
        return mapping.get(value.lower().strip(), cls.UNKNOWN)

    @property
    def numeric(self) -> int:
        """Higher = more severe."""
        order = {
            self.CRITICAL: 5,
            self.ERROR: 4,
            self.WARNING: 3,
            self.INFO: 2,
            self.DEBUG: 1,
            self.UNKNOWN: 0,
        }
        return order[self]


@dataclass
class LogEntry:
    """A single, normalised log record."""

    raw: str
    source_file: str
    line_number: int

    timestamp: Optional[datetime] = None
    severity: Severity = Severity.UNKNOWN
    logger_name: str = ""
    message: str = ""
    stack_trace: str = ""
    parsed: bool = False
    redacted: bool = False

    # Stable identifier for deduplication across reruns
    entry_id: str = field(default_factory=lambda: str(uuid.uuid4()))


@dataclass
class Incident:
    """A group of log entries sharing the same fingerprint."""

    fingerprint: str
    severity: Severity
    title: str
    representative_message: str
    representative_stack: str
    source_files: list[str]
    first_seen: Optional[datetime]
    last_seen: Optional[datetime]
    occurrence_count: int = 0
    spike_flagged: bool = False
    spike_reason: str = ""

    # AI analysis (populated after Ollama call)
    ai_title: str = ""
    ai_summary: str = ""
    ai_probable_causes: list[str] = field(default_factory=list)
    ai_evidence: list[str] = field(default_factory=list)
    ai_suggested_checks: list[str] = field(default_factory=list)
    ai_confidence: str = ""
    ai_limitations: str = ""
    ai_analyzed: bool = False
    ai_error: str = ""

    incident_id: str = field(default_factory=lambda: str(uuid.uuid4()))


@dataclass
class AnalysisResult:
    """Structured response from the local AI model."""

    title: str = ""
    summary: str = ""
    probable_causes: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    suggested_checks: list[str] = field(default_factory=list)
    confidence: str = "low"
    limitations: str = ""
    raw_response: str = ""
    success: bool = False
    error: str = ""
