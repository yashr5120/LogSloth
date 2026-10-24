"""
tests/test_parser.py — Unit tests for log parsing and timestamp handling.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
from logsloth.parser import parse_lines, _parse_timestamp
from logsloth.models import Severity
from datetime import datetime


class TestTimestampParsing:
    def test_iso_with_offset(self):
        dt = _parse_timestamp("2024-01-15T10:00:00.123+00:00")
        assert dt is not None
        assert dt.hour == 10

    def test_iso_no_tz(self):
        dt = _parse_timestamp("2024-01-15T10:00:00")
        assert dt is not None

    def test_space_separated(self):
        dt = _parse_timestamp("2024-01-15 10:00:00,123")
        assert dt is not None

    def test_invalid_returns_none(self):
        assert _parse_timestamp("not-a-date") is None

    def test_empty_returns_none(self):
        assert _parse_timestamp("") is None


class TestLineParsing:
    def test_bracket_format(self):
        lines = ["[2024-01-15T10:00:00] ERROR app.module: Something failed\n"]
        entries = parse_lines(lines, "test.log", redact=False)
        assert len(entries) == 1
        e = entries[0]
        assert e.parsed is True
        assert e.severity == Severity.ERROR
        assert "Something failed" in e.message

    def test_dash_format(self):
        lines = ["2024-01-15 10:00:00,123 - WARNING - app.db - Slow query\n"]
        entries = parse_lines(lines, "test.log", redact=False)
        assert len(entries) == 1
        assert entries[0].severity == Severity.WARNING

    def test_iso_inline_format(self):
        lines = ["2024-01-15T10:00:00.123+00:00 ERROR app.api Failed request\n"]
        entries = parse_lines(lines, "test.log", redact=False)
        assert len(entries) == 1
        assert entries[0].severity == Severity.ERROR

    def test_severity_only_format(self):
        lines = ["ERROR: Something broke\n"]
        entries = parse_lines(lines, "test.log", redact=False)
        assert len(entries) == 1
        assert entries[0].severity == Severity.ERROR

    def test_unparsed_line_stored(self):
        lines = ["just some random text that doesnt match\n"]
        entries = parse_lines(lines, "test.log", redact=False)
        assert len(entries) == 1
        assert entries[0].parsed is False
        assert entries[0].severity == Severity.UNKNOWN

    def test_blank_lines_ignored(self):
        lines = ["\n", "   \n", "2024-01-15T10:00:00.000+00:00 INFO app.x Hello\n", "\n"]
        entries = parse_lines(lines, "test.log", redact=False)
        assert len(entries) == 1

    def test_empty_input(self):
        assert parse_lines([], "test.log") == []


class TestMultilineStackTrace:
    TRACEBACK_LINES = [
        "2024-01-15T10:00:00.000+00:00 ERROR app.api Request failed\n",
        "Traceback (most recent call last):\n",
        '  File "/app/views.py", line 42, in handle\n',
        '    result = process(data)\n',
        "ValueError: invalid literal for int()\n",
        "\n",
    ]

    def test_stack_trace_accumulated(self):
        entries = parse_lines(self.TRACEBACK_LINES, "test.log", redact=False)
        # Should be a single entry with a stack trace
        assert len(entries) == 1
        assert "Traceback" in entries[0].stack_trace
        assert "ValueError" in entries[0].stack_trace

    def test_stack_trace_in_parent_entry(self):
        entries = parse_lines(self.TRACEBACK_LINES, "test.log", redact=False)
        assert entries[0].severity == Severity.ERROR

    def test_two_separate_errors_produce_two_entries(self):
        lines = [
            "2024-01-15T10:00:00.000+00:00 ERROR app.x Error A\n",
            "\n",
            "2024-01-15T10:00:01.000+00:00 ERROR app.x Error B\n",
        ]
        entries = parse_lines(lines, "test.log", redact=False)
        assert len(entries) == 2


class TestMalformedRecords:
    def test_partial_json_line(self):
        lines = ['{"key": "value", "another":\n']
        entries = parse_lines(lines, "test.log", redact=False)
        assert len(entries) == 1
        assert entries[0].parsed is False

    def test_very_long_line(self):
        lines = ["x" * 10000 + "\n"]
        entries = parse_lines(lines, "test.log", redact=False)
        assert len(entries) == 1
