"""
tests/test_e2e.py — End-to-end test using synthetic logs and a mocked AI client.

No network calls, no real Ollama, no model download required.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import json
import tempfile
import pytest
from unittest.mock import MagicMock, patch
from datetime import datetime

from logsloth.collector import ingest_directory
from logsloth.detector import build_incidents, detect_spikes, group_by_fingerprint
from logsloth.analyzer import OllamaClient, analyse_incident, apply_analysis_to_incident
from logsloth.reporter import incident_to_markdown
from logsloth.storage import initialise, upsert_incident, load_all_incidents
from logsloth.models import Severity


SAMPLE_LOG_CONTENT = """\
2024-01-15T10:00:00.000+00:00 INFO app.startup Starting application
2024-01-15T10:01:00.000+00:00 WARNING app.db Connection pool at 80%
2024-01-15T10:02:00.000+00:00 ERROR app.db OperationalError: could not connect to server: Connection refused
2024-01-15T10:02:01.000+00:00 ERROR app.db OperationalError: could not connect to server: Connection refused
2024-01-15T10:02:02.000+00:00 ERROR app.db OperationalError: could not connect to server: Connection refused
2024-01-15T10:02:03.000+00:00 CRITICAL app.db Database pool exhausted
2024-01-15T10:03:00.000+00:00 ERROR app.api HTTPError: 503 Service Unavailable
2024-01-15T10:03:01.000+00:00 ERROR app.api HTTPError: 503 Service Unavailable
2024-01-15T10:05:00.000+00:00 INFO app.db Connection restored
"""

MOCK_AI_RESPONSE = {
    "title": "Database Connection Failure",
    "summary": "The application is unable to reach the database server. Multiple connection attempts failed.",
    "probable_causes": ["Database server is down", "Network partition between app and db"],
    "evidence": ["OperationalError: could not connect to server: Connection refused"],
    "suggested_checks": [
        "Check if database server process is running",
        "Verify network connectivity to db host",
    ],
    "confidence": "medium",
    "limitations": "Cannot determine whether the db server crashed or was never started.",
}


@pytest.fixture
def log_dir(tmp_path):
    log_file = tmp_path / "test_app.log"
    log_file.write_text(SAMPLE_LOG_CONTENT, encoding="utf-8")
    return tmp_path


@pytest.fixture
def db_path(tmp_path):
    p = tmp_path / "e2e_test.db"
    initialise(p)
    return p


class TestEndToEnd:
    def test_full_pipeline_without_ai(self, log_dir, db_path):
        """Parse → group → count → detect spikes → persist → load."""
        # 1. Ingest
        entries = ingest_directory(log_dir)
        assert len(entries) > 0

        # 2. Group
        groups = group_by_fingerprint(entries)
        assert len(groups) >= 2  # DB errors + HTTP errors

        # 3. Build incidents
        incidents = build_incidents(groups)
        assert len(incidents) >= 2

        # 4. Detect spikes (no spike expected with this log — too few events)
        incidents = detect_spikes(incidents, entries, window_seconds=300, multiplier=3.0)

        # 5. Persist
        for inc in incidents.values():
            upsert_incident(db_path, inc)

        # 6. Reload
        loaded = load_all_incidents(db_path)
        assert len(loaded) == len(incidents)

        # 7. Verify at least one ERROR/CRITICAL incident
        severities = {inc.severity for inc in loaded.values()}
        assert Severity.ERROR in severities or Severity.CRITICAL in severities

    def test_redaction_applied_before_ai(self, log_dir):
        """Sensitive data must be removed before evidence is built."""
        from logsloth.parser import parse_lines
        from logsloth.redactor import redact

        lines = [
            "2024-01-15T10:00:00.000+00:00 ERROR app.db "
            "Connection failed with password=hunter2 api_key=sk-live-deadbeef\n"
        ]
        entries = parse_lines(lines, "test.log", redact=True)
        assert "hunter2" not in entries[0].message
        assert "sk-live-deadbeef" not in entries[0].message

    def test_ai_analysis_with_mock(self, log_dir, db_path):
        """Full pipeline with mocked AI — no Ollama required."""
        entries = ingest_directory(log_dir)
        groups = group_by_fingerprint(entries)
        incidents = build_incidents(groups)

        # Pick the first incident
        fp, inc = next(iter(incidents.items()))

        # Mock Ollama response
        mock_resp = MagicMock()
        mock_resp.raise_for_status.return_value = None
        mock_resp.json.return_value = {"response": json.dumps(MOCK_AI_RESPONSE)}

        with patch("logsloth.analyzer.requests.post", return_value=mock_resp):
            client = OllamaClient()
            result = analyse_incident(inc, ["sample line"], client=client)

        assert result.success is True
        apply_analysis_to_incident(inc, result)
        assert inc.ai_analyzed is True
        assert inc.ai_summary != ""

        # Persist and reload
        upsert_incident(db_path, inc)
        loaded = load_all_incidents(db_path)
        assert loaded[fp].ai_analyzed is True

    def test_report_generation(self, log_dir, tmp_path):
        """Verify Markdown report is generated and contains expected sections."""
        from logsloth.reporter import export_report

        entries = ingest_directory(log_dir)
        groups = group_by_fingerprint(entries)
        incidents = build_incidents(groups)
        inc = next(iter(incidents.values()))

        report_path = export_report(inc, tmp_path / "reports")
        assert report_path.exists()
        content = report_path.read_text(encoding="utf-8")

        assert "# Incident Report:" in content
        assert "Fingerprint" in content
        assert "Severity" in content
        assert "LogSloth" in content

    def test_duplicate_ingestion_prevention(self, log_dir, db_path):
        """Re-ingesting the same log file must not double the occurrence counts."""
        from logsloth.storage import record_entry_ids, already_ingested

        entries = ingest_directory(log_dir)
        entry_ids = [(e.entry_id, "fp_test", "test.log") for e in entries[:3]]

        # First ingest
        record_entry_ids(db_path, entry_ids)
        seen = already_ingested(db_path, [t[0] for t in entry_ids])
        assert len(seen) == 3

        # Second ingest — should all already be there
        record_entry_ids(db_path, entry_ids)  # Must not raise or duplicate
        seen2 = already_ingested(db_path, [t[0] for t in entry_ids])
        assert len(seen2) == 3  # unchanged
