"""
tests/test_storage.py — Tests for SQLite persistence and duplicate prevention.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import tempfile
import pytest
from datetime import datetime
from logsloth.models import Incident, Severity
from logsloth.storage import (
    initialise,
    upsert_incident,
    load_all_incidents,
    record_entry_ids,
    already_ingested,
)


def _make_incident(fp: str = "abc123def456", occ: int = 5) -> Incident:
    return Incident(
        fingerprint=fp,
        severity=Severity.ERROR,
        title="Test Incident",
        representative_message="Something broke",
        representative_stack="",
        source_files=["test.log"],
        first_seen=datetime(2024, 1, 15, 10, 0, 0),
        last_seen=datetime(2024, 1, 15, 11, 0, 0),
        occurrence_count=occ,
    )


@pytest.fixture
def db_path(tmp_path):
    p = tmp_path / "test.db"
    initialise(p)
    return p


class TestPersistence:
    def test_upsert_and_load(self, db_path):
        inc = _make_incident()
        upsert_incident(db_path, inc)
        loaded = load_all_incidents(db_path)
        assert inc.fingerprint in loaded
        assert loaded[inc.fingerprint].occurrence_count == 5

    def test_upsert_updates_existing(self, db_path):
        inc = _make_incident(occ=5)
        upsert_incident(db_path, inc)
        inc.occurrence_count = 10
        upsert_incident(db_path, inc)
        loaded = load_all_incidents(db_path)
        assert loaded[inc.fingerprint].occurrence_count == 10

    def test_multiple_incidents(self, db_path):
        for i in range(5):
            upsert_incident(db_path, _make_incident(fp=f"fp{i:012d}", occ=i + 1))
        loaded = load_all_incidents(db_path)
        assert len(loaded) == 5

    def test_ai_fields_persisted(self, db_path):
        inc = _make_incident()
        inc.ai_summary = "Test summary"
        inc.ai_analyzed = True
        inc.ai_confidence = "high"
        upsert_incident(db_path, inc)
        loaded = load_all_incidents(db_path)
        reloaded = loaded[inc.fingerprint]
        assert reloaded.ai_summary == "Test summary"
        assert reloaded.ai_analyzed is True

    def test_empty_db_returns_empty_dict(self, db_path):
        loaded = load_all_incidents(db_path)
        assert loaded == {}

    def test_missing_db_returns_empty_dict(self, tmp_path):
        missing = tmp_path / "nonexistent.db"
        assert load_all_incidents(missing) == {}


class TestDuplicatePrevention:
    def test_entry_ids_recorded(self, db_path):
        ids = [("id1", "fp001234567890", "test.log"), ("id2", "fp001234567890", "test.log")]
        record_entry_ids(db_path, ids)
        found = already_ingested(db_path, ["id1", "id2", "id3"])
        assert "id1" in found
        assert "id2" in found
        assert "id3" not in found

    def test_duplicate_entry_id_ignored(self, db_path):
        ids = [("id1", "fp001234567890", "test.log")]
        record_entry_ids(db_path, ids)
        # Second insert of same id should not raise
        record_entry_ids(db_path, ids)
        found = already_ingested(db_path, ["id1"])
        assert len(found) == 1

    def test_empty_entry_ids(self, db_path):
        assert already_ingested(db_path, []) == set()
