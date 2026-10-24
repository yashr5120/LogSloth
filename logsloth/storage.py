"""
logsloth/storage.py — SQLite persistence for incidents and occurrence counts.

Uses parameterised queries, explicit transactions, and a well-defined schema.
Duplicate ingestion is prevented by using a stable (fingerprint, entry_id) key.
Raw log content is not stored.
"""
from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Iterator, Optional

from logsloth.models import Incident, Severity

_SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS incidents (
    fingerprint       TEXT PRIMARY KEY,
    incident_id       TEXT NOT NULL,
    severity          TEXT NOT NULL,
    title             TEXT NOT NULL,
    representative_message TEXT NOT NULL,
    representative_stack   TEXT NOT NULL DEFAULT '',
    source_files      TEXT NOT NULL DEFAULT '[]',
    first_seen        TEXT,
    last_seen         TEXT,
    occurrence_count  INTEGER NOT NULL DEFAULT 0,
    spike_flagged     INTEGER NOT NULL DEFAULT 0,
    spike_reason      TEXT NOT NULL DEFAULT '',
    ai_title          TEXT NOT NULL DEFAULT '',
    ai_summary        TEXT NOT NULL DEFAULT '',
    ai_probable_causes TEXT NOT NULL DEFAULT '[]',
    ai_evidence        TEXT NOT NULL DEFAULT '[]',
    ai_suggested_checks TEXT NOT NULL DEFAULT '[]',
    ai_confidence     TEXT NOT NULL DEFAULT '',
    ai_limitations    TEXT NOT NULL DEFAULT '',
    ai_analyzed       INTEGER NOT NULL DEFAULT 0,
    ai_error          TEXT NOT NULL DEFAULT '',
    updated_at        TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS ingested_entries (
    entry_id          TEXT PRIMARY KEY,
    fingerprint       TEXT NOT NULL,
    source_file       TEXT NOT NULL,
    ingested_at       TEXT NOT NULL
);
"""


@contextmanager
def _conn(db_path: Path) -> Iterator[sqlite3.Connection]:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(str(db_path), check_same_thread=False)
    con.row_factory = sqlite3.Row
    try:
        yield con
        con.commit()
    except Exception:
        con.rollback()
        raise
    finally:
        con.close()


def initialise(db_path: Path) -> None:
    """Create tables if they do not exist."""
    with _conn(db_path) as con:
        con.executescript(_SCHEMA)


def _ts(dt: Optional[datetime]) -> Optional[str]:
    return dt.isoformat() if dt else None


def _from_ts(s: Optional[str]) -> Optional[datetime]:
    if not s:
        return None
    try:
        return datetime.fromisoformat(s)
    except ValueError:
        return None


def upsert_incident(db_path: Path, incident: Incident) -> None:
    """Insert or update a single incident row."""
    now = datetime.utcnow().isoformat()
    with _conn(db_path) as con:
        con.execute(
            """
            INSERT INTO incidents (
                fingerprint, incident_id, severity, title,
                representative_message, representative_stack, source_files,
                first_seen, last_seen, occurrence_count,
                spike_flagged, spike_reason,
                ai_title, ai_summary, ai_probable_causes, ai_evidence,
                ai_suggested_checks, ai_confidence, ai_limitations,
                ai_analyzed, ai_error, updated_at
            ) VALUES (
                :fp, :iid, :sev, :title,
                :rep_msg, :rep_stack, :sources,
                :first_seen, :last_seen, :occ,
                :spike_flagged, :spike_reason,
                :ai_title, :ai_summary, :ai_causes, :ai_ev,
                :ai_checks, :ai_conf, :ai_lim,
                :ai_analyzed, :ai_error, :now
            )
            ON CONFLICT(fingerprint) DO UPDATE SET
                severity          = excluded.severity,
                title             = excluded.title,
                representative_message = excluded.representative_message,
                representative_stack   = excluded.representative_stack,
                source_files      = excluded.source_files,
                first_seen        = COALESCE(MIN(incidents.first_seen, excluded.first_seen), excluded.first_seen),
                last_seen         = MAX(COALESCE(incidents.last_seen,''), COALESCE(excluded.last_seen,'')),
                occurrence_count  = excluded.occurrence_count,
                spike_flagged     = excluded.spike_flagged,
                spike_reason      = excluded.spike_reason,
                ai_title          = excluded.ai_title,
                ai_summary        = excluded.ai_summary,
                ai_probable_causes = excluded.ai_probable_causes,
                ai_evidence        = excluded.ai_evidence,
                ai_suggested_checks = excluded.ai_suggested_checks,
                ai_confidence     = excluded.ai_confidence,
                ai_limitations    = excluded.ai_limitations,
                ai_analyzed       = excluded.ai_analyzed,
                ai_error          = excluded.ai_error,
                updated_at        = excluded.updated_at
            """,
            {
                "fp": incident.fingerprint,
                "iid": incident.incident_id,
                "sev": incident.severity.value,
                "title": incident.title,
                "rep_msg": incident.representative_message[:1000],
                "rep_stack": incident.representative_stack[:2000],
                "sources": json.dumps(incident.source_files),
                "first_seen": _ts(incident.first_seen),
                "last_seen": _ts(incident.last_seen),
                "occ": incident.occurrence_count,
                "spike_flagged": int(incident.spike_flagged),
                "spike_reason": incident.spike_reason,
                "ai_title": incident.ai_title,
                "ai_summary": incident.ai_summary,
                "ai_causes": json.dumps(incident.ai_probable_causes),
                "ai_ev": json.dumps(incident.ai_evidence),
                "ai_checks": json.dumps(incident.ai_suggested_checks),
                "ai_conf": incident.ai_confidence,
                "ai_lim": incident.ai_limitations,
                "ai_analyzed": int(incident.ai_analyzed),
                "ai_error": incident.ai_error,
                "now": now,
            },
        )


def record_entry_ids(db_path: Path, entry_ids: list[tuple[str, str, str]]) -> None:
    """
    Record ingested entry IDs to prevent double-counting.

    *entry_ids* is a list of (entry_id, fingerprint, source_file) tuples.
    """
    now = datetime.utcnow().isoformat()
    with _conn(db_path) as con:
        con.executemany(
            """
            INSERT OR IGNORE INTO ingested_entries (entry_id, fingerprint, source_file, ingested_at)
            VALUES (?, ?, ?, ?)
            """,
            [(eid, fp, src, now) for eid, fp, src in entry_ids],
        )


def already_ingested(db_path: Path, entry_ids: list[str]) -> set[str]:
    """Return the subset of *entry_ids* that have already been recorded."""
    if not entry_ids:
        return set()
    placeholders = ",".join("?" * len(entry_ids))
    with _conn(db_path) as con:
        rows = con.execute(
            f"SELECT entry_id FROM ingested_entries WHERE entry_id IN ({placeholders})",
            entry_ids,
        ).fetchall()
    return {row["entry_id"] for row in rows}


def load_all_incidents(db_path: Path) -> dict[str, Incident]:
    """Load all persisted incidents from SQLite."""
    if not db_path.exists():
        return {}

    with _conn(db_path) as con:
        rows = con.execute("SELECT * FROM incidents ORDER BY occurrence_count DESC").fetchall()

    result: dict[str, Incident] = {}
    for row in rows:
        inc = Incident(
            fingerprint=row["fingerprint"],
            incident_id=row["incident_id"],
            severity=Severity(row["severity"]),
            title=row["title"],
            representative_message=row["representative_message"],
            representative_stack=row["representative_stack"] or "",
            source_files=json.loads(row["source_files"] or "[]"),
            first_seen=_from_ts(row["first_seen"]),
            last_seen=_from_ts(row["last_seen"]),
            occurrence_count=row["occurrence_count"],
            spike_flagged=bool(row["spike_flagged"]),
            spike_reason=row["spike_reason"] or "",
            ai_title=row["ai_title"] or "",
            ai_summary=row["ai_summary"] or "",
            ai_probable_causes=json.loads(row["ai_probable_causes"] or "[]"),
            ai_evidence=json.loads(row["ai_evidence"] or "[]"),
            ai_suggested_checks=json.loads(row["ai_suggested_checks"] or "[]"),
            ai_confidence=row["ai_confidence"] or "",
            ai_limitations=row["ai_limitations"] or "",
            ai_analyzed=bool(row["ai_analyzed"]),
            ai_error=row["ai_error"] or "",
        )
        result[inc.fingerprint] = inc

    return result
