"""
logsloth/detector.py — Severity ranking and error-spike detection.

Spike detection compares the error rate in a recent window against a
historical baseline. It requires at least SPIKE_MIN_BASELINE events in
the baseline period to avoid false positives on low-traffic services.
"""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta
from typing import Optional

from logsloth.models import Incident, LogEntry, Severity

# ---------------------------------------------------------------------------
# Severity ranking helpers
# ---------------------------------------------------------------------------

_SEV_ORDER = [
    Severity.CRITICAL,
    Severity.ERROR,
    Severity.WARNING,
    Severity.INFO,
    Severity.DEBUG,
    Severity.UNKNOWN,
]


def dominant_severity(entries: list[LogEntry]) -> Severity:
    """Return the highest (most critical) severity found in *entries*."""
    if not entries:
        return Severity.UNKNOWN
    best = Severity.UNKNOWN
    for entry in entries:
        if entry.severity.numeric > best.numeric:
            best = entry.severity
    return best


# ---------------------------------------------------------------------------
# Occurrence grouping
# ---------------------------------------------------------------------------

def group_by_fingerprint(
    entries: list[LogEntry],
) -> dict[str, list[LogEntry]]:
    """Group entries by their fingerprint; must be called after fingerprints computed."""
    from logsloth.fingerprint import compute_fingerprint

    groups: dict[str, list[LogEntry]] = defaultdict(list)
    for entry in entries:
        fp = compute_fingerprint(entry)
        groups[fp].append(entry)
    return dict(groups)


def build_incidents(
    groups: dict[str, list[LogEntry]],
    existing_incidents: Optional[dict[str, "Incident"]] = None,
) -> dict[str, Incident]:
    """
    Build or update Incident objects from fingerprint groups.

    If *existing_incidents* is provided, occurrence counts are merged.
    """
    from logsloth.fingerprint import representative_title

    result: dict[str, Incident] = {}

    for fp, entries in groups.items():
        timestamps = [e.timestamp for e in entries if e.timestamp]
        first_seen = min(timestamps) if timestamps else None
        last_seen = max(timestamps) if timestamps else None
        sources = list({e.source_file for e in entries})
        rep = entries[0]
        sev = dominant_severity(entries)

        existing = (existing_incidents or {}).get(fp)
        base_count = existing.occurrence_count if existing else 0

        incident = Incident(
            fingerprint=fp,
            severity=sev,
            title=representative_title(rep),
            representative_message=rep.message or rep.raw[:200],
            representative_stack=rep.stack_trace,
            source_files=sources,
            first_seen=first_seen,
            last_seen=last_seen,
            occurrence_count=base_count + len(entries),
            incident_id=existing.incident_id if existing else str(__import__("uuid").uuid4()),
        )

        # Preserve previous AI analysis if available
        if existing and existing.ai_analyzed:
            incident.ai_title = existing.ai_title
            incident.ai_summary = existing.ai_summary
            incident.ai_probable_causes = existing.ai_probable_causes
            incident.ai_evidence = existing.ai_evidence
            incident.ai_suggested_checks = existing.ai_suggested_checks
            incident.ai_confidence = existing.ai_confidence
            incident.ai_limitations = existing.ai_limitations
            incident.ai_analyzed = existing.ai_analyzed

        result[fp] = incident

    return result


# ---------------------------------------------------------------------------
# Spike detection
# ---------------------------------------------------------------------------

def detect_spikes(
    incidents: dict[str, Incident],
    entries: list[LogEntry],
    *,
    window_seconds: int = 300,
    multiplier: float = 3.0,
    min_baseline: int = 5,
) -> dict[str, Incident]:
    """
    Flag incidents where the recent event rate exceeds *multiplier* × baseline.

    Safe against: missing timestamps, out-of-order events, empty datasets.
    Returns the same *incidents* dict with spike_flagged / spike_reason updated.
    """
    now = max(
        (e.timestamp for e in entries if e.timestamp),
        default=None,
    )

    if now is None:
        # No timestamps — cannot compute rates
        return incidents

    window_start = now - timedelta(seconds=window_seconds)
    baseline_start = window_start - timedelta(seconds=window_seconds * 2)

    from logsloth.fingerprint import compute_fingerprint

    # Count per fingerprint in [recent window] and [baseline window]
    recent: dict[str, int] = defaultdict(int)
    baseline: dict[str, int] = defaultdict(int)

    for entry in entries:
        if entry.timestamp is None:
            continue
        fp = compute_fingerprint(entry)
        if entry.timestamp >= window_start:
            recent[fp] += 1
        elif entry.timestamp >= baseline_start:
            baseline[fp] += 1

    for fp, incident in incidents.items():
        recent_count = recent.get(fp, 0)
        baseline_count = baseline.get(fp, 0)

        if baseline_count < min_baseline:
            # Insufficient history for a meaningful comparison
            if recent_count >= 10:
                # Sudden burst with no baseline — still flag it
                incident.spike_flagged = True
                incident.spike_reason = (
                    f"{recent_count} occurrences in last {window_seconds}s "
                    f"with no prior baseline (< {min_baseline} events)."
                )
            continue

        rate_recent = recent_count / window_seconds
        rate_baseline = baseline_count / (window_seconds * 2)

        if rate_baseline > 0 and rate_recent >= multiplier * rate_baseline:
            incident.spike_flagged = True
            incident.spike_reason = (
                f"Rate {rate_recent:.3f}/s vs baseline {rate_baseline:.3f}/s "
                f"({rate_recent / rate_baseline:.1f}× — threshold {multiplier}×)."
            )
        else:
            incident.spike_flagged = False
            incident.spike_reason = ""

    return incidents
