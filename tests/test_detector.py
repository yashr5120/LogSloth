"""
tests/test_detector.py — Tests for occurrence counting and spike detection.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from datetime import datetime, timedelta
import pytest
from logsloth.models import LogEntry, Severity
from logsloth.detector import build_incidents, detect_spikes, group_by_fingerprint
from logsloth.fingerprint import compute_fingerprint


def _make_entry(msg: str, ts: datetime | None = None, sev: Severity = Severity.ERROR) -> LogEntry:
    return LogEntry(
        raw=msg,
        source_file="test.log",
        line_number=1,
        timestamp=ts,
        severity=sev,
        message=msg,
        parsed=True,
    )


BASE_MSG = "OperationalError: could not connect to server: Connection refused"
NOW = datetime(2024, 1, 15, 12, 0, 0)


class TestGrouping:
    def test_same_message_grouped(self):
        entries = [_make_entry(BASE_MSG) for _ in range(5)]
        groups = group_by_fingerprint(entries)
        assert len(groups) == 1
        fp = list(groups.keys())[0]
        assert len(groups[fp]) == 5

    def test_different_errors_different_groups(self):
        entries = [
            _make_entry("KeyError: 'user_role'"),
            _make_entry("ValueError: invalid int"),
            _make_entry("KeyError: 'user_role'"),
        ]
        groups = group_by_fingerprint(entries)
        assert len(groups) == 2


class TestIncidentBuilding:
    def test_occurrence_count(self):
        entries = [_make_entry(BASE_MSG, ts=NOW + timedelta(seconds=i)) for i in range(7)]
        groups = group_by_fingerprint(entries)
        incidents = build_incidents(groups)
        inc = list(incidents.values())[0]
        assert inc.occurrence_count == 7

    def test_first_and_last_seen(self):
        t0 = NOW
        t1 = NOW + timedelta(minutes=5)
        entries = [_make_entry(BASE_MSG, ts=t0), _make_entry(BASE_MSG, ts=t1)]
        groups = group_by_fingerprint(entries)
        incidents = build_incidents(groups)
        inc = list(incidents.values())[0]
        assert inc.first_seen == t0
        assert inc.last_seen == t1

    def test_dominant_severity_critical_wins(self):
        entries = [
            _make_entry(BASE_MSG, sev=Severity.WARNING),
            _make_entry(BASE_MSG, sev=Severity.CRITICAL),
            _make_entry(BASE_MSG, sev=Severity.ERROR),
        ]
        groups = group_by_fingerprint(entries)
        incidents = build_incidents(groups)
        inc = list(incidents.values())[0]
        assert inc.severity == Severity.CRITICAL


class TestSpikeDetection:
    def _make_spike_entries(self, baseline_count: int, spike_count: int):
        """Create entries: baseline 10min ago, spike in last 5min."""
        entries = []
        window = 300  # 5 minutes
        baseline_start = NOW - timedelta(seconds=window * 3)
        spike_start = NOW - timedelta(seconds=window - 10)

        for i in range(baseline_count):
            t = baseline_start + timedelta(seconds=i * 5)
            entries.append(_make_entry(BASE_MSG, ts=t))

        for i in range(spike_count):
            t = spike_start + timedelta(seconds=i)
            entries.append(_make_entry(BASE_MSG, ts=t))

        return entries

    def test_spike_flagged_on_burst(self):
        entries = self._make_spike_entries(baseline_count=10, spike_count=60)
        groups = group_by_fingerprint(entries)
        incidents = build_incidents(groups)
        incidents = detect_spikes(incidents, entries, window_seconds=300, multiplier=3.0, min_baseline=5)
        inc = list(incidents.values())[0]
        assert inc.spike_flagged is True
        assert inc.spike_reason != ""

    def test_no_spike_normal_rate(self):
        entries = self._make_spike_entries(baseline_count=20, spike_count=2)
        groups = group_by_fingerprint(entries)
        incidents = build_incidents(groups)
        incidents = detect_spikes(incidents, entries, window_seconds=300, multiplier=3.0, min_baseline=5)
        inc = list(incidents.values())[0]
        assert inc.spike_flagged is False

    def test_no_timestamps_no_spike(self):
        entries = [_make_entry(BASE_MSG, ts=None) for _ in range(50)]
        groups = group_by_fingerprint(entries)
        incidents = build_incidents(groups)
        incidents = detect_spikes(incidents, entries)
        inc = list(incidents.values())[0]
        assert inc.spike_flagged is False

    def test_empty_entries_safe(self):
        result = detect_spikes({}, [])
        assert result == {}

    def test_insufficient_baseline_no_false_positive(self):
        """With < min_baseline events in baseline, only flag if burst >= 10."""
        entries = [
            _make_entry(BASE_MSG, ts=NOW - timedelta(seconds=10)),
            _make_entry(BASE_MSG, ts=NOW - timedelta(seconds=5)),
        ]
        groups = group_by_fingerprint(entries)
        incidents = build_incidents(groups)
        incidents = detect_spikes(incidents, entries, window_seconds=300, multiplier=3.0, min_baseline=5)
        inc = list(incidents.values())[0]
        # Only 2 events — not a spike
        assert inc.spike_flagged is False
