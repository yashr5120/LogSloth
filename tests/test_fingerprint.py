"""
tests/test_fingerprint.py — Unit tests for fingerprinting stability and separation.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
from logsloth.fingerprint import compute_fingerprint
from logsloth.models import LogEntry, Severity


def _entry(msg: str, stack: str = "", sev: Severity = Severity.ERROR) -> LogEntry:
    return LogEntry(
        raw=msg,
        source_file="test.log",
        line_number=1,
        severity=sev,
        message=msg,
        stack_trace=stack,
        parsed=True,
    )


class TestFingerprintStability:
    def test_same_error_same_fingerprint(self):
        e1 = _entry("OperationalError: could not connect to server: Connection refused")
        e2 = _entry("OperationalError: could not connect to server: Connection refused")
        assert compute_fingerprint(e1) == compute_fingerprint(e2)

    def test_different_ids_same_fingerprint(self):
        """Variable identifiers (user_id=42 vs user_id=99) should not change the fingerprint."""
        e1 = _entry("KeyError: user_id=42 not found in session")
        e2 = _entry("KeyError: user_id=99 not found in session")
        # Both normalise to the same KeyError group
        fp1 = compute_fingerprint(e1)
        fp2 = compute_fingerprint(e2)
        # They should be the same fingerprint (normalised numbers)
        assert fp1 == fp2

    def test_fingerprint_is_12_chars(self):
        e = _entry("Something went wrong")
        fp = compute_fingerprint(e)
        assert len(fp) == 12
        assert fp.isalnum()


class TestFingerprintSeparation:
    def test_different_exception_types_different_fingerprints(self):
        e_key = _entry("KeyError: 'user_role' not found")
        e_val = _entry("ValueError: invalid literal for int() with base 10")
        assert compute_fingerprint(e_key) != compute_fingerprint(e_val)

    def test_db_error_vs_http_error_different_fingerprints(self):
        e_db = _entry("OperationalError: could not connect to server: Connection refused")
        e_http = _entry("HTTPError: 503 Service Unavailable for url: https://api.example.com")
        assert compute_fingerprint(e_db) != compute_fingerprint(e_http)

    def test_different_stack_locations_different_fingerprints(self):
        stack_a = 'File "/app/services/payment.py", line 87, in process_payment\n  ValueError'
        stack_b = 'File "/app/models/user.py", line 12, in get_role\n  ValueError'
        e_a = _entry("ValueError: invalid input", stack=stack_a)
        e_b = _entry("ValueError: invalid input", stack=stack_b)
        assert compute_fingerprint(e_a) != compute_fingerprint(e_b)

    def test_unrelated_messages_different_fingerprints(self):
        e1 = _entry("ImportError: No module named 'missing_plugin'")
        e2 = _entry("TypeError: unsupported operand type(s) for +: 'int' and 'NoneType'")
        assert compute_fingerprint(e1) != compute_fingerprint(e2)

    def test_db_connection_errors_group_together(self):
        """Multiple DB connection refusals should fingerprint identically."""
        msgs = [
            "OperationalError: could not connect to server: Connection refused",
            "OperationalError: could not connect to server: Connection refused",
            "OperationalError: could not connect to server: Connection refused",
        ]
        fps = {compute_fingerprint(_entry(m)) for m in msgs}
        assert len(fps) == 1, "All DB connection errors should share one fingerprint"
