"""
tests/test_redactor.py — Unit tests for secret redaction.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
from logsloth.redactor import redact


KNOWN_SECRETS = [
    # Bearer token
    "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.abc123",
    # API key
    "api_key=sk-test-fakekeyABCDEF123456",
    # Password in key=value
    "password=SuperSecret123!",
    # AWS access key
    "AKIAIOSFODNN7EXAMPLE",
    # JWT
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyMTIzIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
    # URL embedded password
    "postgres://admin:SuperSecret@db-host:5432/myapp",
    # Query param
    "https://api.example.com/v1/data?token=secret-token-abc123&page=1",
]


class TestRedactionPatterns:
    @pytest.mark.parametrize("secret_text", KNOWN_SECRETS)
    def test_known_secrets_are_redacted(self, secret_text: str):
        """Verify that known secret patterns are removed from the output."""
        result = redact(secret_text)
        # None of the following raw values should survive redaction
        dangerous_fragments = [
            "SuperSecret123!",
            "SuperSecret",
            "sk-test-fakekeyABCDEF123456",
            "AKIAIOSFODNN7EXAMPLE",
            "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
            "secret-token-abc123",
        ]
        for frag in dangerous_fragments:
            if frag in secret_text:
                assert frag not in result, (
                    f"Secret fragment '{frag}' survived redaction.\n"
                    f"Input:  {secret_text}\n"
                    f"Output: {result}"
                )

    def test_redacted_placeholder_present(self):
        result = redact("Authorization: Bearer mysecrettoken123")
        assert "[REDACTED]" in result

    def test_non_sensitive_text_preserved(self):
        text = "2024-01-15 10:00:00 INFO app.web GET /api/health 200 OK"
        assert redact(text) == text

    def test_empty_string(self):
        assert redact("") == ""

    def test_none_equivalent(self):
        # Ensure no crash on falsy input
        assert redact("") == ""

    def test_url_scheme_preserved_user_stripped(self):
        result = redact("postgres://admin:password@db-host:5432/db")
        assert "postgres://" in result
        assert "password" not in result

    def test_api_key_in_log_line(self):
        line = '2024-01-15T10:00:00 WARNING app.x Request api_key=sk-live-abcdef123 rejected'
        result = redact(line)
        assert "sk-live-abcdef123" not in result

    def test_multiple_secrets_in_one_line(self):
        line = "token=abc123secret password=hunter2 other=fine"
        result = redact(line)
        assert "abc123secret" not in result
        assert "hunter2" not in result
        assert "fine" in result
