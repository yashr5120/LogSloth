"""
config.py — Application configuration loaded from environment variables.
"""
from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()


class Config:
    """Centralised, immutable application configuration."""

    # Ollama
    OLLAMA_BASE_URL: str = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
    OLLAMA_MODEL: str = os.getenv("OLLAMA_MODEL", "gemma3:1b")
    OLLAMA_TIMEOUT: int = int(os.getenv("OLLAMA_TIMEOUT_SECONDS", "60"))

    # Paths
    LOG_DIR: Path = Path(os.getenv("LOG_DIR", "./sample_logs"))
    DB_PATH: Path = Path(os.getenv("DB_PATH", "./logsloth.db"))
    REPORTS_DIR: Path = Path(os.getenv("REPORTS_DIR", "./reports"))

    # Spike detection
    SPIKE_WINDOW_SECONDS: int = int(os.getenv("SPIKE_WINDOW_SECONDS", "300"))
    SPIKE_MULTIPLIER: float = float(os.getenv("SPIKE_MULTIPLIER", "3.0"))
    SPIKE_MIN_BASELINE: int = int(os.getenv("SPIKE_MIN_BASELINE", "5"))

    # AI evidence budget
    MAX_EVIDENCE_LINES: int = int(os.getenv("MAX_EVIDENCE_LINES", "40"))

    # Redaction
    REDACTION_PLACEHOLDER: str = "[REDACTED]"

    @classmethod
    def ensure_dirs(cls) -> None:
        cls.LOG_DIR.mkdir(parents=True, exist_ok=True)
        cls.REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        cls.DB_PATH.parent.mkdir(parents=True, exist_ok=True)
