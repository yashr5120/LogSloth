"""
logsloth/collector.py — File ingestion and optional file-following.

Reads log files from a configured directory. Supports optional tail-style
following via Watchdog (polling mode for Windows compatibility).
"""
from __future__ import annotations

import time
from pathlib import Path
from threading import Event, Thread
from typing import Callable

from logsloth.models import LogEntry
from logsloth.parser import parse_file


def collect_files(
    log_dir: Path,
    *,
    extensions: tuple[str, ...] = (".log", ".txt", ".out"),
) -> list[Path]:
    """Return all log files under *log_dir* matching *extensions*."""
    if not log_dir.exists():
        return []
    return sorted(
        p for p in log_dir.rglob("*") if p.suffix in extensions and p.is_file()
    )


def ingest_directory(
    log_dir: Path,
    *,
    extensions: tuple[str, ...] = (".log", ".txt", ".out"),
    redact: bool = True,
) -> list[LogEntry]:
    """Parse all log files in *log_dir* and return a flat list of entries."""
    all_entries: list[LogEntry] = []
    for path in collect_files(log_dir, extensions=extensions):
        all_entries.extend(parse_file(path, redact=redact))
    return all_entries


# ---------------------------------------------------------------------------
# Optional file-following (non-blocking, thread-based)
# ---------------------------------------------------------------------------

class LogTailer:
    """
    Tail one or more log files and invoke *callback* with new LogEntry objects.

    Uses polling to remain compatible with Windows filesystems.
    Bind file paths explicitly — never scans arbitrary directories.
    """

    def __init__(
        self,
        paths: list[Path],
        callback: Callable[[list[LogEntry]], None],
        poll_interval: float = 1.0,
    ) -> None:
        self._paths = paths
        self._callback = callback
        self._poll_interval = poll_interval
        self._offsets: dict[Path, int] = {p: 0 for p in paths}
        self._stop_event = Event()
        self._thread: Thread | None = None

    def start(self) -> None:
        self._stop_event.clear()
        self._thread = Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=5)

    def _run(self) -> None:
        from logsloth.parser import parse_lines

        while not self._stop_event.is_set():
            for path in self._paths:
                try:
                    size = path.stat().st_size
                    offset = self._offsets.get(path, 0)
                    if size <= offset:
                        continue
                    with path.open("r", encoding="utf-8", errors="replace") as fh:
                        fh.seek(offset)
                        new_lines = fh.readlines()
                        self._offsets[path] = fh.tell()
                    if new_lines:
                        entries = parse_lines(new_lines, str(path))
                        if entries:
                            self._callback(entries)
                except OSError:
                    pass
            time.sleep(self._poll_interval)
