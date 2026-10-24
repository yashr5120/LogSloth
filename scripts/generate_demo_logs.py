"""
scripts/generate_demo_logs.py — Generate reproducible synthetic demo logs.

Run:  python scripts/generate_demo_logs.py

Generates sample_logs/demo_full.log covering all 8 required scenarios.
All credentials are fake test data.
"""
from __future__ import annotations

import random
import sys
from datetime import datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

OUTPUT = Path(__file__).parent.parent / "sample_logs" / "demo_full.log"
BASE_TIME = datetime(2024, 1, 15, 9, 0, 0)
random.seed(42)


def ts(offset_secs: float) -> str:
    return (BASE_TIME + timedelta(seconds=offset_secs)).strftime("%Y-%m-%dT%H:%M:%S.000+00:00")


lines: list[str] = []


def log(t: float, level: str, logger: str, msg: str) -> None:
    lines.append(f"{ts(t)} {level} {logger} {msg}")


# ----- Scenario 1: Startup -----
log(0, "INFO", "app.startup", "Application starting on port 8080")
log(1, "INFO", "app.db", "Connected to postgres at db-host:5432")
log(2, "INFO", "app.cache", "Redis cache connected")

# ----- Scenario 6: Warnings before cluster -----
for i in range(5):
    log(120 + i * 10, "WARNING", "app.db", "Connection pool utilisation rising: {:.0f}%".format(60 + i * 8))

# ----- Scenario 1+4: DB connection failures (gradual then sudden) -----
# Gradual increase
for i in range(5):
    log(200 + i * 30, "ERROR", "app.db", "OperationalError: could not connect to server: Connection refused")

# Sudden spike
for i in range(15):
    log(350 + i * 2, "ERROR", "app.db", "OperationalError: could not connect to server: Connection refused")

log(382, "CRITICAL", "app.db", "Database connection pool exhausted after 20 retries. Shutting down DB layer.")

# ----- Scenario 2: HTTP 5xx responses -----
for i in range(10):
    log(360 + i * 3, "ERROR", "app.web", "HTTPError: 503 Service Unavailable for url: https://api.payments.internal/charge")

log(395, "ERROR", "app.web", "HTTPError: 502 Bad Gateway for url: https://api.inventory.internal/stock")

# ----- Scenario 3: Python exceptions with full stack traces -----
log(410, "ERROR", "app.auth", """KeyError: 'user_role'
Traceback (most recent call last):
  File "/app/middleware/auth.py", line 34, in validate_token
    role = token_data['user_role']
KeyError: 'user_role'""")

log(420, "ERROR", "app.payment", """ConnectionError: HTTPSConnectionPool Max retries exceeded
Traceback (most recent call last):
  File "/app/services/payment.py", line 87, in process_payment
    response = requests.post(gateway_url, json=payload, timeout=30)
  File "/usr/lib/python3.11/site-packages/requests/adapters.py", line 565, in send
    raise ConnectionError(e, request=request)
requests.exceptions.ConnectionError: HTTPSConnectionPool(host='api.payments.internal', port=443): Max retries exceeded""")

# ----- Scenario 5: Warnings preceding error cluster -----
for i in range(4):
    log(430 + i * 5, "WARNING", "app.cache", "High cache miss rate: {:.0f}%".format(75 + i * 5))

log(451, "ERROR", "app.cache", "CacheConnectionError: Redis connection lost after 3 retries")
log(452, "ERROR", "app.cache", "CacheConnectionError: Redis connection lost after 3 retries")

# ----- Scenario 7: Sensitive-looking test credentials (must be redacted) -----
log(460, "WARNING", "app.config", "Test environment detected: api_key=sk-test-FAKECREDENTIAL12345 (not real)")
log(461, "WARNING", "app.config", "DB URL: postgres://testuser:FakeTestPassword@localhost:5432/testdb")

# ----- Scenario 8: Unrelated errors that must not be grouped together -----
log(470, "ERROR", "app.import", "ImportError: No module named 'missing_analytics_plugin'")
log(471, "ERROR", "app.db", "TypeError: unsupported operand type(s) for +: 'int' and 'NoneType'")
log(472, "ERROR", "app.auth", "ValueError: Token expired or invalid JWT signature")

# ----- Scenario 6: Malformed entries -----
lines.append("MALFORMED_ENTRY: {broken json }")
lines.append("just some plain text that has no timestamp or severity level at all")
lines.append(">>> weird shell-looking line from log aggregator")

# ----- Recovery -----
log(600, "INFO", "app.db", "Reconnecting to database...")
log(602, "INFO", "app.db", "Database connection restored successfully")
log(605, "INFO", "app.web", "Service fully recovered — resuming normal operations")


OUTPUT.parent.mkdir(parents=True, exist_ok=True)
OUTPUT.write_text("\n".join(lines) + "\n", encoding="utf-8")
print(f"Generated {len(lines)} log lines -> {OUTPUT}")
print()
print("Expected groupings:")
print("  1. OperationalError (DB connection) — ~20 occurrences (spike at t=350s)")
print("  2. HTTPError 503 (payment gateway) — ~10 occurrences")
print("  3. HTTPError 502 (inventory) — 1 occurrence")
print("  4. KeyError 'user_role' — 1 occurrence")
print("  5. ConnectionError (payment service) — 1 occurrence")
print("  6. CacheConnectionError — 2 occurrences")
print("  7. ImportError (missing plugin) — 1 occurrence")
print("  8. TypeError (NoneType) — 1 occurrence")
print("  9. ValueError (JWT) — 1 occurrence")
print()
print("Scenarios 7 (fake credentials) and 6 (malformed) should be redacted/unparsed.")
