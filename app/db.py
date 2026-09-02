"""SQLite storage: API keys and daily usage counters."""

from __future__ import annotations

import os
import secrets
import sqlite3
from contextlib import contextmanager
from datetime import date, datetime, timezone
from pathlib import Path

DB_PATH = Path(os.getenv("DOMAININTEL_DB", "data/domainintel.db"))

_SCHEMA = """
CREATE TABLE IF NOT EXISTS api_keys (
    key         TEXT PRIMARY KEY,
    label       TEXT NOT NULL,
    daily_limit INTEGER NOT NULL DEFAULT 100,
    active      INTEGER NOT NULL DEFAULT 1,
    created_at  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS usage (
    key   TEXT NOT NULL,
    day   TEXT NOT NULL,
    count INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (key, day)
);
"""


@contextmanager
def _conn():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db() -> None:
    with _conn() as c:
        c.executescript(_SCHEMA)


def create_key(label: str, daily_limit: int = 100) -> str:
    key = f"di_{secrets.token_urlsafe(24)}"
    with _conn() as c:
        c.execute(
            "INSERT INTO api_keys (key, label, daily_limit, created_at) VALUES (?, ?, ?, ?)",
            (key, label, daily_limit, datetime.now(timezone.utc).isoformat()),
        )
    return key


def check_and_count(key: str) -> tuple[bool, str]:
    """Atomically validate a key and consume one request from today's quota."""
    today = date.today().isoformat()
    with _conn() as c:
        row = c.execute(
            "SELECT daily_limit, active FROM api_keys WHERE key = ?", (key,)
        ).fetchone()
        if row is None:
            return False, "invalid API key"
        if not row["active"]:
            return False, "API key disabled"
        c.execute(
            "INSERT INTO usage (key, day, count) VALUES (?, ?, 0) "
            "ON CONFLICT(key, day) DO NOTHING",
            (key, today),
        )
        used = c.execute(
            "SELECT count FROM usage WHERE key = ? AND day = ?", (key, today)
        ).fetchone()["count"]
        if used >= row["daily_limit"]:
            return False, f"daily limit reached ({row['daily_limit']}/day)"
        c.execute(
            "UPDATE usage SET count = count + 1 WHERE key = ? AND day = ?", (key, today)
        )
    return True, "ok"


def key_stats(key: str) -> dict | None:
    today = date.today().isoformat()
    with _conn() as c:
        row = c.execute(
            "SELECT label, daily_limit, active FROM api_keys WHERE key = ?", (key,)
        ).fetchone()
        if row is None:
            return None
        used_row = c.execute(
            "SELECT count FROM usage WHERE key = ? AND day = ?", (key, today)
        ).fetchone()
    used = used_row["count"] if used_row else 0
    return {
        "label": row["label"],
        "daily_limit": row["daily_limit"],
        "used_today": used,
        "remaining_today": max(0, row["daily_limit"] - used),
        "active": bool(row["active"]),
    }
