"""
Raw log storage and deduplication module (DuckDB raw_events).
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import duckdb
from app.storage.db import get_db


def hash_raw_log(raw_text: str) -> str:
    """Compute SHA-256 hash of raw log string."""
    return hashlib.sha256(raw_text.encode("utf-8")).hexdigest()


def save_raw_event(
    raw_text: str,
    source_file: Optional[str] = None,
    conn: Optional[duckdb.DuckDBPyConnection] = None,
) -> str:
    """Save raw event text to DuckDB raw_events table with deduplication."""
    c = conn or get_db()
    raw_id = hash_raw_log(raw_text)
    now = datetime.now(timezone.utc)

    c.execute(
        """
        INSERT OR IGNORE INTO raw_events (raw_event_id, raw_text, received_at, source_file)
        VALUES (?, ?, ?, ?);
        """,
        [raw_id, raw_text, now, source_file],
    )
    return raw_id


def get_raw_event(
    raw_event_id: str,
    conn: Optional[duckdb.DuckDBPyConnection] = None,
) -> Optional[dict]:
    """Retrieve raw event by its SHA-256 ID."""
    c = conn or get_db()
    res = c.execute(
        "SELECT raw_event_id, raw_text, received_at, source_file FROM raw_events WHERE raw_event_id = ?",
        [raw_event_id],
    ).fetchone()
    if not res:
        return None
    return {
        "raw_event_id": res[0],
        "raw_text": res[1],
        "received_at": res[2].isoformat() if res[2] else None,
        "source_file": res[3],
    }
