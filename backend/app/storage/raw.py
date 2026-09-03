"""
Raw log storage, hash-chained tamper-evident ledger, and replay detection module (DuckDB raw_events).
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import duckdb
from app.storage.db import get_db

GENESIS_HASH = "0" * 64


def hash_raw_log(raw_text: str, previous_hash: Optional[str] = None) -> str:
    """
    Compute cryptographic SHA-256 hash.
    When previous_hash is provided, creates a cryptographically linked payload.
    When previous_hash is None, computes direct SHA-256 of raw_text.
    """
    if previous_hash:
        payload = raw_text.encode("utf-8") + previous_hash.encode("utf-8")
    else:
        payload = raw_text.encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def get_latest_hash(source_file: Optional[str] = None, conn: Optional[duckdb.DuckDBPyConnection] = None) -> Tuple[str, int]:
    """Retrieve the latest hash and sequence number in the ledger for a source."""
    c = conn or get_db()
    if source_file:
        res = c.execute(
            """
            SELECT raw_event_id, seq_num
            FROM raw_events
            WHERE source_file = ?
            ORDER BY seq_num DESC NULLS LAST, received_at DESC
            LIMIT 1
            """,
            [source_file],
        ).fetchone()
    else:
        res = c.execute(
            """
            SELECT raw_event_id, seq_num
            FROM raw_events
            ORDER BY seq_num DESC NULLS LAST, received_at DESC
            LIMIT 1
            """
        ).fetchone()

    if not res or not res[0]:
        return (GENESIS_HASH, 0)
    last_hash = str(res[0])
    last_seq = int(res[1]) if res[1] is not None else 0
    return (last_hash, last_seq)


def save_raw_event(
    raw_text: str,
    source_file: Optional[str] = None,
    conn: Optional[duckdb.DuckDBPyConnection] = None,
) -> str:
    """
    Save raw event to DuckDB hash-chained ledger.
    raw_event_id = SHA256(raw_text)
    previous_hash = preceding entry raw_event_id
    seq_num = monotonic increment
    """
    c = conn or get_db()
    prev_hash, last_seq = get_latest_hash(source_file, conn=c)
    current_seq = last_seq + 1
    raw_id = hash_raw_log(raw_text)
    now = datetime.now(timezone.utc)

    c.execute(
        """
        INSERT OR IGNORE INTO raw_events (raw_event_id, raw_text, received_at, source_file, previous_hash, seq_num)
        VALUES (?, ?, ?, ?, ?, ?);
        """,
        [raw_id, raw_text, now, source_file, prev_hash, current_seq],
    )
    return raw_id


def save_raw_events_batch(
    records: List[Tuple[str, str, Optional[str]]],
    conn: Optional[duckdb.DuckDBPyConnection] = None,
) -> None:
    """
    Batch save raw events preserving hash-chain links and monotonic sequence ordering.
    Records format: [(raw_id, raw_text, source_file), ...]
    """
    if not records:
        return
    c = conn or get_db()
    now = datetime.now(timezone.utc)

    # Group by source_file to maintain distinct sequential chains
    source_records: Dict[Optional[str], List[Tuple[str, str]]] = {}
    for raw_id, raw_text, source_file in records:
        source_records.setdefault(source_file, []).append((raw_id, raw_text))

    rows_to_insert: List[Tuple[str, str, datetime, Optional[str], str, int]] = []

    for source_file, items in source_records.items():
        prev_hash, last_seq = get_latest_hash(source_file, conn=c)
        for raw_id, raw_text in items:
            last_seq += 1
            canonical_id = hash_raw_log(raw_text)
            rows_to_insert.append(
                (canonical_id, raw_text, now, source_file, prev_hash, last_seq)
            )
            prev_hash = canonical_id

    c.executemany(
        """
        INSERT OR IGNORE INTO raw_events (raw_event_id, raw_text, received_at, source_file, previous_hash, seq_num)
        VALUES (?, ?, ?, ?, ?, ?);
        """,
        rows_to_insert,
    )


def verify_chain(
    source_file: Optional[str] = None,
    conn: Optional[duckdb.DuckDBPyConnection] = None,
) -> Tuple[bool, int, List[Dict[str, Any]]]:
    """
    Walk the full ledger sequence and verify hash chain integrity.
    Detects ANY break, modification, insertion, deletion, or reordering.
    Returns (is_valid, checked_count, violations).
    """
    c = conn or get_db()
    if source_file:
        rows = c.execute(
            """
            SELECT raw_event_id, raw_text, previous_hash, seq_num
            FROM raw_events
            WHERE source_file = ?
            ORDER BY seq_num ASC NULLS LAST, received_at ASC
            """,
            [source_file],
        ).fetchall()
    else:
        rows = c.execute(
            """
            SELECT raw_event_id, raw_text, previous_hash, seq_num
            FROM raw_events
            ORDER BY seq_num ASC NULLS LAST, received_at ASC
            """
        ).fetchall()

    if not rows:
        return (True, 0, [])

    violations: List[Dict[str, Any]] = []
    expected_prev = GENESIS_HASH

    for idx, (raw_id, raw_text, prev_hash, seq_num) in enumerate(rows):
        # 1. Verify previous hash linkage (catches deletion, insertion, reordering)
        if idx > 0 and prev_hash is not None and prev_hash != expected_prev:
            violations.append({
                "index": idx,
                "seq_num": seq_num,
                "raw_event_id": raw_id,
                "error": "Broken chain link: previous_hash does not match preceding event hash",
                "expected_previous_hash": expected_prev,
                "actual_previous_hash": prev_hash,
            })

        # 2. Verify hash content integrity (catches content modification)
        calc_id = hash_raw_log(raw_text)
        if raw_id != calc_id:
            violations.append({
                "index": idx,
                "seq_num": seq_num,
                "raw_event_id": raw_id,
                "error": "Tampered content: raw_event_id does not match recalculated hash of raw_text",
                "expected_hash": calc_id,
                "actual_hash": raw_id,
            })

        if prev_hash is not None:
            expected_prev = raw_id

    is_valid = len(violations) == 0
    return (is_valid, len(rows), violations)


def detect_duplicate(
    raw_text: str,
    source_file: Optional[str] = None,
    conn: Optional[duckdb.DuckDBPyConnection] = None,
) -> bool:
    """
    Check if the exact raw text has been ingested previously (for replay/duplicate detection).
    """
    c = conn or get_db()
    direct_hash = hashlib.sha256(raw_text.encode("utf-8")).hexdigest()
    if source_file:
        res = c.execute(
            "SELECT 1 FROM raw_events WHERE (raw_event_id = ? OR raw_text = ?) AND source_file = ? LIMIT 1",
            [direct_hash, raw_text, source_file],
        ).fetchone()
    else:
        res = c.execute(
            "SELECT 1 FROM raw_events WHERE raw_event_id = ? OR raw_text = ? LIMIT 1",
            [direct_hash, raw_text],
        ).fetchone()
    return res is not None


def get_raw_event(
    raw_event_id: str,
    conn: Optional[duckdb.DuckDBPyConnection] = None,
) -> Optional[dict]:
    """Retrieve raw event by its ID."""
    c = conn or get_db()
    res = c.execute(
        "SELECT raw_event_id, raw_text, received_at, source_file, previous_hash, seq_num FROM raw_events WHERE raw_event_id = ?",
        [raw_event_id],
    ).fetchone()
    if not res:
        return None
    return {
        "raw_event_id": res[0],
        "raw_text": res[1],
        "received_at": res[2].isoformat() if res[2] else None,
        "source_file": res[3],
        "previous_hash": res[4],
        "seq_num": res[5],
    }
