"""
Persistent storage and management for the Human Review Queue (Node 6).
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import duckdb
from app.storage.db import get_db


def enqueue_for_review(
    fingerprint: str,
    format_name: str,
    suggested_mapping: Dict[str, Any],
    confidence: float,
    sample_line: str,
    conn: Optional[duckdb.DuckDBPyConnection] = None,
) -> bool:
    """
    Enqueue or increment sibling count for a structural log fingerprint.
    If fingerprint already exists in queue, increments sibling_count.
    """
    c = conn or get_db()
    mapping_str = json.dumps(suggested_mapping)
    now = datetime.now(timezone.utc)

    # Check if fingerprint already exists
    existing = c.execute(
        "SELECT sibling_count FROM pending_reviews WHERE fingerprint = ?",
        [fingerprint],
    ).fetchone()

    if existing:
        c.execute(
            "UPDATE pending_reviews SET sibling_count = sibling_count + 1 WHERE fingerprint = ?",
            [fingerprint],
        )
        return False
    else:
        c.execute(
            """
            INSERT INTO pending_reviews (
                fingerprint, format_name, suggested_mapping, confidence, sample_line, sibling_count, status, created_at
            ) VALUES (?, ?, ?, ?, ?, 1, 'pending', ?);
            """,
            [fingerprint, format_name, mapping_str, float(confidence), sample_line, now],
        )
        return True


def get_pending_reviews(conn: Optional[duckdb.DuckDBPyConnection] = None) -> List[Dict[str, Any]]:
    """Retrieve all pending log suggestions awaiting human review."""
    c = conn or get_db()
    rows = c.execute(
        """
        SELECT fingerprint, format_name, suggested_mapping, confidence, sample_line, sibling_count, status, created_at
        FROM pending_reviews
        WHERE status = 'pending'
        ORDER BY created_at DESC;
        """
    ).fetchall()

    reviews = []
    for r in rows:
        mapping = {}
        if r[2]:
            try:
                mapping = json.loads(r[2])
            except Exception:
                mapping = {}
        reviews.append({
            "fingerprint": r[0],
            "format_name": r[1],
            "suggested_mapping": mapping,
            "confidence": r[3],
            "sample_line": r[4],
            "sibling_count": r[5],
            "status": r[6],
            "created_at": r[7].isoformat() if r[7] else None,
        })
    return reviews


def get_review_by_fingerprint(
    fingerprint: str,
    conn: Optional[duckdb.DuckDBPyConnection] = None,
) -> Optional[Dict[str, Any]]:
    """Get a single review item by its fingerprint."""
    c = conn or get_db()
    r = c.execute(
        """
        SELECT fingerprint, format_name, suggested_mapping, confidence, sample_line, sibling_count, status, created_at
        FROM pending_reviews
        WHERE fingerprint = ?;
        """,
        [fingerprint],
    ).fetchone()
    if not r:
        return None

    mapping = {}
    if r[2]:
        try:
            mapping = json.loads(r[2])
        except Exception:
            mapping = {}

    return {
        "fingerprint": r[0],
        "format_name": r[1],
        "suggested_mapping": mapping,
        "confidence": r[3],
        "sample_line": r[4],
        "sibling_count": r[5],
        "status": r[6],
        "created_at": r[7].isoformat() if r[7] else None,
    }


def update_review_status(
    fingerprint: str,
    status: str,
    conn: Optional[duckdb.DuckDBPyConnection] = None,
) -> bool:
    """Update status of a review item (e.g. 'approved' or 'rejected')."""
    c = conn or get_db()
    c.execute(
        "UPDATE pending_reviews SET status = ? WHERE fingerprint = ?",
        [status, fingerprint],
    )
    return True
