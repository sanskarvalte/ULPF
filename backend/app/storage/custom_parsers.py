"""
Storage and lifecycle management for Approved Dynamic Custom Parsers (Node 7).
Persists custom parsers in DuckDB so they survive restarts.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import duckdb
from app.storage.db import get_db


def save_custom_parser(
    format_name: str,
    fingerprint: str,
    pattern_regex: str,
    field_mapping: Dict[str, Any],
    approved_by: Optional[str] = "admin",
    conn: Optional[duckdb.DuckDBPyConnection] = None,
) -> bool:
    """Save an approved custom parser to DuckDB custom_parsers table."""
    c = conn or get_db()
    mapping_str = json.dumps(field_mapping)
    now = datetime.now(timezone.utc)

    c.execute(
        """
        INSERT OR REPLACE INTO custom_parsers (
            format_name, fingerprint, pattern_regex, field_mapping, approved_by, approved_at
        ) VALUES (?, ?, ?, ?, ?, ?);
        """,
        [format_name, fingerprint, pattern_regex, mapping_str, approved_by, now],
    )
    return True


def list_custom_parsers(conn: Optional[duckdb.DuckDBPyConnection] = None) -> List[Dict[str, Any]]:
    """Retrieve all approved custom parsers."""
    c = conn or get_db()
    rows = c.execute(
        """
        SELECT format_name, fingerprint, pattern_regex, field_mapping, approved_by, approved_at
        FROM custom_parsers
        ORDER BY approved_at ASC;
        """
    ).fetchall()

    parsers = []
    for r in rows:
        mapping = {}
        if r[3]:
            try:
                mapping = json.loads(r[3])
            except Exception:
                mapping = {}
        parsers.append({
            "format_name": r[0],
            "fingerprint": r[1],
            "pattern_regex": r[2],
            "field_mapping": mapping,
            "approved_by": r[4],
            "approved_at": r[5].isoformat() if r[5] else None,
        })
    return parsers


def get_custom_parser(
    format_name: str,
    conn: Optional[duckdb.DuckDBPyConnection] = None,
) -> Optional[Dict[str, Any]]:
    """Retrieve a single custom parser by format name."""
    c = conn or get_db()
    r = c.execute(
        """
        SELECT format_name, fingerprint, pattern_regex, field_mapping, approved_by, approved_at
        FROM custom_parsers
        WHERE format_name = ?;
        """,
        [format_name],
    ).fetchone()
    if not r:
        return None

    mapping = {}
    if r[3]:
        try:
            mapping = json.loads(r[3])
        except Exception:
            mapping = {}

    return {
        "format_name": r[0],
        "fingerprint": r[1],
        "pattern_regex": r[2],
        "field_mapping": mapping,
        "approved_by": r[4],
        "approved_at": r[5].isoformat() if r[5] else None,
    }


def delete_custom_parser(
    format_name: str,
    conn: Optional[duckdb.DuckDBPyConnection] = None,
) -> bool:
    """Delete a custom parser."""
    c = conn or get_db()
    c.execute("DELETE FROM custom_parsers WHERE format_name = ?", [format_name])
    return True
