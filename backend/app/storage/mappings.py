"""
Storage for log source registrations and custom schema mapping rules.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import duckdb
from app.storage.db import get_db


def register_source(
    source_name: str,
    format: str,
    vendor: Optional[str] = None,
    product: Optional[str] = None,
    mapping_rules: Optional[Dict[str, Any]] = None,
    conn: Optional[duckdb.DuckDBPyConnection] = None,
) -> str:
    """Register a new log source and optional mapping definition."""
    c = conn or get_db()
    source_id = str(uuid.uuid4())
    rules_json = json.dumps(mapping_rules) if mapping_rules else None
    now = datetime.now(timezone.utc)

    c.execute(
        """
        INSERT OR REPLACE INTO source_registry (
            source_id, source_name, format, vendor, product, mapping_rules, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?);
        """,
        [source_id, source_name, format, vendor, product, rules_json, now],
    )
    return source_id


def list_registered_sources(conn: Optional[duckdb.DuckDBPyConnection] = None) -> List[Dict[str, Any]]:
    """List all registered log sources."""
    c = conn or get_db()
    rows = c.execute(
        "SELECT source_id, source_name, format, vendor, product, mapping_rules, created_at FROM source_registry ORDER BY created_at DESC;"
    ).fetchall()

    sources = []
    for r in rows:
        rules = None
        if r[5]:
            try:
                rules = json.loads(r[5])
            except Exception:
                pass
        sources.append({
            "source_id": r[0],
            "source_name": r[1],
            "format": r[2],
            "vendor": r[3],
            "product": r[4],
            "mapping_rules": rules,
            "created_at": r[6].isoformat() if r[6] else None,
        })
    return sources
