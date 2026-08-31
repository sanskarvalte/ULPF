"""
Local DuckDB database connection and table initialization for ULPF.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

import duckdb

# Determine database path
DEFAULT_DB_PATH = Path(
    os.getenv("ULPF_DB_PATH")
    or (Path(__file__).resolve().parent.parent.parent.parent / "ulpf.duckdb")
)


def get_db(db_path: Optional[str | Path] = None, read_only: bool = False) -> duckdb.DuckDBPyConnection:
    """Connect to local DuckDB and initialize tables."""
    env_path = os.getenv("ULPF_DB_PATH")
    path = str(db_path or (Path(env_path) if env_path else DEFAULT_DB_PATH))
    try:
        conn = duckdb.connect(path, read_only=read_only)
    except duckdb.IOException as e:
        if "Could not set lock" in str(e) and not read_only:
            try:
                conn = duckdb.connect(path, read_only=True)
                return conn
            except Exception:
                raise e
        raise e

    # 1. Raw events table
    conn.execute("""
    CREATE TABLE IF NOT EXISTS raw_events (
        raw_event_id VARCHAR PRIMARY KEY,
        raw_text TEXT NOT NULL,
        received_at TIMESTAMP NOT NULL,
        source_file VARCHAR
    );
    """)

    # 2. Normalized events table
    conn.execute("""
    CREATE TABLE IF NOT EXISTS normalized_events (
        event_id VARCHAR PRIMARY KEY,
        raw_event_id VARCHAR,
        timestamp TIMESTAMP,
        category_name VARCHAR,
        category_uid INTEGER,
        class_name VARCHAR,
        class_uid INTEGER,
        activity_name VARCHAR,
        activity_id INTEGER,
        type_name VARCHAR,
        type_uid INTEGER,
        severity VARCHAR,
        severity_id INTEGER,
        status VARCHAR,
        status_id INTEGER,
        status_code VARCHAR,
        status_detail VARCHAR,
        message VARCHAR,
        src_ip VARCHAR,
        src_port INTEGER,
        src_hostname VARCHAR,
        src_endpoint_name VARCHAR,
        dst_ip VARCHAR,
        dst_port INTEGER,
        dst_hostname VARCHAR,
        dst_endpoint_name VARCHAR,
        protocol VARCHAR,
        direction VARCHAR,
        traffic_bytes BIGINT,
        traffic_packets BIGINT,
        user VARCHAR,
        user_uid VARCHAR,
        user_type VARCHAR,
        user_domain VARCHAR,
        auth_protocol VARCHAR,
        is_mfa BOOLEAN,
        is_remote BOOLEAN,
        logon_type VARCHAR,
        service_name VARCHAR,
        session_uid VARCHAR,
        vendor VARCHAR,
        product VARCHAR,
        product_version VARCHAR,
        log_format VARCHAR,
        log_name VARCHAR,
        unmapped TEXT,
        created_at TIMESTAMP NOT NULL
    );
    """)

    # 3. Source registrations & Schema Mappings table
    conn.execute("""
    CREATE TABLE IF NOT EXISTS source_registry (
        source_id VARCHAR PRIMARY KEY,
        source_name VARCHAR NOT NULL,
        format VARCHAR NOT NULL,
        vendor VARCHAR,
        product VARCHAR,
        mapping_rules TEXT,
        created_at TIMESTAMP NOT NULL
    );
    """)

    return conn
