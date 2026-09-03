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

_GLOBAL_CONN: Optional[duckdb.DuckDBPyConnection] = None


def get_db(db_path: Optional[str | Path] = None, read_only: bool = False) -> duckdb.DuckDBPyConnection:
    """Connect to local DuckDB and initialize tables with cached singleton."""
    global _GLOBAL_CONN
    if db_path is None and _GLOBAL_CONN is not None:
        try:
            return _GLOBAL_CONN.cursor()
        except Exception:
            _GLOBAL_CONN = None

    env_path = os.getenv("ULPF_DB_PATH")
    path = str(db_path or (Path(env_path) if env_path else DEFAULT_DB_PATH))
    is_ro = read_only
    try:
        conn = duckdb.connect(path, read_only=is_ro)
    except duckdb.IOException as e:
        if "Could not set lock" in str(e):
            is_ro = True
            conn = duckdb.connect(path, read_only=True)
        else:
            raise e

    if db_path is None and _GLOBAL_CONN is None:
        _GLOBAL_CONN = conn

    if is_ro:
        return conn.cursor()

    # 1. Raw events table with hash-chaining ledger columns
    conn.execute("""
    CREATE TABLE IF NOT EXISTS raw_events (
        raw_event_id VARCHAR PRIMARY KEY,
        raw_text TEXT NOT NULL,
        received_at TIMESTAMP NOT NULL,
        source_file VARCHAR,
        previous_hash VARCHAR,
        seq_num BIGINT
    );
    """)
    try:
        conn.execute("ALTER TABLE raw_events ADD COLUMN IF NOT EXISTS previous_hash VARCHAR;")
        conn.execute("ALTER TABLE raw_events ADD COLUMN IF NOT EXISTS seq_num BIGINT;")
    except Exception:
        pass

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

    # 4. Pending Review Queue (Node 6)
    conn.execute("""
    CREATE TABLE IF NOT EXISTS pending_reviews (
        fingerprint VARCHAR PRIMARY KEY,
        format_name VARCHAR,
        suggested_mapping TEXT,
        confidence DOUBLE,
        sample_line TEXT,
        sibling_count INTEGER DEFAULT 1,
        status VARCHAR DEFAULT 'pending',
        created_at TIMESTAMP NOT NULL
    );
    """)

    # 5. Persistent Custom Parsers (Node 7)
    conn.execute("""
    CREATE TABLE IF NOT EXISTS custom_parsers (
        format_name VARCHAR PRIMARY KEY,
        fingerprint VARCHAR NOT NULL,
        pattern_regex TEXT NOT NULL,
        field_mapping TEXT NOT NULL,
        approved_by VARCHAR,
        approved_at TIMESTAMP NOT NULL
    );
    """)

    # 6. Blockchain Proof & Chain-of-Custody Ledger
    conn.execute("""
    CREATE TABLE IF NOT EXISTS blockchain_ledger (
        block_index BIGINT PRIMARY KEY,
        timestamp VARCHAR NOT NULL,
        event_id VARCHAR NOT NULL,
        action VARCHAR NOT NULL,
        event_hash VARCHAR NOT NULL,
        previous_hash VARCHAR NOT NULL,
        block_hash VARCHAR NOT NULL
    );
    """)

    # 7. AI Log Intelligence History & Review Audit
    conn.execute("""
    CREATE TABLE IF NOT EXISTS ai_history (
        history_id VARCHAR PRIMARY KEY,
        log_id VARCHAR,
        raw_log_sample TEXT,
        format_name VARCHAR,
        confidence DOUBLE,
        action VARCHAR,
        reviewer VARCHAR,
        reason TEXT,
        parser_config TEXT,
        created_at TIMESTAMP NOT NULL
    );
    """)

    try:
        conn.execute("ALTER TABLE pending_reviews ADD COLUMN IF NOT EXISTS rejection_reason VARCHAR;")
        conn.execute("ALTER TABLE pending_reviews ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP;")
        conn.execute("ALTER TABLE pending_reviews ADD COLUMN IF NOT EXISTS log_id VARCHAR;")
    except Exception:
        pass

    return conn
