"""
Local DuckDB database connection and table initialization for ULPF.
"""

from __future__ import annotations

from contextlib import contextmanager
import os
from pathlib import Path
import re
import time
from typing import Optional

import duckdb

# Determine database path
DEFAULT_DB_PATH = Path(
    os.getenv("ULPF_DATABASE_PATH")
    or os.getenv("ULPF_DB_PATH")
    or (Path(__file__).resolve().parent.parent.parent.parent / "ulpf.duckdb")
)

_GLOBAL_CONN: Optional[duckdb.DuckDBPyConnection] = None


class DatabaseLockError(duckdb.IOException):
    """Raised when DuckDB database file is locked by another process on Windows/POSIX."""

    def __init__(self, db_path: str, message: str, pid: Optional[int] = None):
        super().__init__(message)
        self.db_path = db_path
        self.pid = pid


def is_lock_error(exc: Exception) -> bool:
    """Check if exception represents a file locking conflict on Windows or Unix."""
    msg = str(exc).lower()
    return (
        "being used by another process" in msg
        or "could not set lock" in msg
        or ("cannot open file" in msg and "used by another process" in msg)
        or "file is already open" in msg
        or "lock conflict" in msg
    )


def connect_with_retry(
    path: str,
    read_only: bool = False,
    timeout: float = 5.0,
    retry_interval: float = 0.05,
) -> duckdb.DuckDBPyConnection:
    """Connect to DuckDB with bounded retry for handling transient cross-process Windows locks."""
    t0 = time.time()
    while True:
        try:
            return duckdb.connect(path, read_only=read_only)
        except duckdb.IOException as exc:
            if not is_lock_error(exc):
                raise
            elapsed = time.time() - t0
            if elapsed >= timeout:
                match = re.search(r"\(PID\s+(\d+)\)", str(exc))
                pid = int(match.group(1)) if match else None
                mode_str = "read-only" if read_only else "read-write"
                pid_info = f" (held by process PID {pid})" if pid else ""
                err_msg = (
                    f"DuckDB lock conflict: database file '{path}' is locked by another process{pid_info}. "
                    f"Failed to acquire {mode_str} lock after {timeout:.1f}s. "
                    "Ensure any concurrent operations have completed."
                )
                raise DatabaseLockError(db_path=path, message=err_msg, pid=pid) from exc
            time.sleep(retry_interval)


def reset_db_connection():
    """Reset and explicitly close the global DuckDB connection singleton."""
    global _GLOBAL_CONN
    if _GLOBAL_CONN is not None:
        try:
            _GLOBAL_CONN.close()
        except Exception:
            pass
        _GLOBAL_CONN = None


def close_db_connection(conn: Optional[duckdb.DuckDBPyConnection] = None):
    """Explicitly close a DuckDB connection or the global connection singleton."""
    global _GLOBAL_CONN
    if conn is not None and conn is not _GLOBAL_CONN:
        try:
            conn.close()
        except Exception:
            pass
    reset_db_connection()


@contextmanager
def get_db_connection(
    db_path: Optional[str | Path] = None,
    read_only: bool = False,
    timeout: Optional[float] = None,
):
    """Context manager for scoped DuckDB access that guarantees resource release on exit."""
    conn = get_db(db_path=db_path, read_only=read_only, timeout=timeout)
    try:
        yield conn
    finally:
        if db_path is not None or read_only:
            try:
                conn.close()
            except Exception:
                pass
        else:
            reset_db_connection()


def _init_db_schema(conn: duckdb.DuckDBPyConnection) -> None:
    """Initialize all ULPF database tables, columns, and indexes idempotently."""
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

    # 8. Ingestion Jobs Persistence
    conn.execute("""
    CREATE TABLE IF NOT EXISTS ingestion_jobs (
        job_id VARCHAR PRIMARY KEY,
        filename VARCHAR,
        file_size BIGINT,
        file_size_str VARCHAR,
        source VARCHAR,
        format VARCHAR,
        parser VARCHAR,
        parser_source VARCHAR,
        status VARCHAR,
        events_received INTEGER,
        events_parsed INTEGER,
        events_normalized INTEGER,
        events_stored INTEGER,
        validation_rate DOUBLE,
        accuracy DOUBLE,
        confidence DOUBLE,
        ollama_calls INTEGER,
        ollama_latency DOUBLE,
        ai_resolution_status VARCHAR,
        error VARCHAR,
        fingerprint VARCHAR,
        started_at TIMESTAMP,
        completed_at TIMESTAMP,
        elapsed_time_str VARCHAR,
        lifecycle_json TEXT,
        logs_json TEXT,
        created_at TIMESTAMP NOT NULL
    );
    """)

    try:
        conn.execute("ALTER TABLE pending_reviews ADD COLUMN IF NOT EXISTS rejection_reason VARCHAR;")
        conn.execute("ALTER TABLE pending_reviews ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP;")
        conn.execute("ALTER TABLE pending_reviews ADD COLUMN IF NOT EXISTS log_id VARCHAR;")
    except Exception:
        pass


def get_db(
    db_path: Optional[str | Path] = None,
    read_only: bool = False,
    timeout: Optional[float] = None,
) -> duckdb.DuckDBPyConnection:
    """Connect to local DuckDB and initialize tables with cached singleton."""
    global _GLOBAL_CONN

    lock_timeout = (
        timeout
        if timeout is not None
        else float(os.getenv("ULPF_DB_LOCK_TIMEOUT", "5.0"))
    )
    env_path = os.getenv("ULPF_DB_PATH") or os.getenv("ULPF_DATABASE_PATH")
    path = str(db_path or (Path(env_path) if env_path else DEFAULT_DB_PATH))

    # If caller requests read_only, and we already have an active read-write singleton, reuse cursor
    if read_only and db_path is None and _GLOBAL_CONN is not None:
        try:
            return _GLOBAL_CONN.cursor()
        except Exception:
            _GLOBAL_CONN = None

    # If caller requests read-write, return singleton cursor if available
    if not read_only and db_path is None and _GLOBAL_CONN is not None:
        try:
            return _GLOBAL_CONN.cursor()
        except Exception:
            _GLOBAL_CONN = None

    conn = connect_with_retry(path, read_only=read_only, timeout=lock_timeout)

    # ONLY cache read-write connections in _GLOBAL_CONN
    if not read_only:
        if db_path is None:
            _GLOBAL_CONN = conn
        elif _GLOBAL_CONN is None:
            _GLOBAL_CONN = conn

    if read_only:
        return conn

    _init_db_schema(conn)
    return conn
