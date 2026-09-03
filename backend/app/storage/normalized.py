"""
Normalized events storage, querying, analytics and export functions.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import duckdb
from app.models.event_schema import UnifiedEvent
from app.storage.db import get_db
from app.storage.raw import hash_raw_log, save_raw_event


def save_normalized_event(
    event: UnifiedEvent,
    raw_text: Optional[str] = None,
    source_file: Optional[str] = None,
    conn: Optional[duckdb.DuckDBPyConnection] = None,
) -> Tuple[str, str]:
    """Save both raw and normalized event into DuckDB."""
    c = conn or get_db()
    raw_payload = raw_text if raw_text is not None else event.raw_event
    raw_id = save_raw_event(raw_payload, source_file=source_file, conn=c)

    event.raw_event_id = raw_id
    now = datetime.now(timezone.utc)
    unmapped_str = json.dumps(event.unmapped) if event.unmapped else None

    c.execute(
        """
        INSERT OR REPLACE INTO normalized_events (
            event_id, raw_event_id, timestamp, category_name, category_uid,
            class_name, class_uid, activity_name, activity_id, type_name,
            type_uid, severity, severity_id, status, status_id, status_code,
            status_detail, message, src_ip, src_port, src_hostname,
            src_endpoint_name, dst_ip, dst_port, dst_hostname,
            dst_endpoint_name, protocol, direction, traffic_bytes,
            traffic_packets, user, user_uid, user_type, user_domain,
            auth_protocol, is_mfa, is_remote, logon_type, service_name,
            session_uid, vendor, product, product_version, log_format,
            log_name, unmapped, created_at
        ) VALUES (
            ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
            ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
            ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
            ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
            ?, ?, ?, ?, ?, ?, ?
        );
        """,
        [
            event.event_id, event.raw_event_id, event.timestamp, event.category_name, event.category_uid,
            event.class_name, event.class_uid, event.activity_name, event.activity_id, event.type_name,
            event.type_uid, event.severity, event.severity_id, event.status, event.status_id, event.status_code,
            event.status_detail, event.message, event.src_ip, event.src_port, event.src_hostname,
            event.src_endpoint_name, event.dst_ip, event.dst_port, event.dst_hostname,
            event.dst_endpoint_name, event.protocol, event.direction, event.traffic_bytes,
            event.traffic_packets, event.user, event.user_uid, event.user_type, event.user_domain,
            event.auth_protocol, event.is_mfa, event.is_remote, event.logon_type, event.service_name,
            event.session_uid, event.vendor, event.product, event.product_version, event.log_format,
            event.log_name, unmapped_str, now,
        ],
    )
    return event.event_id, raw_id


def save_events_batch(
    records: List[Tuple[UnifiedEvent, str, Optional[str]]],
    conn: Optional[duckdb.DuckDBPyConnection] = None,
) -> List[Tuple[str, str]]:
    """Batch insert normalized records and deduplicated raw logs using vectorized PyArrow / native staging for high throughput."""
    if not records:
        return []
    c = conn or get_db()
    now = datetime.now(timezone.utc)
    now_iso = now.isoformat()
    saved_pairs: List[Tuple[str, str]] = []

    raw_event_ids = []
    raw_texts = []
    received_ats = []
    source_files = []

    norm_dict = {
        "event_id": [], "raw_event_id": [], "timestamp": [], "category_name": [], "category_uid": [],
        "class_name": [], "class_uid": [], "activity_name": [], "activity_id": [], "type_name": [],
        "type_uid": [], "severity": [], "severity_id": [], "status": [], "status_id": [], "status_code": [],
        "status_detail": [], "message": [], "src_ip": [], "src_port": [], "src_hostname": [],
        "src_endpoint_name": [], "dst_ip": [], "dst_port": [], "dst_hostname": [],
        "dst_endpoint_name": [], "protocol": [], "direction": [], "traffic_bytes": [],
        "traffic_packets": [], "user": [], "user_uid": [], "user_type": [], "user_domain": [],
        "auth_protocol": [], "is_mfa": [], "is_remote": [], "logon_type": [], "service_name": [],
        "session_uid": [], "vendor": [], "product": [], "product_version": [], "log_format": [],
        "log_name": [], "unmapped": [], "created_at": [],
    }

    for event, raw_text, source_file in records:
        raw_payload = raw_text if raw_text is not None else event.raw_event
        raw_id = hash_raw_log(raw_payload)
        event.raw_event_id = raw_id

        raw_event_ids.append(raw_id)
        raw_texts.append(raw_payload)
        received_ats.append(now)
        source_files.append(source_file)

        unmapped_str = json.dumps(event.unmapped) if event.unmapped else None

        norm_dict["event_id"].append(event.event_id)
        norm_dict["raw_event_id"].append(event.raw_event_id)
        norm_dict["timestamp"].append(event.timestamp)
        norm_dict["category_name"].append(event.category_name)
        norm_dict["category_uid"].append(event.category_uid)
        norm_dict["class_name"].append(event.class_name)
        norm_dict["class_uid"].append(event.class_uid)
        norm_dict["activity_name"].append(event.activity_name)
        norm_dict["activity_id"].append(event.activity_id)
        norm_dict["type_name"].append(event.type_name)
        norm_dict["type_uid"].append(event.type_uid)
        norm_dict["severity"].append(event.severity)
        norm_dict["severity_id"].append(event.severity_id)
        norm_dict["status"].append(event.status)
        norm_dict["status_id"].append(event.status_id)
        norm_dict["status_code"].append(event.status_code)
        norm_dict["status_detail"].append(event.status_detail)
        norm_dict["message"].append(event.message)
        norm_dict["src_ip"].append(event.src_ip)
        norm_dict["src_port"].append(event.src_port)
        norm_dict["src_hostname"].append(event.src_hostname)
        norm_dict["src_endpoint_name"].append(event.src_endpoint_name)
        norm_dict["dst_ip"].append(event.dst_ip)
        norm_dict["dst_port"].append(event.dst_port)
        norm_dict["dst_hostname"].append(event.dst_hostname)
        norm_dict["dst_endpoint_name"].append(event.dst_endpoint_name)
        norm_dict["protocol"].append(event.protocol)
        norm_dict["direction"].append(event.direction)
        norm_dict["traffic_bytes"].append(event.traffic_bytes)
        norm_dict["traffic_packets"].append(event.traffic_packets)
        norm_dict["user"].append(event.user)
        norm_dict["user_uid"].append(event.user_uid)
        norm_dict["user_type"].append(event.user_type)
        norm_dict["user_domain"].append(event.user_domain)
        norm_dict["auth_protocol"].append(event.auth_protocol)
        norm_dict["is_mfa"].append(event.is_mfa)
        norm_dict["is_remote"].append(event.is_remote)
        norm_dict["logon_type"].append(event.logon_type)
        norm_dict["service_name"].append(event.service_name)
        norm_dict["session_uid"].append(event.session_uid)
        norm_dict["vendor"].append(event.vendor)
        norm_dict["product"].append(event.product)
        norm_dict["product_version"].append(event.product_version)
        norm_dict["log_format"].append(event.log_format)
        norm_dict["log_name"].append(event.log_name)
        norm_dict["unmapped"].append(unmapped_str)
        norm_dict["created_at"].append(now)

        saved_pairs.append((event.event_id, raw_id))

    # 1. Primary fast-path: PyArrow registration
    try:
        import pyarrow as pa
        raw_tbl = pa.Table.from_pydict({
            "raw_event_id": raw_event_ids,
            "raw_text": raw_texts,
            "received_at": received_ats,
            "source_file": source_files,
        })
        norm_tbl = pa.Table.from_pydict(norm_dict)

        c.register("_tmp_raw", raw_tbl)
        c.execute("INSERT OR IGNORE INTO raw_events SELECT * FROM _tmp_raw;")
        c.unregister("_tmp_raw")

        c.register("_tmp_norm", norm_tbl)
        c.execute("INSERT OR REPLACE INTO normalized_events SELECT * FROM _tmp_norm;")
        c.unregister("_tmp_norm")
        return saved_pairs
    except Exception:
        pass

    # 2. Secondary fast-path: Staged NDJSON loading via DuckDB read_json_auto
    try:
        import tempfile
        from pathlib import Path

        raw_ndjson = []
        for i in range(len(raw_event_ids)):
            raw_ndjson.append(json.dumps({
                "raw_event_id": raw_event_ids[i],
                "raw_text": raw_texts[i],
                "received_at": now_iso,
                "source_file": source_files[i],
            }) + "\n")

        norm_ndjson = []
        col_names = list(norm_dict.keys())
        for i in range(len(raw_event_ids)):
            row_dict = {}
            for k in col_names:
                val = norm_dict[k][i]
                if isinstance(val, datetime):
                    row_dict[k] = val.isoformat()
                else:
                    row_dict[k] = val
            norm_ndjson.append(json.dumps(row_dict) + "\n")

        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".json", encoding="utf-8") as tr:
            tr.writelines(raw_ndjson)
            r_path = Path(tr.name).as_posix()

        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".json", encoding="utf-8") as tn:
            tn.writelines(norm_ndjson)
            n_path = Path(tn.name).as_posix()

        try:
            c.execute(f"INSERT OR IGNORE INTO raw_events (raw_event_id, raw_text, received_at, source_file) SELECT raw_event_id, raw_text, received_at::TIMESTAMP, source_file FROM read_json_auto('{r_path}');")
            c.execute(f"INSERT OR REPLACE INTO normalized_events SELECT * FROM read_json_auto('{n_path}');")
            return saved_pairs
        finally:
            Path(r_path).unlink(missing_ok=True)
            Path(n_path).unlink(missing_ok=True)
    except Exception:
        pass

    # 3. Fallback: Chunked batch transaction (500 rows per query)
    batch_size = 500
    for i in range(0, len(raw_event_ids), batch_size):
        chunk_raw = [
            (raw_event_ids[j], raw_texts[j], received_ats[j], source_files[j])
            for j in range(i, min(i + batch_size, len(raw_event_ids)))
        ]
        ph = ", ".join(["(?, ?, ?, ?)"] * len(chunk_raw))
        params = [val for row in chunk_raw for val in row]
        c.execute(f"INSERT OR IGNORE INTO raw_events (raw_event_id, raw_text, received_at, source_file) VALUES {ph};", params)

    return saved_pairs


def get_total_events_count(
    format_filter: Optional[str] = None,
    search: Optional[str] = None,
    source_filter: Optional[str] = None,
    conn: Optional[duckdb.DuckDBPyConnection] = None,
) -> int:
    """Get total count of normalized events matching optional filters."""
    c = conn or get_db()
    where_clauses = []
    params: List[Any] = []

    if format_filter and format_filter.lower() != "all":
        where_clauses.append("LOWER(log_format) = ?")
        params.append(format_filter.lower())

    if source_filter and source_filter.strip():
        where_clauses.append("raw_event_id IN (SELECT raw_event_id FROM raw_events WHERE LOWER(source_file) = ?)")
        params.append(source_filter.strip().lower())

    if search and search.strip():
        term = f"%{search.strip().lower()}%"
        where_clauses.append(
            "("
            "LOWER(event_id) LIKE ? OR "
            "LOWER(message) LIKE ? OR "
            "LOWER(category_name) LIKE ? OR "
            "LOWER(vendor) LIKE ? OR "
            "LOWER(product) LIKE ? OR "
            "LOWER(user) LIKE ? OR "
            "LOWER(src_ip) LIKE ? OR "
            "LOWER(dst_ip) LIKE ? OR "
            "LOWER(src_hostname) LIKE ? OR "
            "LOWER(dst_hostname) LIKE ? OR "
            "LOWER(raw_event_id) LIKE ?"
            ")"
        )
        params.extend([term] * 11)

    where_sql = f"WHERE {' AND '.join(where_clauses)}" if where_clauses else ""
    query = f"SELECT count(*) FROM normalized_events {where_sql};"
    res = c.execute(query, params).fetchone()
    return res[0] if res else 0


def get_all_events(
    limit: int = 100,
    offset: int = 0,
    order_by: str = "created_at",
    direction: str = "desc",
    format_filter: Optional[str] = None,
    search: Optional[str] = None,
    source_filter: Optional[str] = None,
    conn: Optional[duckdb.DuckDBPyConnection] = None,
) -> List[Dict[str, Any]]:
    """Query normalized events sorted by newest ingest first by default."""
    c = conn or get_db()
    columns = [
        "event_id", "raw_event_id", "timestamp", "category_name", "category_uid",
        "class_name", "class_uid", "activity_name", "activity_id", "type_name",
        "type_uid", "severity", "severity_id", "status", "status_id", "status_code",
        "status_detail", "message", "src_ip", "src_port", "src_hostname",
        "src_endpoint_name", "dst_ip", "dst_port", "dst_hostname",
        "dst_endpoint_name", "protocol", "direction", "traffic_bytes",
        "traffic_packets", "user", "user_uid", "user_type", "user_domain",
        "auth_protocol", "is_mfa", "is_remote", "logon_type", "service_name",
        "session_uid", "vendor", "product", "product_version", "log_format",
        "log_name", "unmapped", "created_at"
    ]

    where_clauses = []
    params: List[Any] = []

    if format_filter and format_filter.lower() != "all":
        where_clauses.append("LOWER(log_format) = ?")
        params.append(format_filter.lower())

    if source_filter and source_filter.strip():
        where_clauses.append("raw_event_id IN (SELECT raw_event_id FROM raw_events WHERE LOWER(source_file) = ?)")
        params.append(source_filter.strip().lower())

    if search and search.strip():
        term = f"%{search.strip().lower()}%"
        where_clauses.append(
            "("
            "LOWER(event_id) LIKE ? OR "
            "LOWER(message) LIKE ? OR "
            "LOWER(category_name) LIKE ? OR "
            "LOWER(vendor) LIKE ? OR "
            "LOWER(product) LIKE ? OR "
            "LOWER(user) LIKE ? OR "
            "LOWER(src_ip) LIKE ? OR "
            "LOWER(dst_ip) LIKE ? OR "
            "LOWER(src_hostname) LIKE ? OR "
            "LOWER(dst_hostname) LIKE ? OR "
            "LOWER(raw_event_id) LIKE ?"
            ")"
        )
        params.extend([term] * 11)

    where_sql = f"WHERE {' AND '.join(where_clauses)}" if where_clauses else ""

    dir_str = "ASC" if direction.lower() == "asc" else "DESC"
    if order_by.lower() == "timestamp":
        order_sql = f"ORDER BY timestamp {dir_str} NULLS LAST, created_at DESC"
    else:
        order_sql = f"ORDER BY created_at {dir_str}, timestamp DESC NULLS LAST"

    query = f"SELECT {', '.join(columns)} FROM normalized_events {where_sql} {order_sql} LIMIT ? OFFSET ?;"
    params.extend([limit, offset])
    results = c.execute(query, params).fetchall()

    events = []
    for row in results:
        d = dict(zip(columns, row))
        if d.get("timestamp"):
            ts = d["timestamp"]
            if hasattr(ts, "strftime"):
                d["timestamp"] = ts.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
            else:
                d["timestamp"] = str(ts)
        if d.get("created_at"):
            ca = d["created_at"]
            if hasattr(ca, "strftime"):
                d["created_at"] = ca.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
            else:
                d["created_at"] = str(ca)
        if d.get("unmapped") and isinstance(d["unmapped"], str):
            try:
                d["unmapped"] = json.loads(d["unmapped"])
            except Exception:
                pass
        events.append(d)
    return events


def get_event_by_id(
    event_id: str,
    conn: Optional[duckdb.DuckDBPyConnection] = None,
) -> Optional[Dict[str, Any]]:
    """Retrieve normalized event joined with original raw log for full forensic traceability."""
    c = conn or get_db()
    query = """
    SELECT n.*, r.raw_text, r.received_at as raw_received_at, r.source_file
    FROM normalized_events n
    LEFT JOIN raw_events r ON n.raw_event_id = r.raw_event_id
    WHERE n.event_id = ?;
    """
    res = c.execute(query, [event_id]).fetchone()
    if not res:
        return None

    columns = [desc[0] for desc in c.description]
    data = dict(zip(columns, res))
    if data.get("timestamp"):
        data["timestamp"] = data["timestamp"].isoformat()
    if data.get("created_at"):
        data["created_at"] = data["created_at"].isoformat()
    if data.get("raw_received_at"):
        data["raw_received_at"] = data["raw_received_at"].isoformat()
    if data.get("unmapped") and isinstance(data["unmapped"], str):
        try:
            data["unmapped"] = json.loads(data["unmapped"])
        except Exception:
            pass
    return data


def get_stats(conn: Optional[duckdb.DuckDBPyConnection] = None) -> Dict[str, Any]:
    """Calculate aggregate statistics via DuckDB."""
    c = conn or get_db()
    total_norm = c.execute("SELECT count(*) FROM normalized_events;").fetchone()[0]
    total_raw = c.execute("SELECT count(*) FROM raw_events;").fetchone()[0]

    by_cat = [
        {"category": row[0] or "Unknown", "count": row[1]}
        for row in c.execute("SELECT category_name, count(*) FROM normalized_events GROUP BY category_name ORDER BY count(*) DESC;").fetchall()
    ]
    by_sev = [
        {"severity": row[0] or "Unknown", "count": row[1]}
        for row in c.execute("SELECT severity, count(*) FROM normalized_events GROUP BY severity ORDER BY count(*) DESC;").fetchall()
    ]
    by_fmt = [
        {"log_format": row[0] or "unknown", "count": row[1]}
        for row in c.execute("SELECT log_format, count(*) FROM normalized_events GROUP BY log_format ORDER BY count(*) DESC;").fetchall()
    ]

    return {
        "total_normalized_events": total_norm,
        "total_raw_events": total_raw,
        "by_category": by_cat,
        "by_severity": by_sev,
        "by_log_format": by_fmt,
    }


def export_to_parquet(
    target_path: str | Path,
    conn: Optional[duckdb.DuckDBPyConnection] = None,
) -> None:
    """Export normalized events to ZSTD-compressed Parquet."""
    c = conn or get_db()
    path_str = str(target_path)
    c.execute(f"COPY normalized_events TO '{path_str}' (FORMAT PARQUET, COMPRESSION ZSTD);")


def export_to_json(
    target_path: str | Path,
    format_filter: Optional[str] = None,
    search: Optional[str] = None,
    order_by: str = "created_at",
    direction: str = "desc",
    limit: Optional[int] = None,
    event_ids: Optional[List[str]] = None,
    conn: Optional[duckdb.DuckDBPyConnection] = None,
) -> None:
    """Export filtered or all normalized events to a formatted JSON file."""
    events = get_all_events(
        limit=limit or 100000,
        offset=0,
        order_by=order_by,
        direction=direction,
        format_filter=format_filter,
        search=search,
        conn=conn,
    )
    if event_ids:
        id_set = set(event_ids)
        events = [e for e in events if e.get("event_id") in id_set]

    path = Path(target_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(events, indent=2, default=str), encoding="utf-8")


def export_to_csv(
    target_path: str | Path,
    conn: Optional[duckdb.DuckDBPyConnection] = None,
) -> None:
    """Export normalized events to CSV file."""
    c = conn or get_db()
    path_str = str(target_path)
    c.execute(f"COPY normalized_events TO '{path_str}' (FORMAT CSV, HEADER true);")
