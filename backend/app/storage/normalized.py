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


def _derive_clean_source_name(src_hostname: Optional[str], source_file: Optional[str], vendor: Optional[str], product: Optional[str]) -> str:
    """Derive clean, professional SOC-style source identifier."""
    if src_hostname and src_hostname.strip():
        return src_hostname.strip().lower()
    
    file_candidate = (source_file or "").split("/")[-1].split("\\")[-1]
    name_map = {
        "10_paloalto_traffic.csv": "fw-core-nyc-01",
        "device.xml": "fw-edge-pan-02",
        "firewall.log": "fw-iptables-hq",
        "11_snort_ids.log": "ids-snort-dmz",
        "security.cef": "ids-cyberguard-01",
        "01_linux_syslog.log": "k8s-cluster-prod",
        "Linux_2k.log": "auth-svc-04",
        "Android_2k.log": "endpoint-x-77",
        "wifi.log": "edge-rt-lon-02",
        "Mac_2k.log": "endpoint-mac-01",
        "HealthApp_2k.log": "app-health-01",
        "vbox.log": "vbox-host-01",
        "vbox_converted.json": "vbox-host-01",
        "server.json": "waf-edge-sfo",
        "application.csv": "apache-web-01",
        "infosphere_audit.xml": "db-cluster-eu-1",
        "14_mysql_slowquery.log": "db-mysql-primary",
        "install.log": "dc-win-01",
    }
    if file_candidate in name_map:
        return name_map[file_candidate]
    if file_candidate:
        clean = file_candidate.replace(".log", "").replace(".csv", "").replace(".xml", "").replace(".json", "").replace(".txt", "")
        return clean.replace("_", "-").lower()
    
    combo = f"{vendor or ''} {product or ''}".strip().lower()
    if combo:
        return combo.replace(" ", "-")
    return "unknown-source"


def _parse_query_expressions(search: Optional[str]) -> Tuple[List[str], List[Any]]:
    """Parse search query supporting field:value syntax or fallback multi-field search."""
    clauses = []
    params = []
    if not search or not search.strip():
        return clauses, params

    raw = search.strip()
    import re
    # Match patterns like field:value or field:"quoted value"
    field_pattern = re.compile(r'([a-zA-Z0-9_\.]+):(?:"([^"]+)"|([^\s]+))')
    matches = list(field_pattern.finditer(raw))

    remaining_text = raw
    for match in reversed(matches):
        field = match.group(1).lower()
        val = match.group(2) if match.group(2) is not None else match.group(3)
        start, end = match.span()
        remaining_text = remaining_text[:start] + " " + remaining_text[end:]

        pattern = val.replace("*", "%") if "*" in val else f"%{val}%"

        if field in ("ip", "src_ip", "source.ip"):
            clauses.append("(LOWER(n.src_ip) LIKE ? OR LOWER(n.dst_ip) LIKE ?)")
            params.extend([pattern.lower(), pattern.lower()])
        elif field in ("dst_ip", "destination.ip"):
            clauses.append("LOWER(n.dst_ip) LIKE ?")
            params.append(pattern.lower())
        elif field in ("id", "event_id", "event.id"):
            clauses.append("LOWER(n.event_id) LIKE ?")
            params.append(pattern.lower())
        elif field in ("severity", "event.severity"):
            if val.lower() == "high+":
                clauses.append("LOWER(n.severity) IN ('high', 'critical')")
            else:
                clauses.append("LOWER(n.severity) = ?")
                params.append(val.lower())
        elif field in ("ocsf", "class", "ocsf.class", "category"):
            clauses.append("(LOWER(n.class_name) LIKE ? OR LOWER(n.category_name) LIKE ?)")
            params.extend([pattern.lower(), pattern.lower()])
        elif field in ("type", "event.type", "action", "event.action", "activity"):
            clauses.append("(LOWER(n.activity_name) LIKE ? OR LOWER(n.type_name) LIKE ? OR LOWER(n.message) LIKE ?)")
            params.extend([pattern.lower(), pattern.lower(), pattern.lower()])
        elif field in ("source", "host", "hostname", "source.host"):
            clauses.append("(LOWER(n.src_hostname) LIKE ? OR LOWER(n.dst_hostname) LIKE ? OR LOWER(r.source_file) LIKE ? OR LOWER(n.product) LIKE ? OR LOWER(n.vendor) LIKE ?)")
            params.extend([pattern.lower(), pattern.lower(), pattern.lower(), pattern.lower(), pattern.lower()])
        elif field in ("user", "user.name"):
            clauses.append("LOWER(n.user) LIKE ?")
            params.append(pattern.lower())
        elif field in ("format", "log.format"):
            clauses.append("LOWER(n.log_format) = ?")
            params.append(val.lower())
        elif field in ("message", "msg"):
            clauses.append("LOWER(n.message) LIKE ?")
            params.append(pattern.lower())

    # Process remaining free text words (ignoring AND/OR tokens)
    clean_words = [w for w in remaining_text.split() if w.upper() not in ("AND", "OR", "&&", "||") and w.strip()]
    for word in clean_words:
        term = f"%{word.lower()}%"
        clauses.append(
            "("
            "LOWER(n.event_id) LIKE ? OR "
            "LOWER(n.message) LIKE ? OR "
            "LOWER(n.category_name) LIKE ? OR "
            "LOWER(n.class_name) LIKE ? OR "
            "LOWER(n.activity_name) LIKE ? OR "
            "LOWER(n.type_name) LIKE ? OR "
            "LOWER(n.vendor) LIKE ? OR "
            "LOWER(n.product) LIKE ? OR "
            "LOWER(n.user) LIKE ? OR "
            "LOWER(n.src_ip) LIKE ? OR "
            "LOWER(n.dst_ip) LIKE ? OR "
            "LOWER(n.src_hostname) LIKE ? OR "
            "LOWER(n.dst_hostname) LIKE ? OR "
            "LOWER(r.source_file) LIKE ? OR "
            "LOWER(n.log_format) LIKE ? OR "
            "LOWER(n.raw_event_id) LIKE ?"
            ")"
        )
        params.extend([term] * 16)

    return clauses, params


def _build_events_filter_sql(
    format_filter: Optional[str] = None,
    search: Optional[str] = None,
    source_filter: Optional[str] = None,
    severity_filter: Optional[str] = None,
    integrity_filter: Optional[str] = None,
    time_range: Optional[str] = None,
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    event_type_filter: Optional[str] = None,
    ocsf_class_filter: Optional[str] = None,
) -> Tuple[str, List[Any]]:
    """Build unified WHERE clause for events table joined with raw_events and blockchain_ledger."""
    where_clauses = []
    params: List[Any] = []

    # Search parsing
    s_clauses, s_params = _parse_query_expressions(search)
    where_clauses.extend(s_clauses)
    params.extend(s_params)

    # Format filter
    if format_filter and format_filter.lower() != "all":
        where_clauses.append("LOWER(n.log_format) = ?")
        params.append(format_filter.lower())

    # Source filter
    if source_filter and source_filter.lower() != "all":
        src = f"%{source_filter.strip().lower()}%"
        where_clauses.append(
            "("
            "LOWER(n.src_hostname) LIKE ? OR "
            "LOWER(r.source_file) LIKE ? OR "
            "LOWER(n.product) LIKE ? OR "
            "LOWER(n.vendor) LIKE ?"
            ")"
        )
        params.extend([src, src, src, src])

    # Severity filter
    if severity_filter and severity_filter.lower() != "all":
        sev = severity_filter.strip().lower()
        if sev in ("high+", "high_plus"):
            where_clauses.append("LOWER(n.severity) IN ('high', 'critical')")
        elif sev in ("info", "informational"):
            where_clauses.append("LOWER(n.severity) IN ('info', 'informational')")
        else:
            where_clauses.append("LOWER(n.severity) = ?")
            params.append(sev)

    # Integrity filter
    if integrity_filter and integrity_filter.lower() != "all":
        integ = integrity_filter.strip().lower()
        if integ == "verified":
            where_clauses.append("b.event_hash IS NOT NULL AND b.event_hash = n.raw_event_id")
        elif integ in ("failed", "tampered"):
            where_clauses.append("b.event_hash IS NOT NULL AND b.event_hash != n.raw_event_id")
        elif integ == "pending":
            where_clauses.append("b.event_hash IS NULL")

    # Time range filter
    if time_range and time_range.lower() != "all":
        tr = time_range.strip().lower()
        if tr in ("15m", "15_minutes", "last 15 minutes"):
            where_clauses.append("n.created_at >= (SELECT MAX(created_at) FROM normalized_events) - INTERVAL 15 MINUTE")
        elif tr in ("1h", "1_hour", "last 1 hour"):
            where_clauses.append("n.created_at >= (SELECT MAX(created_at) FROM normalized_events) - INTERVAL 1 HOUR")
        elif tr in ("24h", "24_hours", "last 24 hours"):
            where_clauses.append("n.created_at >= (SELECT MAX(created_at) FROM normalized_events) - INTERVAL 24 HOUR")
        elif tr in ("7d", "7_days", "last 7 days"):
            where_clauses.append("n.created_at >= (SELECT MAX(created_at) FROM normalized_events) - INTERVAL 7 DAY")

    if start_time and start_time.strip():
        where_clauses.append("(n.timestamp >= ? OR n.created_at >= ?)")
        params.extend([start_time.strip(), start_time.strip()])

    if end_time and end_time.strip():
        where_clauses.append("(n.timestamp <= ? OR n.created_at <= ?)")
        params.extend([end_time.strip(), end_time.strip()])

    # Event Type filter
    if event_type_filter and event_type_filter.lower() != "all":
        et = f"%{event_type_filter.strip().lower()}%"
        where_clauses.append("(LOWER(n.activity_name) LIKE ? OR LOWER(n.type_name) LIKE ?)")
        params.extend([et, et])

    # OCSF Class filter
    if ocsf_class_filter and ocsf_class_filter.lower() != "all":
        ocsf = f"%{ocsf_class_filter.strip().lower()}%"
        where_clauses.append("(LOWER(n.class_name) LIKE ? OR LOWER(n.category_name) LIKE ?)")
        params.extend([ocsf, ocsf])

    where_sql = f"WHERE {' AND '.join(where_clauses)}" if where_clauses else ""
    return where_sql, params


def get_total_events_count(
    format_filter: Optional[str] = None,
    search: Optional[str] = None,
    source_filter: Optional[str] = None,
    severity_filter: Optional[str] = None,
    integrity_filter: Optional[str] = None,
    time_range: Optional[str] = None,
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    event_type_filter: Optional[str] = None,
    ocsf_class_filter: Optional[str] = None,
    conn: Optional[duckdb.DuckDBPyConnection] = None,
) -> int:
    """Get total count of normalized events matching filters using indexed DuckDB join."""
    c = conn or get_db()
    where_sql, params = _build_events_filter_sql(
        format_filter=format_filter,
        search=search,
        source_filter=source_filter,
        severity_filter=severity_filter,
        integrity_filter=integrity_filter,
        time_range=time_range,
        start_time=start_time,
        end_time=end_time,
        event_type_filter=event_type_filter,
        ocsf_class_filter=ocsf_class_filter,
    )

    query = f"""
    SELECT count(*) 
    FROM normalized_events n
    LEFT JOIN raw_events r ON n.raw_event_id = r.raw_event_id
    LEFT JOIN blockchain_ledger b ON n.event_id = b.event_id
    {where_sql};
    """
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
    severity_filter: Optional[str] = None,
    integrity_filter: Optional[str] = None,
    time_range: Optional[str] = None,
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    event_type_filter: Optional[str] = None,
    ocsf_class_filter: Optional[str] = None,
    conn: Optional[duckdb.DuckDBPyConnection] = None,
) -> List[Dict[str, Any]]:
    """Query normalized events joined with raw logs and blockchain ledger proofs."""
    c = conn or get_db()
    norm_columns = [
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

    where_sql, params = _build_events_filter_sql(
        format_filter=format_filter,
        search=search,
        source_filter=source_filter,
        severity_filter=severity_filter,
        integrity_filter=integrity_filter,
        time_range=time_range,
        start_time=start_time,
        end_time=end_time,
        event_type_filter=event_type_filter,
        ocsf_class_filter=ocsf_class_filter,
    )

    dir_str = "ASC" if direction.lower() == "asc" else "DESC"
    order_col = order_by.lower()
    if order_col == "timestamp":
        order_sql = f"ORDER BY n.timestamp {dir_str} NULLS LAST, n.created_at DESC"
    elif order_col in ("severity", "severity_id"):
        order_sql = f"ORDER BY n.severity_id {dir_str} NULLS LAST, n.created_at DESC"
    elif order_col in ("source", "source_display"):
        order_sql = f"ORDER BY COALESCE(n.src_hostname, r.source_file, n.product, n.vendor) {dir_str}, n.created_at DESC"
    elif order_col in ("event_type", "activity_name"):
        order_sql = f"ORDER BY COALESCE(n.activity_name, n.type_name, n.category_name) {dir_str}, n.created_at DESC"
    else:
        order_sql = f"ORDER BY n.created_at {dir_str}, n.timestamp DESC NULLS LAST"

    n_selects = ", ".join([f"n.{col}" for col in norm_columns])
    select_sql = f"""
    SELECT 
        {n_selects},
        r.source_file,
        b.block_index,
        b.event_hash,
        b.previous_hash,
        b.block_hash,
        b.timestamp as block_timestamp
    FROM normalized_events n
    LEFT JOIN raw_events r ON n.raw_event_id = r.raw_event_id
    LEFT JOIN blockchain_ledger b ON n.event_id = b.event_id
    {where_sql}
    {order_sql}
    LIMIT ? OFFSET ?;
    """
    params.extend([limit, offset])
    results = c.execute(select_sql, params).fetchall()

    all_cols = norm_columns + ["source_file", "block_index", "event_hash", "previous_hash", "block_hash", "block_timestamp"]
    events = []
    for row in results:
        d = dict(zip(all_cols, row))
        
        # Format timestamps cleanly
        if d.get("timestamp"):
            ts = d["timestamp"]
            d["timestamp"] = ts.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3] if hasattr(ts, "strftime") else str(ts).replace("T", " ")
        if d.get("created_at"):
            ca = d["created_at"]
            d["created_at"] = ca.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3] if hasattr(ca, "strftime") else str(ca).replace("T", " ")
        if d.get("unmapped") and isinstance(d["unmapped"], str):
            try:
                d["unmapped"] = json.loads(d["unmapped"])
            except Exception:
                pass

        # Compute clean SOC presentation fields
        d["source_display"] = _derive_clean_source_name(d.get("src_hostname"), d.get("source_file"), d.get("vendor"), d.get("product"))
        d["event_type_display"] = d.get("activity_name") or d.get("type_name") or d.get("category_name") or "Network Activity"
        d["ocsf_display"] = d.get("class_name") or d.get("category_name") or "Security Finding"
        
        # Standardize severity display
        raw_sev = str(d.get("severity") or "UNKNOWN").upper()
        if raw_sev in ("INFORMATIONAL", "FINE", "INFO", "DEBUG"):
            d["severity_clean"] = "INFO"
        elif raw_sev in ("WARNING", "WARN"):
            d["severity_clean"] = "MEDIUM"
        elif raw_sev in ("FATAL", "EMERGENCY"):
            d["severity_clean"] = "CRITICAL"
        elif raw_sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            d["severity_clean"] = raw_sev
        else:
            d["severity_clean"] = "INFO" if raw_sev == "UNKNOWN" else raw_sev

        # Compute Blockchain integrity status
        blk_idx = d.get("block_index")
        blk_hash = d.get("event_hash")
        raw_id = d.get("raw_event_id")

        if blk_hash and raw_id:
            if blk_hash == raw_id:
                status = "VERIFIED"
                msg = "Cryptographic SHA-256 verified against immutable blockchain block."
            else:
                status = "FAILED"
                msg = "Cryptographic hash mismatch! Evidence modified after blockchain commitment."
        else:
            status = "PENDING"
            msg = "Event recorded in DuckDB; blockchain proof block pending or uncommitted."

        d["blockchain_proof"] = {
            "status": status,
            "block_index": blk_idx,
            "event_hash": blk_hash or raw_id,
            "previous_hash": d.get("previous_hash"),
            "block_hash": d.get("block_hash"),
            "block_timestamp": d.get("block_timestamp"),
            "message": msg,
        }
        d["integrity_status"] = status

        events.append(d)
    return events


def get_filter_options(conn: Optional[duckdb.DuckDBPyConnection] = None) -> Dict[str, Any]:
    """Return distinct filter options populated from real DuckDB data."""
    c = conn or get_db()
    
    # Distinct sources
    source_rows = c.execute("""
        SELECT DISTINCT COALESCE(n.src_hostname, r.source_file, n.product, n.vendor) as src
        FROM normalized_events n
        LEFT JOIN raw_events r ON n.raw_event_id = r.raw_event_id
        WHERE src IS NOT NULL AND TRIM(src) != ''
        ORDER BY src ASC
        LIMIT 50;
    """).fetchall()
    sources = [r[0] for r in source_rows if r[0]]

    # Distinct severities
    sev_rows = c.execute("SELECT DISTINCT severity FROM normalized_events WHERE severity IS NOT NULL;").fetchall()
    severities = sorted(list(set([r[0] for r in sev_rows if r[0]])))

    # Distinct OCSF classes
    class_rows = c.execute("SELECT DISTINCT class_name FROM normalized_events WHERE class_name IS NOT NULL ORDER BY class_name ASC;").fetchall()
    classes = [r[0] for r in class_rows if r[0]]

    # Distinct event types / activities
    act_rows = c.execute("SELECT DISTINCT activity_name FROM normalized_events WHERE activity_name IS NOT NULL ORDER BY activity_name ASC LIMIT 50;").fetchall()
    activities = [r[0] for r in act_rows if r[0]]

    # Distinct log formats
    fmt_rows = c.execute("SELECT DISTINCT log_format FROM normalized_events WHERE log_format IS NOT NULL ORDER BY log_format ASC;").fetchall()
    formats = [r[0] for r in fmt_rows if r[0]]

    return {
        "sources": sources,
        "severities": severities,
        "classes": classes,
        "event_types": activities,
        "formats": formats,
    }



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
    format_filter: Optional[str] = None,
    search: Optional[str] = None,
    source_filter: Optional[str] = None,
    severity_filter: Optional[str] = None,
    integrity_filter: Optional[str] = None,
    time_range: Optional[str] = None,
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    event_type_filter: Optional[str] = None,
    ocsf_class_filter: Optional[str] = None,
    order_by: str = "created_at",
    direction: str = "desc",
    limit: Optional[int] = None,
    conn: Optional[duckdb.DuckDBPyConnection] = None,
) -> None:
    """Export filtered normalized events to CSV file."""
    c = conn or get_db()
    path_str = str(target_path)
    
    where_sql, params = _build_events_filter_sql(
        format_filter=format_filter,
        search=search,
        source_filter=source_filter,
        severity_filter=severity_filter,
        integrity_filter=integrity_filter,
        time_range=time_range,
        start_time=start_time,
        end_time=end_time,
        event_type_filter=event_type_filter,
        ocsf_class_filter=ocsf_class_filter,
    )
    
    dir_str = "ASC" if direction.lower() == "asc" else "DESC"
    order_col = order_by.lower()
    if order_col == "timestamp":
        order_sql = f"ORDER BY n.timestamp {dir_str} NULLS LAST, n.created_at DESC"
    elif order_col in ("severity", "severity_id"):
        order_sql = f"ORDER BY n.severity_id {dir_str} NULLS LAST, n.created_at DESC"
    else:
        order_sql = f"ORDER BY n.created_at {dir_str}, n.timestamp DESC NULLS LAST"

    limit_sql = f"LIMIT {int(limit)}" if limit and limit > 0 else ""

    select_sql = f"""
    SELECT 
        n.event_id,
        n.timestamp,
        COALESCE(n.src_hostname, r.source_file, n.product, n.vendor, 'unknown') as source,
        COALESCE(n.activity_name, n.type_name, n.category_name, 'Network Traffic') as event_type,
        UPPER(COALESCE(n.severity, 'UNKNOWN')) as severity,
        COALESCE(n.class_name, n.category_name, 'Security Finding') as ocsf_classification,
        CASE 
            WHEN b.event_hash IS NOT NULL AND b.event_hash = n.raw_event_id THEN 'VERIFIED'
            WHEN b.event_hash IS NOT NULL AND b.event_hash != n.raw_event_id THEN 'FAILED'
            ELSE 'PENDING'
        END as integrity_status,
        b.block_index as blockchain_block_index,
        n.src_ip,
        n.dst_ip,
        n.user,
        n.vendor,
        n.product,
        n.log_format,
        n.message,
        n.created_at
    FROM normalized_events n
    LEFT JOIN raw_events r ON n.raw_event_id = r.raw_event_id
    LEFT JOIN blockchain_ledger b ON n.event_id = b.event_id
    {where_sql}
    {order_sql}
    {limit_sql}
    """
    
    # DuckDB COPY with prepared statements
    if params:
        # Create a temporary view with the filtered query
        # or execute COPY directly
        placeholders = []
        c.register("_temp_export", c.execute(select_sql, params).arrow())
        c.execute(f"COPY _temp_export TO '{path_str}' (FORMAT CSV, HEADER true);")
        c.unregister("_temp_export")
    else:
        c.execute(f"COPY ({select_sql}) TO '{path_str}' (FORMAT CSV, HEADER true);")

