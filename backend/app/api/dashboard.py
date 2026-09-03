"""
Dashboard API router for ULPF.
Provides high-performance aggregated endpoints for Page 1 Dashboard:
- /api/dashboard/summary: KPI metric cards (Events, Normalized, OCSF, Unknown, Anomalies, Blockchain)
- /api/dashboard/event-volume: 24-hour event volume distribution & peak EPS
- /api/dashboard/source-distribution: Source/category distribution for donut chart
- /api/dashboard/recent-events: Latest security events with anomaly & blockchain verification tags
- /api/dashboard/system-health: Operational health of API, DuckDB, AI engine, and Blockchain
"""

from __future__ import annotations

import logging
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query
from app.ai.inference import detect_anomalies
from app.blockchain.ledger import get_blockchain_overview
from app.storage.db import get_db

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/dashboard", tags=["Dashboard"])

# In-memory cache for ML anomaly detection to guarantee sub-50ms dashboard responses
_ANOMALY_CACHE: Dict[str, Any] = {
    "timestamp": 0.0,
    "data": None,
}
_CACHE_TTL_SECONDS = 60.0


def _get_cached_anomalies() -> Dict[str, Any]:
    """Retrieve anomaly detection results with in-memory TTL caching."""
    now = time.time()
    if _ANOMALY_CACHE["data"] is not None and (now - _ANOMALY_CACHE["timestamp"]) < _CACHE_TTL_SECONDS:
        return _ANOMALY_CACHE["data"]
    try:
        data = detect_anomalies()
        _ANOMALY_CACHE["data"] = data
        _ANOMALY_CACHE["timestamp"] = now
        return data
    except Exception as e:
        logger.warning(f"Error computing anomalies: {e}")
        if _ANOMALY_CACHE["data"] is not None:
            return _ANOMALY_CACHE["data"]
        return {"anomalies_detected": 0, "anomalies": [], "total_windows_analyzed": 0}


@router.get("/summary", summary="Get KPI Metrics for Dashboard")
def get_dashboard_summary() -> Dict[str, Any]:
    """
    Returns actual calculated metrics for the 6 Dashboard KPI cards:
    1. Events Processed
    2. Normalized count & percentage
    3. OCSF Events count & percentage
    4. Unknown Formats count
    5. Anomalies count (Isolation Forest)
    6. Blockchain Verified count
    """
    conn = get_db(read_only=True)
    try:
        norm_row = conn.execute("SELECT count(*) FROM normalized_events;").fetchone()
        raw_row = conn.execute("SELECT count(*) FROM raw_events;").fetchone()
        norm_count = norm_row[0] if norm_row else 0
        raw_count = raw_row[0] if raw_row else 0

        # Normalization percentage
        base_count = max(raw_count, norm_count)
        norm_pct = round((norm_count / base_count) * 100.0, 1) if base_count > 0 else 0.0

        # OCSF count: events with valid category/class mapping
        ocsf_row = conn.execute(
            """
            SELECT count(*) 
            FROM normalized_events 
            WHERE class_uid IS NOT NULL 
               OR category_uid IS NOT NULL 
               OR (class_name IS NOT NULL AND class_name != '');
            """
        ).fetchone()
        ocsf_count = ocsf_row[0] if ocsf_row else 0
        ocsf_pct = round((ocsf_count / norm_count) * 100.0, 1) if norm_count > 0 else 0.0

        # Unknown formats: unparsed logs pending review + unrecognized formats in normalized store
        try:
            pending_row = conn.execute("SELECT count(*) FROM pending_reviews;").fetchone()
            pending_count = pending_row[0] if pending_row else 0
        except Exception:
            pending_count = 0

        unrecognized_row = conn.execute(
            """
            SELECT count(*) 
            FROM normalized_events 
            WHERE lower(log_format) IN ('unknown', 'unknown_pending_review', 'unknown_custom');
            """
        ).fetchone()
        unrecognized_count = unrecognized_row[0] if unrecognized_row else 0
        unknown_formats = pending_count + unrecognized_count

        # Blockchain verified count: total blocks in ledger
        try:
            bc_row = conn.execute("SELECT count(*) FROM blockchain_ledger;").fetchone()
            blockchain_verified = bc_row[0] if bc_row else 0
        except Exception:
            blockchain_verified = 0

    finally:
        conn.close()

    # Anomalies count from Isolation Forest
    anomaly_data = _get_cached_anomalies()
    anomalies_count = anomaly_data.get("anomalies_detected", 0)

    return {
        "events_processed": base_count,
        "raw_events_count": raw_count,
        "normalized_count": norm_count,
        "normalized_pct": norm_pct,
        "ocsf_events_count": ocsf_count,
        "ocsf_pct": ocsf_pct,
        "unknown_formats_count": unknown_formats,
        "anomalies_count": anomalies_count,
        "blockchain_verified_count": blockchain_verified,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@router.get("/event-volume", summary="Get 24-Hour Event Volume & EPS")
def get_event_volume() -> Dict[str, Any]:
    """
    Returns aggregated event volume across 24 hourly periods and peak EPS.
    Handles empty, burst, and historical data gracefully.
    """
    conn = get_db(read_only=True)
    try:
        # Check if events exist
        total_row = conn.execute("SELECT count(*) FROM normalized_events;").fetchone()
        total_events = total_row[0] if total_row else 0

        if total_events == 0:
            return {
                "total_events": 0,
                "max_eps": 0,
                "max_hourly_count": 0,
                "buckets": [
                    {"label": f"{i:02d}:00", "hour": f"{i:02d}:00", "count": 0, "pct": 0}
                    for i in range(24)
                ],
            }

        # Query the latest 24 distinct hourly groups by created_at or timestamp
        query = """
        SELECT 
            strftime(date_trunc('hour', COALESCE(created_at, timestamp)), '%Y-%m-%d %H:00') as hr,
            count(*) as count
        FROM normalized_events
        GROUP BY hr
        ORDER BY hr DESC
        LIMIT 24;
        """
        rows = conn.execute(query).fetchall()
        rows.reverse()  # Chronological order (oldest to newest)

        # Pad to 24 slots if fewer than 24 hours exist
        buckets: List[Dict[str, Any]] = []
        if len(rows) < 24:
            needed = 24 - len(rows)
            for i in range(needed):
                buckets.append({
                    "hour": f"slot_{i:02d}",
                    "label": f"--:00",
                    "count": 0,
                })

        for r in rows:
            hr_str = str(r[0])
            label = hr_str.split(" ")[1] if " " in hr_str else hr_str
            buckets.append({
                "hour": hr_str,
                "label": label,
                "count": int(r[1]),
            })

        max_count = max((b["count"] for b in buckets), default=0)
        # EPS calculation: peak hourly count / 3600 seconds, rounded to 1 decimal
        max_eps = round(max_count / 3600.0, 1) if max_count > 0 else 0

        # Assign percentage height for visualization relative to max_count
        for b in buckets:
            b["pct"] = round((b["count"] / max_count) * 100.0, 1) if max_count > 0 else 0

        return {
            "total_events": total_events,
            "max_eps": max_eps,
            "max_hourly_count": max_count,
            "buckets": buckets,
        }
    finally:
        conn.close()


@router.get("/source-distribution", summary="Get Source / Category Distribution")
def get_source_distribution() -> Dict[str, Any]:
    """
    Calculates distribution of stored events across functional security sources.
    Returns percentages and event counts matching the Stitch donut chart.
    """
    conn = get_db(read_only=True)
    try:
        query = """
        SELECT 
            CASE 
                WHEN lower(category_name) LIKE '%network%' THEN 'FIREWALL'
                WHEN lower(category_name) LIKE '%system%' OR lower(category_name) LIKE '%device%' THEN 'EDR'
                WHEN lower(category_name) LIKE '%auth%' OR lower(category_name) LIKE '%ident%' THEN 'AUTH / IAM'
                WHEN lower(category_name) LIKE '%app%' THEN 'APPLICATION'
                WHEN lower(category_name) LIKE '%security%' THEN 'FINDINGS'
                ELSE 'SYSTEM / PROXY'
            END as display_source,
            count(*) as count
        FROM normalized_events
        GROUP BY display_source
        ORDER BY count DESC;
        """
        rows = conn.execute(query).fetchall()
        total = sum(r[1] for r in rows)

        # Palette matching Stitch design: primary cyan, amber/tertiary, slate, etc.
        color_map = {
            "FIREWALL": "#98cbff",       # Primary Blue
            "EDR": "#ffb77d",            # Tertiary Amber
            "SYSTEM / PROXY": "#454952", # Secondary container
            "AUTH / IAM": "#38bdf8",     # Cyan
            "APPLICATION": "#88919d",    # Slate outline
            "FINDINGS": "#ffb4ab",       # Error light
        }

        distribution: List[Dict[str, Any]] = []
        for r in rows:
            src = str(r[0])
            cnt = int(r[1])
            pct = round((cnt / total) * 100.0, 1) if total > 0 else 0.0
            distribution.append({
                "source": src,
                "count": cnt,
                "pct": pct,
                "color": color_map.get(src, "#88919d"),
            })

        return {
            "total_events": total,
            "distribution": distribution,
        }
    finally:
        conn.close()


@router.get("/recent-events", summary="Get Recent Security Events for Dashboard Table")
def get_recent_dashboard_events(
    limit: int = Query(10, ge=1, le=50, description="Number of recent events to retrieve"),
) -> List[Dict[str, Any]]:
    """
    Retrieves the most recent security events with:
    - TIME: ISO/timestamp string
    - EVENT ID: unique identifier
    - SOURCE: host / vendor / device
    - FORMAT: detected log format
    - TYPE: activity or event type
    - SEVERITY: HIGH / MEDIUM / LOW / INFO
    - OCSF: Class name / category
    - ANM: Anomaly flag (True if high/critical or flagged)
    - INT: Integrity flag (True if present in blockchain ledger)
    """
    conn = get_db(read_only=True)
    try:
        query = """
        SELECT 
            n.event_id,
            COALESCE(n.timestamp, n.created_at) as event_time,
            COALESCE(n.src_hostname, n.vendor, n.src_ip, 'FW-01') as source,
            COALESCE(n.log_format, 'syslog') as log_format,
            COALESCE(n.activity_name, n.type_name, n.category_name, 'System Activity') as event_type,
            COALESCE(n.severity, 'INFO') as severity,
            COALESCE(n.class_name, 'Class ' || COALESCE(n.class_uid, 1001)) as ocsf_class,
            CASE WHEN lower(n.severity) IN ('high', 'critical') THEN true ELSE false END as is_anomaly,
            CASE WHEN b.block_index IS NOT NULL THEN true ELSE false END as is_verified
        FROM normalized_events n
        LEFT JOIN (SELECT DISTINCT event_id, block_index FROM blockchain_ledger) b ON n.event_id = b.event_id
        ORDER BY n.created_at DESC
        LIMIT ?;
        """
        rows = conn.execute(query, [limit]).fetchall()

        events: List[Dict[str, Any]] = []
        for r in rows:
            ev_id = str(r[0])
            raw_time = r[1]
            if hasattr(raw_time, "strftime"):
                time_str = raw_time.strftime("%H:%M:%S.%fZ")[:-4] + "Z"
            else:
                time_str = str(raw_time)

            events.append({
                "event_id": ev_id,
                "time": time_str,
                "source": str(r[2]),
                "format": str(r[3]).capitalize(),
                "type": str(r[4]),
                "severity": str(r[5]).upper(),
                "ocsf": str(r[6]),
                "is_anomaly": bool(r[7]),
                "is_verified": bool(r[8]),
            })

        return events
    finally:
        conn.close()


@router.get("/system-health", summary="Get Subsystem Health Status")
def get_system_health() -> Dict[str, Any]:
    """
    Returns real-time health for:
    - API: responsive
    - DB: DuckDB operational
    - AI: Isolation Forest engine ready
    - BC: Blockchain ledger operational & tip verified
    """
    db_status = "offline"
    bc_status = "offline"
    ai_status = "offline"

    # DuckDB check
    try:
        conn = get_db(read_only=True)
        conn.execute("SELECT 1;").fetchone()
        db_status = "online"
        conn.close()
    except Exception as e:
        logger.error(f"DB health check failed: {e}")

    # Blockchain check
    try:
        overview = get_blockchain_overview()
        bc_status = "online" if overview.chain_status == "VALID" else "degraded"
    except Exception as e:
        logger.error(f"Blockchain health check failed: {e}")

    # AI engine check
    try:
        from sklearn.ensemble import IsolationForest
        ai_status = "online"
    except Exception as e:
        logger.error(f"AI engine health check failed: {e}")

    all_online = (db_status == "online" and bc_status == "online" and ai_status == "online")

    return {
        "status": "online" if all_online else "degraded",
        "mode": "airgapped_offline",
        "api": "online",
        "database": db_status,
        "ai": ai_status,
        "blockchain": bc_status,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
