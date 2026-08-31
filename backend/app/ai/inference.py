"""
Isolation Forest Machine Learning Anomaly Detection Engine for ULPF.
Runs 100% locally in-memory on DuckDB aggregated security time-windows.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional

import numpy as np
from sklearn.ensemble import IsolationForest
from app.storage.db import get_db


def detect_anomalies(db_path: Optional[str | Path] = None) -> Dict[str, Any]:
    """Execute offline anomaly detection on DuckDB normalized events."""
    conn = get_db(db_path)
    try:
        cursor = conn.execute(
            """
            SELECT
                COALESCE(
                    strftime(date_trunc('minute', n.timestamp), '%Y-%m-%d %H:%M:00'),
                    NULLIF(regexp_extract(r.raw_text, '^([0-9]{2}:[0-9]{2}:[0-9]{2})', 1), ''),
                    strftime(date_trunc('minute', n.created_at), '%Y-%m-%d %H:%M:00')
                ) AS time_window,
                count(*) AS total_events,
                count(CASE WHEN lower(n.severity) IN ('high', 'critical') THEN 1 END) AS high_severity_count,
                count(CASE WHEN lower(n.severity) IN ('medium', 'warn', 'warning') THEN 1 END) AS medium_severity_count,
                count(CASE WHEN lower(n.status) IN ('failure', 'fail', 'denied', 'drop', 'block') THEN 1 END) AS failure_count,
                count(CASE WHEN lower(n.category_name) IN ('authentication', 'identity & access management') THEN 1 END) AS auth_count,
                string_agg(DISTINCT COALESCE(n.vendor, 'Unknown'), ', ') AS vendors,
                string_agg(DISTINCT COALESCE(n.category_name, 'general'), ', ') AS categories
            FROM normalized_events n
            LEFT JOIN raw_events r ON n.raw_event_id = r.raw_event_id
            GROUP BY time_window
            HAVING time_window IS NOT NULL AND time_window != ''
            ORDER BY time_window;
            """
        )
        rows = cursor.fetchall()
    finally:
        conn.close()

    if not rows:
        return {
            "status": "success",
            "total_windows_analyzed": 0,
            "anomalies_detected": 0,
            "anomalies": [],
            "all_windows": [],
        }

    windows: List[Dict[str, Any]] = []
    feature_matrix: List[List[float]] = []

    for r in rows:
        time_win = str(r[0])
        total_cnt = int(r[1])
        high_cnt = int(r[2])
        med_cnt = int(r[3])
        fail_cnt = int(r[4])
        auth_cnt = int(r[5])
        vendors = str(r[6] or "Unknown")
        categories = str(r[7] or "general")

        error_ratio = float(high_cnt / total_cnt) if total_cnt > 0 else 0.0
        failure_ratio = float(fail_cnt / total_cnt) if total_cnt > 0 else 0.0

        item = {
            "time_window": time_win,
            "total_events": total_cnt,
            "high_severity_events": high_cnt,
            "medium_severity_events": med_cnt,
            "failure_events": fail_cnt,
            "auth_events": auth_cnt,
            "error_ratio": round(error_ratio, 3),
            "vendors": vendors,
            "categories": categories,
            "is_anomaly": False,
            "anomaly_score": 0.0,
            "description": "Normal activity",
        }
        windows.append(item)
        feature_matrix.append([float(total_cnt), float(high_cnt), error_ratio, float(fail_cnt)])

    X = np.array(feature_matrix, dtype=float)

    if len(windows) >= 3:
        contamination = min(0.25, max(0.05, 1.0 / len(windows)))
        clf = IsolationForest(
            n_estimators=100,
            contamination=contamination,
            random_state=42,
        )
        clf.fit(X)
        raw_scores = -clf.decision_function(X)
        preds = clf.predict(X)

        s_min, s_max = float(np.min(raw_scores)), float(np.max(raw_scores))
        if s_max > s_min:
            norm_scores = (raw_scores - s_min) / (s_max - s_min)
        else:
            norm_scores = np.zeros(len(raw_scores))

        for idx, w in enumerate(windows):
            is_outlier = bool(preds[idx] == -1 or w["high_severity_events"] >= 3 or (w["high_severity_events"] > 0 and w["error_ratio"] >= 0.5))
            score = round(float(norm_scores[idx]), 3)

            w["anomaly_score"] = score
            w["is_anomaly"] = is_outlier

            if is_outlier:
                if w["high_severity_events"] > 0:
                    w["description"] = (
                        f"Unusual spike of {w['high_severity_events']} high-severity event(s) "
                        f"out of {w['total_events']} total events (error rate: {int(w['error_ratio']*100)}%)."
                    )
                else:
                    w["description"] = f"Unusual surge in event volume ({w['total_events']} events)."
    else:
        for w in windows:
            if w["high_severity_events"] > 0:
                w["is_anomaly"] = True
                w["anomaly_score"] = round(min(1.0, 0.5 + (w["high_severity_events"] * 0.1)), 2)
                w["description"] = f"Spike of {w['high_severity_events']} high-severity event(s) detected."
            else:
                w["is_anomaly"] = False
                w["anomaly_score"] = 0.1

    flagged_anomalies = [w for w in windows if w["is_anomaly"]]

    return {
        "status": "success",
        "total_windows_analyzed": len(windows),
        "anomalies_detected": len(flagged_anomalies),
        "anomalies": flagged_anomalies,
        "all_windows": windows,
    }
