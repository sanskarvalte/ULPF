"""
Accuracy Evaluation API endpoints for ULPF.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Optional

from fastapi import APIRouter, File, Query, UploadFile

from app.evaluation.evaluator import evaluate_ground_truth, evaluate_log_file

router = APIRouter(prefix="/api/evaluation", tags=["Evaluation"])


@router.get("/accuracy")
def get_ground_truth_accuracy() -> Dict[str, Any]:
    """
    Run ground-truth benchmark and return real calculated accuracy metrics.
    """
    return evaluate_ground_truth()


@router.post("/file-completeness")
async def evaluate_uploaded_file_completeness(file: UploadFile = File(...)) -> Dict[str, Any]:
    """
    Evaluate event count integrity and field completeness on an uploaded log file.
    """
    content_bytes = await file.read()
    content = content_bytes.decode("utf-8", errors="replace")

    from app.pipeline import run_pipeline

    raw_lines = [l for l in content.splitlines() if l.strip()]
    raw_count = len(raw_lines)

    result = run_pipeline(content, filename=file.filename or "uploaded.log", save_to_db=False)
    normalized_events = result.get("events") or []
    norm_count = len(normalized_events)
    unparsed_count = result.get("unparsed_count", 0)

    event_ids = [ev.raw_event_id for ev in normalized_events if ev.raw_event_id]
    unique_ids = set(event_ids)
    duplicate_count = len(event_ids) - len(unique_ids)

    completeness_fields = [
        "timestamp",
        "vendor",
        "product",
        "category_name",
        "severity",
        "status",
        "src_ip",
        "dst_ip",
        "src_port",
        "dst_port",
        "user",
        "activity_name",
    ]

    field_populated_counts = {f: 0 for f in completeness_fields}
    for ev in normalized_events:
        d = ev.model_dump()
        for f in completeness_fields:
            if d.get(f) is not None:
                field_populated_counts[f] += 1

    field_completeness = {}
    for f in completeness_fields:
        pct = (field_populated_counts[f] / norm_count * 100.0) if norm_count > 0 else 0.0
        field_completeness[f] = {
            "populated_count": field_populated_counts[f],
            "completeness_percent": round(pct, 2),
        }

    integrity_passed = (raw_count == norm_count + unparsed_count) and (duplicate_count == 0)

    return {
        "file_name": file.filename,
        "raw_event_count": raw_count,
        "normalized_event_count": norm_count,
        "unparsed_event_count": unparsed_count,
        "duplicate_count": duplicate_count,
        "fan_out_ratio": round(norm_count / raw_count, 4) if raw_count else 0.0,
        "event_count_integrity_passed": integrity_passed,
        "detected_format": result.get("format"),
        "field_completeness": field_completeness,
    }
