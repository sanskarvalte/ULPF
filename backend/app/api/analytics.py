"""
Analytics and ML Anomaly Detection API endpoints.
"""

from __future__ import annotations

from typing import Any, Dict

from fastapi import APIRouter
from app.ai.inference import detect_anomalies
from app.storage.normalized import get_stats

router = APIRouter(tags=["Analytics & AI"])


@router.get("/stats", summary="Get database aggregation metrics")
def get_database_stats() -> Dict[str, Any]:
    return get_stats()


@router.get("/anomalies", summary="Detect anomalies via Isolation Forest ML")
def get_anomalies() -> Dict[str, Any]:
    return detect_anomalies()
