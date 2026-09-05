"""
Real ULPF Ollama AI Backend API Endpoints.

Exposes authentic, observable AI telemetry:
- GET /api/v1/ai/status: Real connection and model availability for local Ollama
- GET /api/v1/ai/metrics: Live observable LLM calls, latency, parser generation, and learned cache reuses
- GET /api/v1/ai/resolutions: Live stream of recent unknown-format resolutions
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Query

from app.ai.telemetry import (
    check_ollama_status,
    get_real_ai_metrics,
    get_recent_ai_resolutions,
)

router = APIRouter(prefix="/ai", tags=["ULPF AI Engine & Telemetry"])


@router.get("/status", summary="Get Real Ollama and Model Availability")
def get_ai_status() -> Dict[str, Any]:
    """
    Query real local Ollama instance (http://127.0.0.1:11434/api/tags)
    and verify whether configured model (qwen3:4b) is available.
    """
    status_info = check_ollama_status()
    return {
        "success": True,
        "data": status_info,
    }


@router.get("/metrics", summary="Get Real Accumulated AI Telemetry & Parser Metrics")
def get_ai_metrics() -> Dict[str, Any]:
    """
    Return accumulated observable metrics from local Ollama client,
    learned parser cache, review queue, and DuckDB store.
    """
    metrics = get_real_ai_metrics()
    return {
        "success": True,
        "data": metrics,
    }


@router.get("/resolutions", summary="Get Recent Real AI Resolutions")
def get_ai_resolutions(limit: int = Query(20, ge=1, le=100)) -> Dict[str, Any]:
    """
    Return list of recent log resolutions, distinguishing between:
    - AI Used: True (Ollama invoked for new unknown format)
    - AI Used: False (Cached/learned parser or rule-based parser reused)
    """
    resolutions = get_recent_ai_resolutions(limit=limit)
    return {
        "success": True,
        "data": resolutions,
    }
