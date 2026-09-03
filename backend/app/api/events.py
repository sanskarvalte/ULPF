"""
Events querying and traceability API endpoints.
"""

import os
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query, status
from fastapi.responses import FileResponse

from app.storage.normalized import (
    export_to_csv,
    export_to_json,
    export_to_parquet,
    get_all_events,
    get_event_by_id,
    get_total_events_count,
)

router = APIRouter(tags=["Events & Traceability"])


@router.get("/events", summary="Get paginated normalized events")
def list_events(
    limit: int = Query(100, ge=1, le=1000, description="Max number of events to return."),
    offset: int = Query(0, ge=0, description="Offset for pagination."),
    order_by: str = Query("created_at", description="Field to sort by: created_at or timestamp."),
    direction: str = Query("desc", description="Sort direction: asc or desc."),
    format: Optional[str] = Query(None, description="Filter by log format (syslog, android, json, etc.)."),
    search: Optional[str] = Query(None, description="Text search filter."),
    source: Optional[str] = Query(None, description="Filter by source file / stream identifier."),
) -> Dict[str, Any]:
    events = get_all_events(
        limit=limit,
        offset=offset,
        order_by=order_by,
        direction=direction,
        format_filter=format,
        search=search,
        source_filter=source,
    )
    total = get_total_events_count(format_filter=format, search=search, source_filter=source)
    return {
        "count": len(events),
        "total": total,
        "limit": limit,
        "offset": offset,
        "order_by": order_by,
        "direction": direction,
        "events": events,
    }


@router.get("/events/{event_id}", summary="Get single event details with raw log traceability")
def get_event(event_id: str) -> Dict[str, Any]:
    event = get_event_by_id(event_id)
    if not event:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Event '{event_id}' not found in DuckDB database.",
        )
    return event


@router.get("/export/parquet", summary="Download normalized events as Parquet")
def export_parquet_download() -> FileResponse:
    export_dir = Path(os.getenv("ULPF_EXPORTS_DIR") or (Path(__file__).resolve().parent.parent.parent.parent / "exports"))
    export_dir.mkdir(parents=True, exist_ok=True)
    parquet_path = export_dir / "normalized_events.parquet"

    export_to_parquet(parquet_path)
    if not parquet_path.exists():
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to generate Parquet export file.",
        )

    return FileResponse(
        path=str(parquet_path),
        filename="normalized_events.parquet",
        media_type="application/octet-stream",
        headers={"Content-Disposition": 'attachment; filename="normalized_events.parquet"'},
    )


@router.get("/export/json", summary="Download normalized events as JSON")
def export_json_download(
    format: Optional[str] = Query(None, description="Filter by log format (e.g. syslog, android, xml, json)"),
    search: Optional[str] = Query(None, description="Search query string"),
    order_by: str = Query("created_at", description="Sort field ('created_at' or 'timestamp')"),
    direction: str = Query("desc", description="Sort direction ('asc' or 'desc')"),
    limit: Optional[int] = Query(None, description="Max number of events to export"),
    event_ids: Optional[str] = Query(None, description="Comma-separated event IDs to export only specific newly ingested events"),
) -> FileResponse:
    export_dir = Path(os.getenv("ULPF_EXPORTS_DIR") or (Path(__file__).resolve().parent.parent.parent.parent / "exports"))
    export_dir.mkdir(parents=True, exist_ok=True)

    suffix = f"_{format}" if format and format.lower() != "all" else ""
    json_path = export_dir / f"normalized_events{suffix}.json"

    id_list = [eid.strip() for eid in event_ids.split(",") if eid.strip()] if event_ids else None

    export_to_json(
        target_path=json_path,
        format_filter=format,
        search=search,
        order_by=order_by,
        direction=direction,
        limit=limit,
        event_ids=id_list,
    )
    if not json_path.exists():
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to generate JSON export file.",
        )

    download_filename = f"normalized_events{suffix}.json" if suffix else "normalized_events.json"

    return FileResponse(
        path=str(json_path),
        filename=download_filename,
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{download_filename}"'},
    )


@router.get("/export/csv", summary="Download normalized events as CSV")
def export_csv_download() -> FileResponse:
    export_dir = Path(os.getenv("ULPF_EXPORTS_DIR") or (Path(__file__).resolve().parent.parent.parent.parent / "exports"))
    export_dir.mkdir(parents=True, exist_ok=True)
    csv_path = export_dir / "normalized_events.csv"

    export_to_csv(csv_path)
    if not csv_path.exists():
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to generate CSV export file.",
        )

    return FileResponse(
        path=str(csv_path),
        filename="normalized_events.csv",
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="normalized_events.csv"'},
    )
