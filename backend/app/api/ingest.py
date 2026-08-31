"""
Ingestion API endpoints (text upload, multipart file upload, and JSON ingestion).
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional, Tuple

from fastapi import APIRouter, File, Form, HTTPException, UploadFile, status
from pydantic import BaseModel, Field

from app.ingestion.detector import detect_format
from app.models.event_schema import UnifiedEvent
from app.normalization.engine import normalize_event
from app.parsers.csv_parser import parse_csv_log_all
from app.parsers.generic_parser import parse_generic_log
from app.parsers.xml_parser import parse_xml_log_all
from app.storage.normalized import save_events_batch

router = APIRouter(prefix="", tags=["Ingestion"])


class TextUploadRequest(BaseModel):
    raw_text: str = Field(..., description="Raw log text (single or multi-line).")
    source_file: Optional[str] = Field("api_upload.log", description="Optional source label/filename.")


class UploadEventItem(BaseModel):
    event_id: str
    raw_event_id: str
    detected_format: str
    normalized_event: Dict[str, Any]


class UploadResponse(BaseModel):
    status: str = "success"
    file_name: str
    detected_format: str
    event_count: int
    events: List[UploadEventItem]


def _split_events(raw: str, fmt: str) -> list[str]:
    if fmt == "json":
        try:
            payload = json.loads(raw)
            if isinstance(payload, list):
                return [json.dumps(item) for item in payload]
        except json.JSONDecodeError:
            pass
        return [raw]
    elif fmt in ("syslog", "cef", "leef", "generic", "android"):
        lines = [line for line in raw.splitlines() if line.strip()]
        return lines if lines else [raw]
    return [raw]


def process_and_store_text(raw_text: str, source_filename: str) -> UploadResponse:
    if not raw_text or not raw_text.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Log content is empty.",
        )

    try:
        fmt, parser_fn = detect_format(raw_text)
    except Exception:
        fmt, parser_fn = "generic", parse_generic_log

    records_to_save: List[Tuple[UnifiedEvent, str, str]] = []
    processed_items: List[UploadEventItem] = []

    if fmt == "csv":
        try:
            csv_events = parse_csv_log_all(raw_text)
            for event in csv_events:
                event = normalize_event(event)
                records_to_save.append((event, event.raw_event, source_filename))
        except Exception:
            fmt, parser_fn = "generic", parse_generic_log
    elif fmt == "xml":
        try:
            xml_events = parse_xml_log_all(raw_text)
            for event in xml_events:
                event = normalize_event(event)
                records_to_save.append((event, event.raw_event, source_filename))
        except Exception:
            fmt, parser_fn = "generic", parse_generic_log

    if not records_to_save:
        chunks = _split_events(raw_text, fmt)
        for chunk in chunks:
            if not chunk.strip():
                continue
            try:
                event = parser_fn(chunk)
            except Exception:
                event = parse_generic_log(chunk)

            event = normalize_event(event)
            records_to_save.append((event, chunk, source_filename))

    if not records_to_save:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No valid log events could be parsed from the provided input.",
        )

    saved_ids = save_events_batch(records_to_save)

    for (event, _, _), (eid, rid) in zip(records_to_save, saved_ids):
        processed_items.append(
            UploadEventItem(
                event_id=eid,
                raw_event_id=rid,
                detected_format=fmt,
                normalized_event=event.model_dump(),
            )
        )

    return UploadResponse(
        status="success",
        file_name=source_filename,
        detected_format=fmt,
        event_count=len(processed_items),
        events=processed_items,
    )


@router.post("/upload", response_model=UploadResponse, summary="Upload and ingest log file or raw text")
async def upload_log(
    file: Optional[UploadFile] = File(None, description="Log file to upload."),
    raw_text: Optional[str] = Form(None, description="Direct raw log text."),
    source_file: Optional[str] = Form(None, description="Optional filename label."),
) -> UploadResponse:
    if file is not None and file.filename:
        filename = file.filename
        content_bytes = await file.read()
        if content_bytes:
            try:
                text = content_bytes.decode("utf-8")
            except UnicodeDecodeError:
                text = content_bytes.decode("latin-1", errors="replace")
            return process_and_store_text(text, filename)

    if raw_text is not None and raw_text.strip():
        filename = source_file or "direct_input.log"
        return process_and_store_text(raw_text, filename)

    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail="Must provide a non-empty file upload or 'raw_text' form field.",
    )


@router.post("/upload/json", response_model=UploadResponse, summary="Upload raw log text via JSON body")
def upload_log_json(payload: TextUploadRequest) -> UploadResponse:
    return process_and_store_text(payload.raw_text, payload.source_file or "api_payload.log")


@router.post("/convert", summary="Direct single-file log to JSON converter (No DB contamination)")
async def convert_single_file(
    file: Optional[UploadFile] = File(None, description="Single log file to convert."),
    raw_text: Optional[str] = Form(None, description="Single log text snippet to convert."),
):
    """Convert only this single input into a normalized JSON file."""
    text = ""
    filename = "single_normalized_output.json"
    if file is not None and file.filename:
        content_bytes = await file.read()
        try:
            text = content_bytes.decode("utf-8")
        except UnicodeDecodeError:
            text = content_bytes.decode("latin-1", errors="replace")
        from pathlib import Path
        filename = Path(file.filename).stem + "_normalized.json"
    elif raw_text and raw_text.strip():
        text = raw_text.strip()
    else:
        raise HTTPException(status_code=400, detail="Please provide a file or raw_text to convert.")

    try:
        fmt, parser_fn = detect_format(text)
    except Exception:
        fmt, parser_fn = "generic", parse_generic_log

    results = []
    if fmt == "csv":
        try:
            csv_events = parse_csv_log_all(text)
            for ev in csv_events:
                ev = normalize_event(ev)
                results.append(ev.model_dump(mode="json"))
        except Exception:
            fmt, parser_fn = "generic", parse_generic_log
    elif fmt == "xml":
        try:
            xml_events = parse_xml_log_all(text)
            for ev in xml_events:
                ev = normalize_event(ev)
                results.append(ev.model_dump(mode="json"))
        except Exception:
            fmt, parser_fn = "generic", parse_generic_log

    if not results:
        chunks = _split_events(text, fmt)
        for chunk in chunks:
            if not chunk.strip():
                continue
            try:
                ev = parser_fn(chunk)
            except Exception:
                ev = parse_generic_log(chunk)
            ev = normalize_event(ev)
            results.append(ev.model_dump(mode="json"))

    from fastapi.responses import Response
    json_bytes = json.dumps(results, indent=2, default=str).encode("utf-8")
    return Response(
        content=json_bytes,
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'}
    )
