"""
ULPF Backend Entrypoint (FastAPI Application & CLI Engine).

Runs 100% offline. Supports:
1. REST API server with FastAPI routers.
2. Direct CLI log file/directory ingestion and DuckDB query inspection.
3. Interactive multi-view frontend dashboard at /dashboard and /
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Optional

# Ensure backend directory is prioritized in sys.path
_BACKEND_DIR = Path(__file__).resolve().parent.parent
if str(_BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(_BACKEND_DIR))

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

from app.api.analytics import router as analytics_router
from app.api.events import router as events_router
from app.api.ingest import router as ingest_router
from app.api.mappings import router as mappings_router
from app.api.sources import router as sources_router
from app.ingestion.detector import detect_format
from app.models.event_schema import UnifiedEvent
from app.normalization.engine import normalize_event
from app.parsers.csv_parser import parse_csv_log_all
from app.parsers.generic_parser import parse_generic_log
from app.parsers.xml_parser import parse_xml_log_all
from app.storage.db import get_db
from app.storage.normalized import (
    export_to_parquet,
    get_all_events,
    get_event_by_id,
    get_stats,
    save_events_batch,
)

# ── FastAPI App Setup ──────────────────────────────────────────────────
app = FastAPI(
    title="ULPF — Universal Log Pre-processing Framework API",
    description="Enterprise log normalization, OCSF mapping, DuckDB storage & ML Anomaly Detection.",
    version="2.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include modular API routers
app.include_router(ingest_router)
app.include_router(sources_router)
app.include_router(mappings_router)
app.include_router(events_router)
app.include_router(analytics_router)

# Locate frontend directory
FRONTEND_DIR = Path(__file__).resolve().parent.parent.parent / "frontend"

if FRONTEND_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR)), name="static")
    if (FRONTEND_DIR / "src").exists():
        app.mount("/src", StaticFiles(directory=str(FRONTEND_DIR / "src")), name="src")

    @app.get("/", include_in_schema=False)
    @app.get("/dashboard", include_in_schema=False)
    def serve_frontend():
        return FileResponse(str(FRONTEND_DIR / "index.html"))
else:
    @app.get("/", include_in_schema=False)
    def root():
        return RedirectResponse(url="/docs")


@app.get("/health", tags=["System"])
def health_check():
    return {"status": "ok", "mode": "airgapped_offline"}


# ── CLI Pipeline Engine ─────────────────────────────────────────────────
def _split_into_events(raw_text: str, fmt: str) -> list[str]:
    if fmt == "json":
        try:
            val = json.loads(raw_text)
            if isinstance(val, list):
                return [json.dumps(item) for item in val]
            elif isinstance(val, dict):
                return [raw_text]
        except json.JSONDecodeError:
            lines = [line.strip() for line in raw_text.splitlines() if line.strip()]
            if lines and lines[0].startswith("{"):
                return lines
        return [raw_text]
    elif fmt in ("syslog", "cef", "leef", "generic", "android"):
        lines = [line for line in raw_text.splitlines() if line.strip()]
        return lines if lines else [raw_text]
    return [raw_text]


def ingest_file(file_path: Path, conn=None, output_json_path: Optional[Path] = None) -> int:
    """Ingest a single log file into DuckDB and optionally save its normalized JSON output."""
    try:
        raw_text = file_path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        raw_text = file_path.read_text(encoding="latin-1", errors="replace")

    if not raw_text.strip():
        print(f"  [SKIPPED] {file_path.name} is empty.")
        return 0

    try:
        fmt, parser_fn = detect_format(raw_text)
    except Exception:
        fmt, parser_fn = "generic", parse_generic_log

    records_to_save = []
    normalized_list = []
    if fmt == "csv":
        try:
            csv_events = parse_csv_log_all(raw_text)
            for ev in csv_events:
                ev = normalize_event(ev)
                records_to_save.append((ev, ev.raw_event, file_path.name))
                normalized_list.append(ev.model_dump(mode="json"))
        except Exception:
            fmt, parser_fn = "generic", parse_generic_log
    elif fmt == "xml":
        try:
            xml_events = parse_xml_log_all(raw_text)
            for ev in xml_events:
                ev = normalize_event(ev)
                records_to_save.append((ev, ev.raw_event, file_path.name))
                normalized_list.append(ev.model_dump(mode="json"))
        except Exception:
            fmt, parser_fn = "generic", parse_generic_log

    if not records_to_save:
        chunks = _split_into_events(raw_text, fmt)
        for chunk in chunks:
            if not chunk.strip():
                continue
            try:
                ev = parser_fn(chunk)
            except Exception:
                ev = parse_generic_log(chunk)
            ev = normalize_event(ev)
            records_to_save.append((ev, chunk, file_path.name))
            normalized_list.append(ev.model_dump(mode="json"))

    if not records_to_save:
        print(f"  [SKIPPED] No valid events in {file_path.name}")
        return 0

    save_events_batch(records_to_save, conn=conn)
    print(f"  ✓ {file_path.name}: Normalized {len(records_to_save)} event(s) as [{fmt.upper()}]")

    if output_json_path:
        out_p = Path(output_json_path)
        out_p.parent.mkdir(parents=True, exist_ok=True)
        out_p.write_text(json.dumps(normalized_list, indent=2, default=str), encoding="utf-8")
        print(f"  📥 Saved single-file normalized output to: {out_p.resolve()}")

    return len(records_to_save)


def ingest_path(target_path: Path, output_json_path: Optional[Path] = None) -> None:
    """Ingest a file or directory of log files."""
    conn = get_db()
    total = 0
    if target_path.is_file():
        total += ingest_file(target_path, conn=conn, output_json_path=output_json_path)
    elif target_path.is_dir():
        files = sorted([p for p in target_path.iterdir() if p.is_file() and not p.name.startswith(".")])
        print(f"\n📂 Processing {len(files)} file(s) in {target_path}...")
        for f in files:
            total += ingest_file(f, conn=conn)
    print(f"\n✨ Ingestion complete: {total} total event(s) normalized & persisted into DuckDB.")


def main():
    parser = argparse.ArgumentParser(description="ULPF CLI — Universal Log Pre-processing Framework")
    parser.add_argument("path", nargs="?", help="File or directory of logs to ingest")
    parser.add_argument("-o", "--output", help="Save normalized output of this single file as JSON")
    parser.add_argument("--stats", action="store_true", help="Print database statistics")
    parser.add_argument("--list-events", action="store_true", help="List recent normalized events")
    parser.add_argument("--show-event", metavar="EVENT_ID", help="Inspect single event with raw log traceability")
    parser.add_argument("--export-parquet", metavar="OUT_FILE", help="Export normalized events to Parquet")
    parser.add_argument("--export-json", metavar="OUT_FILE", help="Export normalized events to JSON file")
    parser.add_argument("--export-csv", metavar="OUT_FILE", help="Export normalized events to CSV file")

    args = parser.parse_args()

    if args.stats:
        stats = get_stats()
        print("\n📊 Database Statistics:")
        print(f"  • Total Normalized Events: {stats['total_normalized_events']}")
        print(f"  • Deduplicated Raw Events: {stats['total_raw_events']}")
        print("  • Categories:", ", ".join(f"{c['category']}: {c['count']}" for c in stats['by_category']))
        print("  • Formats:", ", ".join(f"{f['log_format']}: {f['count']}" for f in stats['by_log_format']))
        return

    if args.list_events:
        events = get_all_events(limit=20)
        print(f"\n📋 Last {len(events)} Normalized Events:")
        for e in events:
            print(f"  [{e['timestamp'] or e['created_at']}] [{e['severity'] or 'INFO'}] [{e['category_name'] or 'General'}] {e['message'] or e['raw_event_id']}")
        return

    if args.show_event:
        ev = get_event_by_id(args.show_event)
        if not ev:
            print(f"❌ Event '{args.show_event}' not found.")
            return
        print("\n🔍 Event Traceability Details:")
        print(json.dumps(ev, indent=2, default=str))
        return

    if args.export_parquet:
        out = Path(args.export_parquet)
        out.parent.mkdir(parents=True, exist_ok=True)
        export_to_parquet(out)
        print(f"📦 Successfully exported normalized events to Parquet: {out.resolve()}")
        return

    if args.export_json:
        out = Path(args.export_json)
        out.parent.mkdir(parents=True, exist_ok=True)
        from app.storage.normalized import export_to_json
        export_to_json(out)
        print(f"📥 Successfully exported normalized events to JSON: {out.resolve()}")
        return

    if args.export_csv:
        out = Path(args.export_csv)
        out.parent.mkdir(parents=True, exist_ok=True)
        from app.storage.normalized import export_to_csv
        export_to_csv(out)
        print(f"📊 Successfully exported normalized events to CSV: {out.resolve()}")
        return

    if args.path:
        out_p = Path(args.output) if args.output else None
        ingest_path(Path(args.path), output_json_path=out_p)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
