"""
ULPF Backend Entrypoint (FastAPI Application & CLI Engine).
8-Node Target Architecture Coordinator.

Runs 100% offline. Supports:
1. REST API server with FastAPI routers.
2. Direct CLI log file/directory ingestion using unified 8-node pipeline.
3. Interactive multi-view frontend dashboard at /dashboard and /
4. Dynamic parser reloading on startup.
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
from app.api.blockchain import router as blockchain_router
from app.api.dashboard import router as dashboard_router
from app.api.evaluation import router as evaluation_router
from app.api.events import router as events_router
from app.api.ingest import router as ingest_router
from app.api.mappings import router as mappings_router
from app.api.review import router as review_router
from app.api.sources import router as sources_router
from app.blockchain.ledger import init_blockchain
from app.evaluation.evaluator import evaluate_ground_truth, evaluate_log_file
from app.ingestion.detector import load_and_register_all_custom_parsers
from app.pipeline import pipeline
from app.storage.db import get_db
from app.storage.normalized import (
    export_to_parquet,
    get_all_events,
    get_event_by_id,
    get_stats,
)

# ── FastAPI App Setup ──────────────────────────────────────────────────
app = FastAPI(
    title="ULPF — Universal Log Pre-processing Framework API",
    description="8-Node Enterprise log normalization, OCSF mapping, DuckDB storage, Blockchain Integrity & ML Anomaly Detection.",
    version="2.1.0",
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


@app.on_event("startup")
def on_startup():
    """Startup lifecycle: Load and register all approved custom parsers and initialize blockchain ledger."""
    init_blockchain()
    count = load_and_register_all_custom_parsers()
    if count > 0:
        print(f"🚀 [STARTUP] Loaded and registered {count} approved custom parser(s) into active pipeline.")


# Include modular API routers
app.include_router(dashboard_router)
app.include_router(ingest_router)
app.include_router(ingest_router, prefix="/api")
app.include_router(blockchain_router)
app.include_router(review_router)
app.include_router(sources_router)
app.include_router(sources_router, prefix="/api")
app.include_router(mappings_router)
app.include_router(events_router)
app.include_router(analytics_router)
app.include_router(evaluation_router)

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
    return {"status": "ok", "mode": "airgapped_offline", "pipeline": "8_nodes_active"}


# ── CLI Pipeline Engine ─────────────────────────────────────────────────

def ingest_file(file_path: Path, output_json_path: Optional[Path] = None) -> int:
    """Ingest a single log file using the 8-node pipeline."""
    if not file_path.exists() or file_path.stat().st_size == 0:
        print(f"  [SKIPPED] {file_path.name} is empty or missing.")
        return 0

    events = pipeline.ingest_file(file_path, persist=True)
    fmt = events[0].log_format if events else "unknown"
    print(f"  ✓ {file_path.name}: Normalized {len(events)} event(s) as [{fmt.upper()}]")

    if output_json_path:
        out_p = Path(output_json_path)
        out_p.parent.mkdir(parents=True, exist_ok=True)
        dump_data = [ev.model_dump(mode="json") for ev in events]
        out_p.write_text(json.dumps(dump_data, indent=2, default=str), encoding="utf-8")
        print(f"  📥 Saved single-file normalized output to: {out_p.resolve()}")

    return len(events)


def ingest_path(target_path: Path, output_json_path: Optional[Path] = None) -> None:
    """Ingest a file or directory of log files through the 8-node pipeline."""
    # Ensure custom parsers are loaded for CLI
    load_and_register_all_custom_parsers()

    total = 0
    if target_path.is_file():
        total += ingest_file(target_path, output_json_path=output_json_path)
    elif target_path.is_dir():
        files = sorted([p for p in target_path.iterdir() if p.is_file() and not p.name.startswith(".")])
        print(f"\n📂 Processing {len(files)} file(s) in {target_path} via 8-Node Pipeline...")
        for f in files:
            total += ingest_file(f)
    print(f"\n✨ Ingestion complete: {total} total event(s) normalized & persisted into DuckDB.")


def print_evaluation_report(results: Dict[str, Any]) -> None:
    """Pretty-print benchmark results."""
    print("\n" + "=" * 65)
    print("      ULPF NORMALIZATION & CONVERSION ACCURACY REPORT")
    print("=" * 65)
    print(f"  • Total Test Events Evaluated: {results.get('total_test_events')}")
    print(f"  • Format Detection Accuracy:   {results.get('format_detection_accuracy_percent')}%")
    print(f"  • Overall Field Accuracy:       {results.get('overall_field_accuracy_percent')}%\n")
    print("  Field Breakdown:")
    print("  " + "-" * 60)
    print(f"  {'Field Name':<20} | {'Accuracy':<10} | {'Correct / Expected'}")
    print("  " + "-" * 60)
    for field, data in results.get("field_accuracies", {}).items():
        print(f"  {field:<20} | {data['accuracy_percent']:>8}% | {data['correct']}/{data['expected']}")
    print("=" * 65 + "\n")


def print_file_completeness_report(results: Dict[str, Any]) -> None:
    """Pretty-print file integrity and completeness results."""
    print("\n" + "=" * 65)
    print(f"   FILE INTEGRITY & COMPLETENESS REPORT: {results.get('file_name')}")
    print("=" * 65)
    print(f"  • Raw Lines / Events:        {results.get('raw_event_count')}")
    print(f"  • Normalized Events Emitted: {results.get('normalized_event_count')}")
    print(f"  • Unparsed Events:           {results.get('unparsed_event_count')}")
    print(f"  • Duplicate Raw IDs:         {results.get('duplicate_count')}")
    print(f"  • Fan-out Ratio:             {results.get('fan_out_ratio')} (Target: 1.00)")
    print(f"  • Count Integrity Verified:  {'✓ PASSED' if results.get('event_count_integrity_passed') else '✗ FAILED'}")
    print(f"  • Primary Detected Format:   {results.get('detected_format', '').upper()}\n")
    print("  Field Completeness (Populated non-null values):")
    print("  " + "-" * 60)
    print(f"  {'Field Name':<20} | {'Completeness':<12} | {'Populated Count'}")
    print("  " + "-" * 60)
    for field, data in results.get("field_completeness", {}).items():
        print(f"  {field:<20} | {data['completeness_percent']:>10}% | {data['populated_count']}")
    print("=" * 65 + "\n")


def main():
    parser = argparse.ArgumentParser(description="ULPF CLI — Universal Log Pre-processing Framework")
    parser.add_argument("path", nargs="?", help="File or directory of logs to ingest")
    parser.add_argument("-o", "--output", help="Save normalized output of this single file as JSON")
    parser.add_argument("--evaluate-accuracy", action="store_true", help="Run ground-truth accuracy benchmark")
    parser.add_argument("--evaluate-file", metavar="FILE_PATH", help="Evaluate event count integrity and field completeness for a log file")
    parser.add_argument("--stats", action="store_true", help="Print database statistics")
    parser.add_argument("--list-events", action="store_true", help="List recent normalized events")
    parser.add_argument("--show-event", metavar="EVENT_ID", help="Inspect single event with raw log traceability")
    parser.add_argument("--export-parquet", metavar="OUT_FILE", help="Export normalized events to Parquet")
    parser.add_argument("--export-json", metavar="OUT_FILE", help="Export normalized events to JSON file")
    parser.add_argument("--export-csv", metavar="OUT_FILE", help="Export normalized events to CSV file")

    args = parser.parse_args()

    if args.evaluate_accuracy:
        results = evaluate_ground_truth()
        print_evaluation_report(results)
        return

    if args.evaluate_file:
        results = evaluate_log_file(args.evaluate_file)
        print_file_completeness_report(results)
        return

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
