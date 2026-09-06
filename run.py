#!/usr/bin/env python3
"""
ULPF Local Server Runner.
Runs 100% locally on a specified port without any external online dependencies.
Accesses all 255,000+ DuckDB events directly from local storage.

Usage:
    python run.py [--port 8000] [--host 127.0.0.1]
"""
import sys
import argparse
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# Add backend directory to sys.path
root_dir = Path(__file__).resolve().parent
backend_dir = root_dir / "backend"
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

def main():
    parser = argparse.ArgumentParser(description="Run ULPF locally on a port with all DuckDB events")
    parser.add_argument("--port", "-p", type=int, default=8000, help="Local port to bind (default: 8000)")
    parser.add_argument("--host", "-H", default="127.0.0.1", help="Host interface to bind (default: 127.0.0.1)")
    args = parser.parse_args()

    try:
        from app.storage.normalized import get_total_events_count
        from app.storage.db import reset_db_connection
        total_events = get_total_events_count()
        reset_db_connection()
    except Exception as e:
        total_events = 0

    print("\n" + "=" * 68)
    print("  🚀  ULPF — Universal Log Pre-processing Framework")
    print("  🔒  Running 100% LOCALLY on port without any online dependencies")
    print(f"  📦  Local DuckDB Storage: {total_events:,} events available")
    print(f"  🌐  Web App:       http://{args.host}:{args.port}")
    print(f"  🔍  Log Explorer:  http://{args.host}:{args.port}/#explorer")
    print(f"  📖  Local API:     http://{args.host}:{args.port}/docs")
    print("=" * 68 + "\n")

    import uvicorn
    try:
        uvicorn.run("app.main:app", host=args.host, port=args.port, reload=False)
    finally:
        try:
            from app.storage.db import reset_db_connection
            reset_db_connection()
        except Exception:
            pass

if __name__ == "__main__":
    main()
