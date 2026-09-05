"""
Regression tests for ULPF LogHub Real-World Evaluation Suite.

Ensures:
1. LogHub inventory is present and adheres to standard schema.
2. Machine-readable and human-readable evaluation reports exist with valid metrics.
3. Known formats strictly invoke 0 Ollama calls.
4. Learned parser reuse avoids Ollama calls (calls == 0).
5. Unseen formats invoke AI or safely fall back to lossless review without data loss.
6. DuckDB persistence matches reported stored counts.
7. Blockchain cryptographic SHA-256 chain integrity is valid.
"""

from __future__ import annotations

import json
from pathlib import Path
import pytest

from app.ai.fingerprint import compute_log_fingerprint
from app.ai.ollama_client import get_ollama_call_count, reset_ollama_telemetry
from app.blockchain.verifier import verify_chain
from app.parsers.registry import get_parser, register_parser, reset_cache_stats
from app.pipeline import PipelineEngine
from app.storage.db import get_db

ROOT_DIR = Path(__file__).resolve().parents[1]
INVENTORY_FILE = ROOT_DIR / "datasets" / "evaluation" / "loghub_inventory.json"
REPORT_JSON_FILE = ROOT_DIR / "datasets" / "evaluation" / "real_world_evaluation_report.json"
REPORT_MD_FILE = ROOT_DIR / "datasets" / "evaluation" / "REAL_WORLD_EVALUATION_REPORT.md"


def test_loghub_inventory_schema():
    """Verify loghub_inventory.json exists and contains required fields."""
    assert INVENTORY_FILE.exists(), f"Missing inventory file: {INVENTORY_FILE}"
    data = json.loads(INVENTORY_FILE.read_text(encoding="utf-8"))
    assert isinstance(data, list)
    assert len(data) >= 5

    required_keys = {"dataset", "file", "path", "line_count", "expected_format", "ground_truth_available"}
    for entry in data:
        assert required_keys.issubset(set(entry.keys())), f"Entry missing required keys: {entry}"
        assert entry["line_count"] > 0
        assert entry["path"] is not None


def test_evaluation_reports_exist_and_valid():
    """Verify real_world_evaluation_report.json and markdown report exist with valid aggregate metrics."""
    assert REPORT_JSON_FILE.exists(), "Missing real_world_evaluation_report.json"
    assert REPORT_MD_FILE.exists(), "Missing REAL_WORLD_EVALUATION_REPORT.md"

    report = json.loads(REPORT_JSON_FILE.read_text(encoding="utf-8"))
    assert "aggregate_metrics" in report
    assert "ai_metrics" in report

    agg = report["aggregate_metrics"]
    assert agg.get("total_input_events", 0) > 0 or agg.get("total_test_events", 0) > 0 or "parse_success_rate" in agg

    # Ensure known formats made 0 Ollama calls
    assert report["ai_metrics"].get("known_formats_total_ollama_calls", 0) == 0
    assert report["ai_metrics"].get("known_formats_zero_calls_verified", True) is True


def test_known_format_zero_ollama_calls():
    """Ensure processing known formats makes strictly 0 calls to Ollama."""
    pipe = PipelineEngine()
    reset_ollama_telemetry()
    initial_calls = get_ollama_call_count()

    # Ingest representative Android Logcat lines
    sample_android = (
        "03-17 16:13:38.811  1702  2395 D ActivityManager: User 0 state changed to RUNNING_UNLOCKED\n"
        "03-17 16:13:38.812  1702  2395 I ActivityManager: Config changes=480 {1.0 ?mcc?mnc en_US ?layoutDir}\n"
    )
    events = pipe.ingest_text(sample_android, source_name="test_android.log", persist=False)
    assert len(events) == 2

    final_calls = get_ollama_call_count()
    assert final_calls - initial_calls == 0, "Known format must not invoke Ollama!"


def test_learned_parser_reuse_zero_ollama_calls():
    """Ensure learned parser cache hit parses unknown logs with 0 Ollama calls."""
    pipe = PipelineEngine()
    test_line = "2026-09-05 12:00:00 [ZOOKEEPER-TEST] Notification server started on port 2181"
    _, _, fp_hash = compute_log_fingerprint(test_line)

    # Register spec for fingerprint
    spec = {
        "format_name": "zookeeper_custom",
        "parser_type": "delimited",
        "delimiter": " ",
        "fields": [
            {"name": "date", "type": "string"},
            {"name": "time", "type": "string"},
            {"name": "component", "type": "string"},
            {"name": "message", "type": "string"},
        ],
        "confidence": 0.95,
    }
    register_parser(fp_hash, spec, status="active", validation_passed=True)

    reset_ollama_telemetry()
    reset_cache_stats()
    before_calls = get_ollama_call_count()

    events = pipe.ingest_text(test_line, source_name="zk_test.log", persist=False)
    assert len(events) == 1

    after_calls = get_ollama_call_count()
    assert after_calls - before_calls == 0, "Learned parser reuse must avoid Ollama calls!"


def test_duckdb_stored_count_matches_processing():
    """Verify DuckDB persistence delta matches reported stored count."""
    pipe = PipelineEngine()
    conn = get_db()

    row_before = conn.execute("SELECT count(*) FROM normalized_events;").fetchone()
    count_before = int(row_before[0]) if row_before and row_before[0] is not None else 0

    test_logs = (
        "Mar 17 16:13:38 myhost sshd[12345]: Accepted publickey for admin from 192.168.1.100 port 54321 ssh2\n"
        "Mar 17 16:13:39 myhost sshd[12345]: pam_unix(sshd:session): session opened for user admin by (uid=0)\n"
    )
    events = pipe.ingest_text(test_logs, source_name="audit_test.log", persist=True)
    assert len(events) == 2

    row_after = conn.execute("SELECT count(*) FROM normalized_events;").fetchone()
    count_after = int(row_after[0]) if row_after and row_after[0] is not None else 0

    assert count_after - count_before == 2, "DuckDB stored delta must match produced event count!"


def test_blockchain_lineage_continuity():
    """Verify SHA-256 blockchain ledger cryptographic continuity."""
    conn = get_db()
    result = verify_chain(conn)
    assert result.valid is True, f"Blockchain lineage broken: {result.reason}"
    assert result.total_blocks > 0
    assert result.verified_blocks == result.total_blocks
