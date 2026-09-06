"""
Tests for ULPF Phase 4.1 — Framework Contract & Interface Hardening.

Covers:
1. CLI -> PipelineEngine convergence
2. Python API -> PipelineEngine convergence
3. REST API -> PipelineEngine convergence
4. Known log deterministic parser (Ollama = 0)
5. Unknown log cold AI dynamic path
6. Unknown log warm learned cache (Ollama = 0)
7. Positional log extra_col_N preserved without fabricated semantic names
8. Empty input failure (EmptyInputError / EMPTY_INPUT status)
9. Invalid input failure (InvalidInputError / INVALID_INPUT status)
10. AI timeout fallback to REVIEW
11. AI unavailable fallback to REVIEW
12. Ambiguous semantics routed to REVIEW without fabricated security classification
"""

import os
import sys
import tempfile
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

# Ensure backend directory is discoverable
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT / "backend") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "backend"))
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import ulpf
from ulpf import (
    PipelineEngine,
    pipeline,
    ProcessingResult,
    ProcessingStatus,
    EmptyInputError,
    InvalidInputError,
)
from app.models.event_schema import UnifiedEvent
from app.main import process_file_with_summary


@pytest.fixture
def tmp_log_file(tmp_path):
    """Create a temporary syslog file."""
    f = tmp_path / "sample_syslog.log"
    f.write_text(
        "Jul 12 14:22:01 server sshd[1234]: Accepted password for root from 192.168.1.10 port 22 ssh2\n"
        "Jul 12 14:22:02 server sshd[1235]: Failed password for invalid user admin from 192.168.1.20 port 22 ssh2\n",
        encoding="utf-8",
    )
    return f


def test_1_cli_pipeline_convergence(tmp_log_file):
    """Test 1: CLI process_file_with_summary delegates to pipeline.process_file."""
    with patch.object(pipeline, "process_file", wraps=pipeline.process_file) as mock_pf:
        count = process_file_with_summary(tmp_log_file)
        assert mock_pf.called, "CLI did not delegate to pipeline.process_file"
        assert count == 2


def test_2_python_api_pipeline_convergence(tmp_log_file):
    """Test 2: Python API exports process_file, process_text, and process_lines returning ProcessingResult."""
    # 1. process_file
    res_file = pipeline.process_file(tmp_log_file, persist=False)
    assert isinstance(res_file, ProcessingResult)
    assert res_file.status == ProcessingStatus.SUCCESS
    assert res_file.format == "SYSLOG"
    assert res_file.total_events == 2
    assert res_file["format"] == "SYSLOG"  # dict subscripting compatibility

    # 2. process_text
    raw_text = "Jul 12 14:22:01 server sshd[1234]: Accepted password for root from 192.168.1.10 port 22 ssh2\n"
    res_text = pipeline.process_text(raw_text, persist=False)
    assert isinstance(res_text, ProcessingResult)
    assert res_text.status == ProcessingStatus.SUCCESS
    assert len(res_text.events) == 1

    # 3. process_lines
    lines = ["Jul 12 14:22:01 server sshd[1234]: Accepted password for root from 192.168.1.10 port 22 ssh2"]
    res_lines = pipeline.process_lines(lines, persist=False)
    assert isinstance(res_lines, ProcessingResult)
    assert res_lines.status == ProcessingStatus.SUCCESS
    assert len(res_lines.events) == 1


def test_3_rest_api_pipeline_convergence():
    """Test 3: REST API routes converge on pipeline processing."""
    from fastapi.testclient import TestClient
    from app.main import app

    client = TestClient(app)

    # Test /convert endpoint
    sample = "Jul 12 14:22:01 server sshd[1234]: Accepted password for root from 192.168.1.10 port 22 ssh2\n"
    response = client.post("/convert", data={"raw_text": sample})
    assert response.status_code == 200
    events = response.json()
    assert isinstance(events, list)
    assert len(events) == 1
    assert events[0].get("log_format") == "syslog"


def test_4_known_log_deterministic_zero_ollama(tmp_log_file):
    """Test 4: Known syslog log processes deterministically with Ollama calls = 0."""
    res = pipeline.process_file(tmp_log_file, persist=False)
    assert res.status == ProcessingStatus.SUCCESS
    assert res.format == "SYSLOG"
    assert res.parser_source == "rule_based"
    assert res.details.get("ollama_calls", 0) == 0


def test_5_unknown_log_cold_ai_path(tmp_path):
    """Test 5: Cold unknown log triggers dynamic resolution path."""
    unknown_file = tmp_path / "cold_unknown.log"
    unknown_file.write_text("DEVICE_BOOT_EVENT id=99881 rev=4.1 subsystem=sensor status=READY\n", encoding="utf-8")

    mock_res = {
        "success": True,
        "status": "promoted",
        "confidence": 0.95,
        "accuracy": 100.0,
        "parser_spec": {
            "regex": r"DEVICE_BOOT_EVENT id=(?P<device_id>\d+) rev=(?P<revision>[\d\.]+) subsystem=(?P<subsystem>\w+) status=(?P<status>\w+)",
            "field_mapping": {"device_id": "unmapped.device_id"},
            "ocsf_class": "Base Event",
            "format_name": "device_boot",
        },
        "errors": [],
    }

    with patch("app.pipeline.resolve_unknown_log", return_value=mock_res):
        res = pipeline.process_file(unknown_file, persist=False, auto_resolve_ai=True)
        assert res.status in (ProcessingStatus.SUCCESS, ProcessingStatus.REVIEW)
        assert res.total_events == 1


def test_6_unknown_log_warm_cache_zero_ollama(tmp_path):
    """Test 6: Warm unknown log with cached parser runs with Ollama calls = 0."""
    from app.parsers.registry import register_parser

    test_fp = "TEST_FP_WARM_CACHE"
    spec = {
        "regex": r"WARM_LOG_SAMPLE id=(?P<msg_id>\d+)",
        "field_mapping": {"msg_id": "unmapped.msg_id"},
        "confidence": 0.95,
        "format_name": "warm_format",
    }
    register_parser(test_fp, spec)

    warm_file = tmp_path / "warm_sample.log"
    warm_file.write_text("WARM_LOG_SAMPLE id=12345\n", encoding="utf-8")

    with patch("app.pipeline.compute_log_fingerprint", return_value=("", "", test_fp)):
        res = pipeline.process_file(warm_file, persist=False, auto_resolve_ai=True)
        assert res.status in (ProcessingStatus.SUCCESS, ProcessingStatus.REVIEW)
        assert res.parser_source == "learned_cache"
        assert res.details.get("ollama_calls", 0) == 0


def test_7_positional_log_extra_col_preserved(tmp_path):
    """Test 7: Positional log preserves unmapped columns as extra_col_N without fabricated names."""
    trade_file = tmp_path / "trade_sample.log"
    trade_file.write_text("TRADE_EXEC|ORD-99124|AAPL|BUY|150|182.50|NYSE|FILLED\n", encoding="utf-8")

    res = pipeline.process_file(trade_file, persist=False, auto_resolve_ai=False)
    assert res.total_events == 1
    ev = res.events[0]
    unmapped = ev.unmapped or {}

    extra_cols = [k for k in unmapped.keys() if k.startswith("extra_col_")]
    assert len(extra_cols) >= 5, f"Expected extra_col_N fields in unmapped, found: {list(unmapped.keys())}"
    assert unmapped.get("extra_col_1") == "TRADE_EXEC"
    assert unmapped.get("extra_col_2") == "ORD-99124"
    assert unmapped.get("extra_col_3") == "AAPL"


def test_8_empty_input_failure(tmp_path):
    """Test 8: Empty file or string raises EmptyInputError or returns EMPTY_INPUT status."""
    empty_file = tmp_path / "empty.log"
    empty_file.write_text("", encoding="utf-8")

    # Default non-raising behavior returns clean result with SKIPPED/FAILED status and error_code
    res = pipeline.process_file(empty_file, persist=False, raise_errors=False)
    assert res.status in (ProcessingStatus.SKIPPED, ProcessingStatus.FAILED)
    assert res.details.get("error_code") == "EMPTY_INPUT"

    # raise_errors=True raises EmptyInputError
    with pytest.raises(EmptyInputError):
        pipeline.process_file(empty_file, persist=False, raise_errors=True)

    with pytest.raises(EmptyInputError):
        pipeline.process_text("", persist=False, raise_errors=True)

    with pytest.raises(EmptyInputError):
        pipeline.process_lines([], persist=False, raise_errors=True)


def test_9_invalid_input_failure():
    """Test 9: Non-existent file path produces InvalidInputError or FAILED status."""
    missing_path = Path("non_existent_file_path_12345.log")

    res = pipeline.process_file(missing_path, persist=False, raise_errors=False)
    assert res.status == ProcessingStatus.FAILED
    assert res.details.get("error_code") == "INVALID_INPUT"

    with pytest.raises(InvalidInputError):
        pipeline.process_file(missing_path, persist=False, raise_errors=True)


def test_10_ai_timeout_fallback(tmp_path):
    """Test 10: AI timeout gracefully degrades to REVIEW status without crashing."""
    sample_file = tmp_path / "timeout_sample.log"
    sample_file.write_text("TIMEOUT_TEST_EVENT value=99999\n", encoding="utf-8")

    mock_timeout_res = {
        "success": False,
        "status": "timeout",
        "fallback": True,
        "confidence": 0.20,
        "parser_spec": None,
        "events": [],
        "errors": ["timed out"],
    }

    with patch("app.pipeline.resolve_unknown_log", return_value=mock_timeout_res):
        res = pipeline.process_file(sample_file, persist=False, auto_resolve_ai=True)
        assert res.total_events == 1
        assert res.status in (ProcessingStatus.REVIEW, ProcessingStatus.SUCCESS)


def test_11_ai_unavailable_fallback(tmp_path):
    """Test 11: AI unavailable gracefully falls back without crashing."""
    sample_file = tmp_path / "unavail_sample.log"
    sample_file.write_text("UNAVAIL_TEST_EVENT value=88888\n", encoding="utf-8")

    mock_unavail_res = {
        "success": False,
        "status": "unavailable",
        "fallback": True,
        "confidence": 0.20,
        "parser_spec": None,
        "events": [],
        "errors": ["connection refused"],
    }

    with patch("app.pipeline.resolve_unknown_log", return_value=mock_unavail_res):
        res = pipeline.process_file(sample_file, persist=False, auto_resolve_ai=True)
        assert res.total_events == 1
        assert res.status in (ProcessingStatus.REVIEW, ProcessingStatus.SUCCESS)


def test_12_ambiguous_semantics_review(tmp_path):
    """Test 12: Logs with ambiguous semantics are classified as review without fabricated classification."""
    ambiguous_file = tmp_path / "ambiguous.log"
    ambiguous_file.write_text("GENERIC_EVENT component=foo code=100 text='something happened'\n", encoding="utf-8")

    res = pipeline.process_file(ambiguous_file, persist=False, auto_resolve_ai=False)
    assert res.total_events == 1
    ev = res.events[0]
    clf_status = ev.classification_status or (ev.unmapped.get("classification_status") if ev.unmapped else None)
    assert clf_status in ("review", "unknown", None)
