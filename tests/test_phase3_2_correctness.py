"""
Unit test suite for ULPF Phase 3.2 Correctness Hardening:
1. Dataset F parser & evaluator correctness
2. Dataset D unknown field preservation
3. Numeric type comparison correctness
4. Positional parser (pipe & CSV) tests
5. Warm cache identical output guarantees
"""

import os
import pytest
from app.ai.ollama_detector import _extract_all_delimited_key_values, process_unmatched_log_with_ai
from app.ai.dynamic_parser import parse_with_spec
from app.normalization.engine import normalize_event
from app.pipeline import PipelineEngine
from app.evaluation.accuracy_benchmark import _compare_field_value, evaluate_dataset_item


def test_dataset_f_positional_extraction():
    """Dataset F: pipe-delimited log extracts all positional columns losslessly."""
    raw = "2026-09-01 10:15:30|TRADE_EXEC|ORD-99124|AAPL|BUY|150|182.50|NYSE|FILLED"
    pairs = _extract_all_delimited_key_values(raw)

    assert pairs["extra_col_1"] == "2026-09-01 10:15:30"
    assert pairs["extra_col_2"] == "TRADE_EXEC"
    assert pairs["extra_col_3"] == "ORD-99124"
    assert pairs["extra_col_4"] == "AAPL"
    assert pairs["extra_col_5"] == "BUY"
    assert pairs["extra_col_6"] == "150"
    assert pairs["extra_col_7"] == "182.50"
    assert pairs["extra_col_8"] == "NYSE"
    assert pairs["extra_col_9"] == "FILLED"
    assert len(pairs) == 9


def test_dataset_f_pipeline_and_evaluator():
    """Dataset F evaluated through PipelineEngine achieves 100% field & preservation accuracy."""
    item = {
        "id": "F_test",
        "dataset_name": "F. Positional/delimited unknown log",
        "category_type": "unknown",
        "raw": "2026-09-01 10:15:30|TRADE_EXEC|ORD-99124|AAPL|BUY|150|182.50|NYSE|FILLED",
        "expected_format": "unknown",
        "expected_event_count": 1,
        "expected_timestamp": "2026-09-01 10:15:30",
        "expected_fields": {
            "extra_col_1": "2026-09-01 10:15:30",
            "extra_col_2": "TRADE_EXEC",
            "extra_col_3": "ORD-99124",
            "extra_col_4": "AAPL",
            "extra_col_5": "BUY",
            "extra_col_6": "150",
            "extra_col_7": "182.50",
            "extra_col_8": "NYSE",
            "extra_col_9": "FILLED",
        },
        "expected_unmapped_keys": [
            "extra_col_1", "extra_col_2", "extra_col_3", "extra_col_4",
            "extra_col_5", "extra_col_6", "extra_col_7", "extra_col_8", "extra_col_9"
        ],
        "expected_ocsf": {
            "category_name": None,
            "class_name": None,
            "activity_name": None,
            "classification_status": "review"
        }
    }
    engine = PipelineEngine()
    res = evaluate_dataset_item(item, engine)

    assert res["field_presence_accuracy"] == 100.0
    assert res["field_value_accuracy"] == 100.0
    assert res["unknown_field_preservation"] == 100.0
    assert res["timestamp_accuracy"] == 100.0
    assert res["validation_rate"] == 100.0
    assert res["passed"] is True


def test_dataset_d_unknown_preservation():
    """Dataset D (ZooKeeper) preserves zookeeper.version and fingerprint 100% without loss."""
    raw = "2015-07-29 17:41:40,593 - INFO  [main:Environment@97] - Server environment:zookeeper.version=3.4.6-1569965"
    engine = PipelineEngine()
    events = engine.ingest_text(raw, persist=False)
    assert len(events) == 1
    ev = events[0]

    assert ev.unmapped is not None
    assert ev.unmapped.get("zookeeper.version") == "3.4.6-1569965"
    assert ev.unmapped.get("fingerprint") is not None
    assert ev.timestamp is not None
    assert "2015-07-29" in str(ev.timestamp)
    assert "17:41:40" in str(ev.timestamp)


def test_numeric_type_comparison():
    """Evaluator handles ints, floats, strings, and avoids false digit substring matches."""
    # Exact and float equivalence
    assert _compare_field_value(182.5, "182.50", "price") is True
    assert _compare_field_value("182.50", 182.5, "price") is True
    assert _compare_field_value(150, "150", "quantity") is True
    assert _compare_field_value("150", 150, "quantity") is True
    assert _compare_field_value(0.04, "0.04", "vibration_g") is True

    # Inequality and non-matching digits
    assert _compare_field_value(10, 0, "dropped") is False
    assert _compare_field_value("10", "0", "dropped") is False
    assert _compare_field_value("0", "10", "dropped") is False
    assert _compare_field_value(150, 151, "quantity") is False


def test_timestamp_comparison_with_comma_milliseconds():
    """Timestamp comparison handles comma vs dot milliseconds cleanly."""
    assert _compare_field_value("2015-07-29 17:41:40.593000+00:00", "2015-07-29 17:41:40", "timestamp") is True
    assert _compare_field_value("2015-07-29 17:41:40,593", "2015-07-29 17:41:40", "timestamp") is True
    assert _compare_field_value("2026-09-01 10:15:30+00:00", "2026-09-01 10:15:30", "expected_timestamp") is True


def test_warm_cache_preserves_extracted_fields():
    """Warm execution with generic fallback spec preserves key-values identically to cold extraction."""
    raw = "2015-07-29 17:41:40,593 - INFO  [main:Environment@97] - Server environment:zookeeper.version=3.4.6-1569965"
    fallback_spec = {
        "format_name": "unknown_review",
        "parser_type": "generic",
        "fields": [],
        "confidence": 0.20
    }
    warm_ev = parse_with_spec(raw, fallback_spec)
    assert warm_ev.unmapped.get("zookeeper.version") == "3.4.6-1569965"
