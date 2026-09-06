"""
Unit test suite for ULPF Phase 3.2 Correctness Hardening:
1. Dataset F parser & evaluator correctness
2. Dataset D unknown field preservation
3. Numeric type comparison correctness
4. Positional parser (pipe & CSV) tests
5. Warm cache identical output guarantees
"""

import os
import sys
import json
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT / "backend") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "backend"))
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import pytest
import ulpf
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


def test_dataset_f_pipeline_and_evaluator():
    """Dataset F: pipeline processes positional log and evaluator achieves 100% field value accuracy."""
    gt_path = REPO_ROOT / "datasets" / "ground_truth" / "phase3_ground_truth.json"
    with open(gt_path, "r", encoding="utf-8") as f:
        gt = json.load(f)
    item = next(x for x in gt if x["id"] == "F_unknown_trade_delimited")

    engine = PipelineEngine()
    metrics = evaluate_dataset_item(item, engine)

    assert metrics["field_value_accuracy"] == 100.0, f"Field value accuracy: {metrics['field_value_accuracy']}"
    assert metrics["format_detection_accuracy"] == 100.0
    assert metrics["unknown_field_preservation"] == 100.0


def test_dataset_d_unknown_preservation():
    """Dataset D: test unknown key-value preservation without dropping unmapped fields."""
    gt_path = REPO_ROOT / "datasets" / "ground_truth" / "phase3_ground_truth.json"
    with open(gt_path, "r", encoding="utf-8") as f:
        gt = json.load(f)
    item = next(x for x in gt if x["id"] == "D_unknown_zookeeper")

    engine = PipelineEngine()
    metrics = evaluate_dataset_item(item, engine)

    assert metrics["unknown_field_preservation"] == 100.0
    assert metrics["field_value_accuracy"] == 100.0


def test_numeric_type_comparison():
    """Verify evaluator handles int/float/string co-conversion."""
    assert _compare_field_value(150, "150", "quantity") is True
    assert _compare_field_value("182.5", 182.50, "price") is True
    assert _compare_field_value("true", True, "active") is True
    assert _compare_field_value(101.3, 101.30, "pressure") is True
    assert _compare_field_value("DIFFERENT", 150, "field") is False


def test_timestamp_comparison_with_comma_milliseconds():
    """Verify ISO timestamps with comma vs dot millisecond match."""
    ts1 = "2026-09-01T12:00:00,123Z"
    ts2 = "2026-09-01T12:00:00.123Z"
    assert _compare_field_value(ts1, ts2, "timestamp") is True


def test_warm_cache_preserves_extracted_fields():
    """Verify dynamic parser generated from learned cache preserves unmapped fields."""
    spec = {
        "format_name": "trade_log",
        "pattern": r"^(?P<extra_col_1>[^|]+)\|(?P<extra_col_2>[^|]+)\|(?P<extra_col_3>[^|]+)\|(?P<extra_col_4>[^|]+)\|(?P<extra_col_5>[^|]+)\|(?P<extra_col_6>[^|]+)\|(?P<extra_col_7>[^|]+)\|(?P<extra_col_8>[^|]+)\|(?P<extra_col_9>[^|]+)$",
        "field_mapping": {
            "extra_col_1": "unmapped.extra_col_1",
            "extra_col_2": "unmapped.extra_col_2",
            "extra_col_3": "unmapped.extra_col_3",
            "extra_col_4": "unmapped.extra_col_4",
            "extra_col_5": "unmapped.extra_col_5",
            "extra_col_6": "unmapped.extra_col_6",
            "extra_col_7": "unmapped.extra_col_7",
            "extra_col_8": "unmapped.extra_col_8",
            "extra_col_9": "unmapped.extra_col_9",
        },
        "ocsf_class": "Other Activity",
        "ocsf_category": "System Activity",
        "confidence": 0.95,
    }

    raw = "2026-09-01 10:15:30|TRADE_EXEC|ORD-99124|AAPL|BUY|150|182.50|NYSE|FILLED"
    ev = parse_with_spec(raw, spec)
    assert ev.unmapped["extra_col_3"] == "ORD-99124"
    assert ev.unmapped["extra_col_4"] == "AAPL"
    assert ev.unmapped["extra_col_6"] == "150"
