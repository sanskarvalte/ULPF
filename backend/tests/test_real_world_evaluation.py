"""
Regression and verification tests for the ULPF Real-World Unknown Log Evaluation.
Asserts 13 categories, 12 metrics per category, LogHub dataset benchmarks,
lossless raw data preservation, and zero hallucination/fabrication.
"""

from __future__ import annotations

import json
from pathlib import Path
import pytest

from app.evaluation.real_world_evaluator import (
    _build_evaluation_matrix,
    evaluate_category,
    run_full_real_world_evaluation,
)
from app.normalization.engine import normalize_event
from app.ai.ollama_detector import process_unmatched_log_with_ai


def test_13_category_matrix_completeness():
    """Verify that all 13 required categories are present and populated."""
    matrix = _build_evaluation_matrix()
    expected_categories = [
        "known_linux_logs",
        "authentication_logs",
        "apache_web_logs",
        "hadoop_logs",
        "openssh_logs",
        "database_logs",
        "firewall_network_logs",
        "application_logs",
        "key_value_logs",
        "custom_delimited_logs",
        "json_logs",
        "xml_logs",
        "mixed_structured_logs",
    ]
    assert len(matrix) == 13
    for cat in expected_categories:
        assert cat in matrix, f"Missing category: {cat}"
        cat_id, items = matrix[cat]
        assert cat_id >= 1
        assert len(items) >= 2, f"Category {cat} should have at least 2 test items"


def test_custom_delimited_uncertainty_and_no_fabrication():
    """Verify that ambiguous custom delimited logs are marked uncertain and not fabricated."""
    matrix = _build_evaluation_matrix()
    _, items = matrix["custom_delimited_logs"]
    
    # Check delim_semicolon_fail
    semi_item = next(it for it in items if it.item_id == "delim_semicolon_fail")
    ev = process_unmatched_log_with_ai(semi_item.raw)
    norm = normalize_event(ev)
    
    # Raw event must be preserved losslessly
    assert norm.raw_event == semi_item.raw
    # Must not fabricate an OCSF category out of thin air
    assert norm.category_name is None
    # Must record insufficient semantic evidence / low confidence
    assert norm.unmapped.get("classification_reason") == "insufficient_semantic_evidence"


def test_kernel_iptables_firewall_classification():
    """Regression test: kernel logs with iptables dropped packets must classify as Network Activity, not generic System Activity."""
    raw = "Oct 11 22:15:00 fw-01 kernel: [12345.67] IPTables-Dropped: IN=eth0 OUT= SRC=192.168.1.99 DST=10.0.0.100 PROTO=TCP SPT=49876 DPT=22 ACTION=DROP"
    from app.parsers.syslog_parser import SyslogParser
    parser = SyslogParser()
    ev = parser.parse(raw)
    norm = normalize_event(ev)
    
    assert norm.category_name == "Network Activity"
    assert norm.activity_name in ("Drop", "DROP")
    assert norm.src_ip == "192.168.1.99"
    assert norm.dst_ip == "10.0.0.100"
    assert norm.src_port == 49876
    assert norm.dst_port == 22


def test_hadoop_app_lifecycle_classification():
    """Regression test: Hadoop and YARN logs with dotted class names decompose and classify as Application Activity."""
    raw = "2015-10-18 18:02:00,105 WARN [AsyncDispatcher event handler] org.apache.hadoop.yarn.server.nodemanager.containermanager.ContainerManagerImpl: Event EventType: CONTAINER_INIT failed"
    ev = process_unmatched_log_with_ai(raw)
    norm = normalize_event(ev)
    
    assert norm.category_name == "Application Activity"
    assert norm.severity == "High"  # Enforced by keyword floor on 'failed'
    assert norm.status == "Failure"


def test_real_world_evaluation_run_and_report():
    """Run full evaluation suite and verify machine-readable report schema and performance."""
    report = run_full_real_world_evaluation()
    
    assert report["total_categories_tested"] == 13
    assert report["total_test_events"] >= 36
    
    agg = report["aggregate_metrics"]
    assert agg["format_detection_accuracy"] >= 95.0
    assert agg["parse_success_rate"] == 100.0
    assert agg["ocsf_classification_accuracy"] >= 95.0
    assert agg["overall_accuracy"] >= 90.0
    assert agg["total_ollama_calls"] == 0
    assert agg["aggregate_events_per_second"] > 30.0
    
    # Check machine-readable file was persisted
    report_file = Path(__file__).resolve().parent.parent.parent / "datasets" / "evaluation" / "real_world_evaluation_report.json"
    assert report_file.exists()
    
    with open(report_file, "r", encoding="utf-8") as f:
        data = json.load(f)
    assert data["benchmark"] == "ULPF Real-World Unknown Log Evaluation"
    assert "loghub_benchmark" in data
    loghub_datasets = {d["dataset_name"]: d for d in data["loghub_benchmark"]}
    assert "Android_2k.log" in loghub_datasets
    assert "Mac_2k.log" in loghub_datasets
    assert loghub_datasets["Android_2k.log"]["parse_success_rate"] == 100.0
    assert loghub_datasets["Mac_2k.log"]["parse_success_rate"] == 100.0
