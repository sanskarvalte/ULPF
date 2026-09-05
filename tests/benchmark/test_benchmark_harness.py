"""
Tests for ULPF Benchmark Harness & Reproducibility.
"""

from __future__ import annotations

import json
from pathlib import Path
import pytest

from tests.benchmark.benchmark_runner import run_dataset_benchmark, RESULTS_DIR
from app.pipeline import PipelineEngine



def test_ssh_benchmark_execution():
    report = run_dataset_benchmark("SSH_sample")

    assert report["dataset"] == "SSH_sample"
    assert report["events"] == 3
    assert report["parsed_events"] == 3
    assert report["normalized_events"] == 3
    assert report["parse_accuracy"] == 1.0
    assert report["field_accuracy"] >= 0.95
    assert report["semantic_accuracy"] == 1.0
    assert report["validation_rate"] == 1.0
    assert report["ollama_calls"] == 0
    assert report["processing_time_ms"] > 0
    assert report["avg_event_time_ms"] > 0
    assert report["events_per_second"] > 0
    assert report["peak_memory_mb"] > 0
    assert report["classified_events"] == 3
    assert report["incorrect_events"] == 0

    res_file = RESULTS_DIR / "SSH_sample_benchmark_result.json"
    assert res_file.exists()
    with open(res_file, "r", encoding="utf-8") as f:
        saved = json.load(f)
    assert saved["dataset"] == "SSH_sample"


def test_apache_benchmark_execution():
    report = run_dataset_benchmark("Apache_sample")

    assert report["dataset"] == "Apache_sample"
    assert report["events"] == 3
    assert report["parsed_events"] == 3
    assert report["normalized_events"] == 3
    assert report["parse_accuracy"] == 1.0
    assert report["semantic_accuracy"] == 1.0
    assert report["validation_rate"] == 1.0
    assert report["ollama_calls"] == 0
    assert report["classified_events"] == 3
    assert report["incorrect_events"] == 0


def test_linux_benchmark_execution():
    report = run_dataset_benchmark("Linux_sample")

    assert report["dataset"] == "Linux_sample"
    assert report["events"] == 3
    assert report["parsed_events"] == 3
    assert report["normalized_events"] == 3
    assert report["parse_accuracy"] == 1.0
    assert report["semantic_accuracy"] == 1.0
    assert report["validation_rate"] == 1.0
    assert report["ollama_calls"] == 0
    assert report["classified_events"] == 3
    assert report["incorrect_events"] == 0


def test_hadoop_benchmark_execution():
    report = run_dataset_benchmark("Hadoop_sample")

    assert report["dataset"] == "Hadoop_sample"
    assert report["events"] == 3
    assert report["parsed_events"] == 3
    assert report["normalized_events"] == 3
    assert report["parse_accuracy"] == 1.0
    assert report["semantic_accuracy"] == 1.0
    assert report["validation_rate"] == 1.0
    assert report["ollama_calls"] == 0
    assert report["classified_events"] == 3
    assert report["incorrect_events"] == 0


def test_benchmark_missing_ground_truth_returns_null(tmp_path):
    """When no ground truth is available, semantic_accuracy and field_accuracy MUST be None (null)."""
    from app.config import ULPFConfig
    engine = PipelineEngine(config=ULPFConfig(ai_enabled=False))

    report = run_dataset_benchmark(
        dataset_name="SSH_sample",
        expected_path=tmp_path / "non_existent.json",
        engine=engine,
    )

    assert report["dataset"] == "SSH_sample"
    assert report["events"] == 3
    assert report["parsed_events"] == 3
    assert report["normalized_events"] == 3
    assert report["parse_accuracy"] == 1.0
    # Must NOT be 0.0, 1.0, or confidence — must be None (serializes to null)
    assert report["semantic_accuracy"] is None
    assert report["field_accuracy"] is None
    assert report["validation_rate"] == 1.0


