"""
ULPF LogHub & Dataset Benchmark Runner.

Executes reproducible evaluation of log datasets, computing:
- parse_accuracy
- field_accuracy
- semantic_accuracy
- validation_rate
- ollama_calls
- processing_time_ms

Outputs structured, machine-readable benchmark reports.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
import time
from typing import Any, Dict, List, Optional

backend_dir = str(Path(__file__).resolve().parent.parent.parent / "backend")
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from app.ai.ollama_client import get_ollama_call_count, reset_ollama_telemetry
from app.evaluation.semantic_evaluator import evaluate_batch_semantics
from app.ingestion.detector import (
    _looks_like_apache,
    _looks_like_hadoop,
    matcher_registry,
    parse_apache_log,
    parse_hadoop_log,
)
from app.pipeline import PipelineEngine


import tracemalloc


BENCHMARK_DIR = Path(__file__).resolve().parent
DATASETS_DIR = BENCHMARK_DIR / "datasets"
EXPECTED_DIR = BENCHMARK_DIR / "expected"
RESULTS_DIR = BENCHMARK_DIR / "results"


def run_dataset_benchmark(
    dataset_name: str,
    dataset_path: Optional[Path] = None,
    expected_path: Optional[Path] = None,
    engine: Optional[PipelineEngine] = None,
) -> Dict[str, Any]:
    """
    Run benchmark against a specific dataset file and compare with expected semantic truth.
    Measures processing time, throughput (eps), and memory usage.
    """
    # Register dataset-specific matchers for LogHub formats dynamically
    d_lower = dataset_name.lower()
    registered_temp = None
    if "apache" in d_lower:
        matcher_registry.register("apache", _looks_like_apache, parse_apache_log, is_custom=True)
        registered_temp = "apache"
    elif "hadoop" in d_lower or "hdfs" in d_lower:
        matcher_registry.register("hadoop", _looks_like_hadoop, parse_hadoop_log, is_custom=True)
        registered_temp = "hadoop"

    d_path = dataset_path or (DATASETS_DIR / f"{dataset_name}.log")
    if not d_path.exists():
        # Fallback to .txt or dataset_name without extension
        for ext in (".txt", ""):
            cand = DATASETS_DIR / f"{dataset_name}{ext}"
            if cand.exists():
                d_path = cand
                break

    if not d_path.exists():
        raise FileNotFoundError(f"Dataset file '{dataset_name}' not found at {d_path}")

    exp_path = expected_path or (EXPECTED_DIR / f"{dataset_name}.json")
    expected_events: List[Dict[str, Any]] = []
    if exp_path.exists():
        with open(exp_path, "r", encoding="utf-8") as f:
            raw_exp = json.load(f)
            if isinstance(raw_exp, dict) and "events" in raw_exp:
                expected_events = raw_exp["events"]
            elif isinstance(raw_exp, list):
                expected_events = raw_exp

    pipe = engine or PipelineEngine()
    reset_ollama_telemetry()

    try:
        tracemalloc.start()
        start_time = time.perf_counter()
        res = pipe.process_file(d_path)
        total_time_s = time.perf_counter() - start_time
        _, peak_bytes = tracemalloc.get_traced_memory()
        tracemalloc.stop()
    finally:
        if registered_temp:
            matcher_registry._entries = [e for e in matcher_registry._entries if e[0].lower() != registered_temp]
            matcher_registry._custom_format_names.discard(registered_temp)

    elapsed_ms = round(total_time_s * 1000.0, 2)
    peak_memory_mb = round(peak_bytes / (1024.0 * 1024.0), 3)


    events = res.get("events", [])
    raw_count = res.get("raw_count", len(events))
    parsed_count = res.get("parsed_count", len(events))
    normalized_count = res.get("normalized_count", len(events))
    ollama_calls = res.get("ollama_calls", get_ollama_call_count())

    avg_event_time_ms = round(elapsed_ms / raw_count, 3) if raw_count > 0 else 0.0
    events_per_second = round(raw_count / total_time_s, 2) if total_time_s > 0 else 0.0

    # Build pairs of (event, expected, aliases)
    has_ground_truth = len(expected_events) > 0
    pairs = []
    for idx, ev in enumerate(events):
        if has_ground_truth and idx < len(expected_events):
            item = expected_events[idx]
            if isinstance(item, dict) and "expected" in item:
                exp_dict = item["expected"]
                aliases = item.get("aliases", {})
            else:
                exp_dict = item if isinstance(item, dict) else {}
                aliases = {}
            pairs.append((ev, exp_dict, aliases))
        else:
            pairs.append((ev, {}, {}))

    eval_metrics = evaluate_batch_semantics(pairs, total_raw_events=raw_count)

    # Convert to normalized float rates [0.0 - 1.0] or None matching benchmark specification
    report = {
        "dataset": dataset_name,
        "events": raw_count,
        "parsed_events": parsed_count,
        "normalized_events": normalized_count,
        "validation_rate": round(eval_metrics["validation_rate"] / 100.0, 3) if eval_metrics.get("validation_rate") is not None else 1.0,
        "parse_accuracy": round(eval_metrics["parse_accuracy"] / 100.0, 3) if eval_metrics.get("parse_accuracy") is not None else 1.0,
        "field_accuracy": round(eval_metrics["field_accuracy"] / 100.0, 3) if eval_metrics.get("field_accuracy") is not None else None,
        "semantic_accuracy": round(eval_metrics["semantic_accuracy"] / 100.0, 3) if eval_metrics.get("semantic_accuracy") is not None else None,
        "classified_events": eval_metrics["classified_events"],
        "review_events": eval_metrics["review_events"],
        "unknown_events": eval_metrics["unknown_events"],
        "incorrect_events": eval_metrics["incorrect_events"],
        "ollama_calls": ollama_calls,
        "processing_time_ms": elapsed_ms,
        "avg_event_time_ms": avg_event_time_ms,
        "events_per_second": events_per_second,
        "peak_memory_mb": peak_memory_mb,
    }

    # Persist report
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    out_file = RESULTS_DIR / f"{dataset_name}_benchmark_result.json"
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    return report


def main():
    parser = argparse.ArgumentParser(description="ULPF Benchmark Runner")
    parser.add_argument("--dataset", "-d", default="SSH_sample", help="Dataset name to benchmark")
    parser.add_argument("--output", "-o", help="Optional custom output path for benchmark report JSON")
    args = parser.parse_args()

    report = run_dataset_benchmark(args.dataset)
    if args.output:
        out_p = Path(args.output)
        out_p.parent.mkdir(parents=True, exist_ok=True)
        with open(out_p, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
