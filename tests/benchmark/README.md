# ULPF Benchmark Infrastructure

This benchmark infrastructure provides automated, reproducible evaluation of log processing across LogHub and enterprise datasets.

## Directory Structure
```
tests/benchmark/
├── README.md               # Infrastructure documentation & usage
├── benchmark_runner.py     # Deterministic benchmark execution engine
├── datasets/               # Log dataset files (.log, .txt)
├── expected/               # Ground-truth semantic expectations (.json)
└── results/                # Output machine-readable benchmark reports (.json)
```

## Metrics Evaluated
1. **parse_accuracy**: Fraction of raw log lines successfully extracted into structured events.
2. **field_accuracy**: Fraction of extracted fields matching expected values.
3. **semantic_accuracy**: Fraction of events whose OCSF category, class, activity, and status match ground-truth semantics.
4. **validation_rate**: Fraction of events passing structural canonical validation.
5. **ollama_calls**: Total number of calls made to local Ollama (0 for known/learned logs).
6. **processing_time_ms**: Total processing latency in milliseconds.
7. **events_per_second**: Ingestion throughput.

## Usage
Run the benchmark runner directly or via pytest:
```bash
python tests/benchmark/benchmark_runner.py --dataset SSH
```
Or run the automated suite:
```bash
pytest tests/benchmark/test_benchmark_harness.py -v
```
