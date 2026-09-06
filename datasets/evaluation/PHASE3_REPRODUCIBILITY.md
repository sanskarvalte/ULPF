# ULPF Phase 3.1 — Reproducibility & Benchmark Specification

## 1. Evaluated Datasets
The benchmark suite evaluates 6 representative heterogeneous log formats:
- **A. Known Android**: Android Logcat activity manager launch log.
- **B. Known Syslog/Mac**: Mac OS xpc launchd service execution log.
- **C. Known Linux or Hadoop**: Linux SSH authentication failure.
- **D. Unknown ZooKeeper**: ZooKeeper node startup log (ambiguous semantics -> `REVIEW`).
- **E. Unknown Turbine Telemetry**: Key-value industrial telemetry log (`rpm`, `temp_c`, `vibration_g`).
- **F. Positional/Delimited Unknown**: Pipe-delimited financial trading log (`TRADE_EXEC`).

Ground truth definitions are located at:
`datasets/ground_truth/phase3_ground_truth.json`

## 2. Metric Formulas & Decoupling Guarantees
All empirical metrics are computed against verified ground truth and strictly decoupled:
- **Event Count Accuracy**: `min(actual_events, expected_events) / max(actual_events, expected_events) * 100.0`
- **Field Presence Accuracy**: `detected_expected_fields / total_expected_fields * 100.0`
- **Field Value Accuracy**: `matching_field_values / total_evaluated_fields * 100.0`
- **Field Name Accuracy**: `matching_field_names / total_expected_fields * 100.0`
- **Timestamp Accuracy**: `correct_parsed_timestamps / expected_timestamps * 100.0`
- **OCSF Semantic Accuracy**: `correctly_classified_or_review_guarded / total_evaluated * 100.0`
- **Unknown Field Preservation**: `preserved_unknown_fields / present_unknown_fields * 100.0`
- **Validation Rate**: `structurally_valid_events / total_events * 100.0`
- **Confidence**: `mean(heuristic_scores)` (reported in its own column; never substituted for accuracy)

**Verification Rules**:
- Confidence != Accuracy: High confidence (0.99) does not imply correctness; low confidence (0.20) in raw fallback can still preserve 100% of data.
- Validation != Accuracy: An event may be 100% extracted from raw log but fail OCSF validation if required fields (like timestamp) are absent.
- Accuracy is NEVER derived from model output or parser validation gates.

## 3. Cold vs Warm Registry Isolation Procedure
To guarantee that cold unknown benchmarks do not read from pre-existing learned parsers and do not pollute the user's production registry:
1. An isolated temporary registry file is initialized at `data/parsers/temp_isolated_benchmark_registry.json`.
2. The environment variable `ULPF_REGISTRY_FILE` is set to point to this temporary registry.
3. Cold Run 1 starts with an empty registry, forcing the pipeline to invoke Ollama (calls > 0), generate the parser specification, validate it, and promote it into the temporary registry.
4. Warm Run 2 uses the exact same input. The fingerprint is now present in the temporary registry; it loads from `learned_cache` with Ollama calls = 0 and verifies identical output.
5. Upon benchmark completion, the temporary registry file is deleted and `ULPF_REGISTRY_FILE` is unset.
6. The production registry (`data/parsers/registry.json`) is never modified.

## 4. Execution Command
To execute the benchmark reproducibly:
```bash
.venv\Scripts\python.exe backend/app/evaluation/accuracy_benchmark.py
```

## 5. Expected Results
- Format Detection: 100%
- Event Count Accuracy: 100%
- Field Presence: 100%
- Field Value Accuracy: 100%
- OCSF Semantic Accuracy: 100% (with ambiguous logs D/E/F correctly routed to `REVIEW`)
- Unknown Field Preservation: 100%
- Structural Validation Rate: 100% (including Dataset E timestamp mapping)
- Cold Unknown: Ollama calls > 0
- Warm Unknown: Ollama calls = 0
- Blockchain Integrity: `VALID` (55,367+ blocks validated)

## 6. Known Limitations
- When local Ollama is offline or models are unloaded, unknown formats fall back to deterministic review preserving the entire raw event into unmapped dictionary with confidence = 0.20.
