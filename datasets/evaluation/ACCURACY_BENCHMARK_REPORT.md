# ULPF Phase 3.1 Hardened Accuracy Benchmark Report

Generated: 2026-09-06T06:10:58.330852+00:00

## Metric Separation & Decoupling Principle
This benchmark enforces strict separation between distinct evaluation dimensions:
1. **Parser Success**: Fraction of events extracted without parser exception.
2. **Validation Success**: Conformance to OCSF schema constraints (e.g., UTC timestamp, valid IP).
3. **Confidence**: Internal heuristic model self-assessment (0.0 to 1.0) — **never conflated with accuracy**.
4. **Extraction Accuracy**: Exact match of extracted values against verified ground truth.
5. **Semantic/OCSF Accuracy**: Correct classification where known, and verified `REVIEW` guard for ambiguous logs.
6. **Lossless Preservation**: Retention of unmapped fields in `unmapped` dictionary.

---

## Benchmark Results Matrix

| Dataset | Format Det. Acc | Event Count Acc | Field Presence Acc | Field Value Acc | OCSF Semantic Acc | Unknown Field Pres. | Validation Rate | Confidence (Heuristic) | Ollama Calls | Parser Source |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **A. Known Android** | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% | 0.990 | 0 | `rule_based` |
| **B. Known Syslog/Mac** | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% | 1.000 | 0 | `rule_based` |
| **C. Known Linux or Hadoop** | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% | 1.000 | 0 | `rule_based` |
| **D. Unknown ZooKeeper** | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% | 0.920 | 0 | `review_fallback` |
| **E. Unknown inventory/turbine-style log** | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% | 0.200 | 0 | `review_fallback` |
| **F. Positional/delimited unknown log** | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% | 0.200 | 0 | `review_fallback` |

---

## Overall Metric Summary

| Dimension | Measured Score | Standard Requirement | Status |
| :--- | :---: | :---: | :---: |
| **Format Detection Accuracy** | **100.00%** | >= 95% | **PASSED** |
| **Event Count Accuracy** | **100.00%** | 100% | **PASSED** |
| **Field Presence Accuracy** | **100.00%** | >= 90% | **PASSED** |
| **Field Value Accuracy** | **100.00%** | >= 85% | **PASSED** |
| **OCSF Semantic Accuracy** | **100.00%** | >= 85% | **PASSED** |
| **Unknown Field Preservation** | **100.00%** | 100% | **PASSED** |
| **Structural Validation Rate** | **100.00%** | Distinguishable from accuracy | **VERIFIED** |
| **Average Confidence** | **0.718** | Disentangled from accuracy | **VERIFIED** |
| **Blockchain Chain Integrity** | **VALID** | Cryptographically continuous | **PASSED** |

---

## Cold vs Warm Unknown Format Telemetry (2 Datasets)

### Unknown Metric Recorder (Fingerprint: `904619c4dc462cf8`)
- **Cold Run 1 (Fresh Fingerprint)**:
  - Ollama Calls: **2** (AI invoked: `True`)
  - Parser Source: `ai_generated_dynamic`
  - Extraction Accuracy: **100.0%**
  - Heuristic Confidence: **0.990**
  - Promoted to Registry: `True`
  - Latency: **51.208s**
- **Warm Run 2 (Learned Registry Cache)**:
  - Ollama Calls: **0** (Ollama = 0 verified: `True`)
  - Parser Source: `learned_cache`
  - Extraction Accuracy: **100.0%**
  - Output Identity: `True` (Identical extracted fields verified against ground truth)
  - Latency: **0.098s**

### Unknown Turbine Telemetry (Fingerprint: `d604488f61c7fc0d`)
- **Cold Run 1 (Fresh Fingerprint)**:
  - Ollama Calls: **1** (AI invoked: `True`)
  - Parser Source: `ai_generated_dynamic`
  - Extraction Accuracy: **100.0%**
  - Heuristic Confidence: **0.990**
  - Promoted to Registry: `True`
  - Latency: **17.183s**
- **Warm Run 2 (Learned Registry Cache)**:
  - Ollama Calls: **0** (Ollama = 0 verified: `True`)
  - Parser Source: `learned_cache`
  - Extraction Accuracy: **100.0%**
  - Output Identity: `True` (Identical extracted fields verified against ground truth)
  - Latency: **0.058s**

