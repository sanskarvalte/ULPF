"""
ULPF AI Parser Accuracy Engine.

Calculates multi-metric accuracy gate metrics:
1. exact_field_match: Percentage of fields matching expected values exactly.
2. normalized_field_match: Percentage matching after semantic normalization (timestamps, numeric equivalence).
3. event_level_match: Percentage of events where 100% of fields match.
4. field_coverage: Percentage of expected fields successfully extracted.
5. unknown_field_preservation: Preservation of unmapped custom attributes without data loss.
6. parse_success: Percentage of samples that parsed without unhandled exceptions.

Enforces accuracy gate: target = 100% for ground-truth samples.
Failing fields are isolated for targeted automatic repair or rejection.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from app.ai.dynamic_parser import parse_with_spec
from app.normalization.field_mapping import COMMON_FIELD_MAP


def _normalize_value(value: Any) -> str:
    """Convert extracted values into comparable strings."""
    if value is None:
        return ""

    if hasattr(value, "isoformat"):
        return value.isoformat()

    return str(value).strip()


def _is_numeric_equal(val1: str, val2: str) -> bool:
    """Check if two string representations represent the exact same numeric value."""
    try:
        f1, f2 = float(val1), float(val2)
        return abs(f1 - f2) < 1e-6
    except (ValueError, TypeError):
        return False


def _is_timestamp_equal(val1: str, val2: str) -> bool:
    """Check if two timestamp strings represent the same point in time or prefix match."""
    if not val1 or not val2:
        return False
    # Clean ISO markers
    c1 = val1.replace("T", " ").replace("Z", "").strip()
    c2 = val2.replace("T", " ").replace("Z", "").strip()
    if c1 == c2:
        return True
    if len(c1) >= 10 and len(c2) >= 10:
        if c1.startswith(c2) or c2.startswith(c1):
            return True
from app.normalization.taxonomy import ACTIVITY_MAP


def _is_semantic_equal(val1: str, val2: str) -> bool:
    """Check if two strings represent semantically normalized equivalents (e.g. login <-> Logon)."""
    if not val1 or not val2:
        return False
    v1_low, v2_low = val1.strip().lower(), val2.strip().lower()
    if v1_low == v2_low:
        return True
    if v1_low in ACTIVITY_MAP and ACTIVITY_MAP[v1_low][0].lower() == v2_low:
        return True
    if v2_low in ACTIVITY_MAP and ACTIVITY_MAP[v2_low][0].lower() == v1_low:
        return True
    return False


def _extract_expected_fields(
    expected: Dict[str, Any],
) -> Dict[str, str]:
    """Normalize expected field values."""
    return {
        str(key).strip().lower(): _normalize_value(value)
        for key, value in expected.items()
    }


def _get_extracted_value(
    field_name: str,
    extracted: Dict[str, Any],
) -> Any:
    """
    Find an extracted field using its original parser name,
    ULPF canonical name, and unmapped dictionary.
    """
    normalized_name = field_name.strip().lower()

    # 1. Direct field match
    if normalized_name in extracted and extracted[normalized_name] is not None:
        return extracted[normalized_name]

    # 2. ULPF common field mapping
    unified_name = COMMON_FIELD_MAP.get(normalized_name)
    if unified_name and unified_name in extracted and extracted[unified_name] is not None:
        return extracted[unified_name]

    # 2b. Fallback between action and activity_name
    if normalized_name in ("action", "act", "event_action") and extracted.get("activity_name") is not None:
        return extracted["activity_name"]
    if normalized_name in ("activity_name", "activity") and extracted.get("action") is not None:
        return extracted["action"]

    # 3. Check unmapped fields
    unmapped = extracted.get("unmapped")
    if isinstance(unmapped, dict):
        if normalized_name in unmapped and unmapped[normalized_name] is not None:
            return unmapped[normalized_name]
        # Case-insensitive search in unmapped
        for k, v in unmapped.items():
            if k.lower() == normalized_name and v is not None:
                return v

    return None


def check_sample_accuracy(
    raw_log: str,
    parser_spec: Dict[str, Any],
    expected: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Parse one sample and compare extracted fields with expected values across all metrics.
    """
    expected_fields = _extract_expected_fields(expected)

    try:
        event = parse_with_spec(raw_log, parser_spec)
        parse_succeeded = True
        parse_error = None
    except Exception as exc:
        return {
            "success": False,
            "parse_success": False,
            "exact_matches": 0,
            "normalized_matches": 0,
            "covered_fields": 0,
            "total_fields": len(expected_fields),
            "unmapped_preserved_count": 0,
            "expected_unmapped_count": 0,
            "mismatches": [
                {"field": k, "expected": v, "extracted": "", "reason": f"parse_exception: {exc}"}
                for k, v in expected_fields.items()
            ],
            "error": str(exc),
        }

    extracted = event.model_dump()
    if event.unmapped:
        extracted.update(event.unmapped)

    exact_matches = 0
    normalized_matches = 0
    covered_fields = 0
    mismatches: List[Dict[str, Any]] = []

    for field_name, expected_value in expected_fields.items():
        raw_extracted = _get_extracted_value(field_name, extracted)
        extracted_value = _normalize_value(raw_extracted)

        if extracted_value:
            covered_fields += 1

        # Check exact equality
        if extracted_value == expected_value:
            exact_matches += 1
            normalized_matches += 1
        # Check normalized equivalence (numeric, timestamp, case-insensitive)
        elif _is_numeric_equal(extracted_value, expected_value):
            normalized_matches += 1
        elif _is_timestamp_equal(extracted_value, expected_value):
            normalized_matches += 1
        elif _is_semantic_equal(extracted_value, expected_value):
            normalized_matches += 1
        else:
            mismatches.append(
                {
                    "field": field_name,
                    "expected": expected_value,
                    "extracted": extracted_value,
                    "reason": "value_mismatch" if extracted_value else "field_missing",
                }
            )

    # Check unmapped field preservation
    expected_unmapped_keys = [
        k for k in expected_fields.keys()
        if k not in COMMON_FIELD_MAP and k not in extracted
    ]
    unmapped_dict = event.unmapped or {}
    unmapped_preserved = sum(
        1 for k in expected_unmapped_keys
        if any(uk.lower() == k for uk in unmapped_dict.keys())
    )

    total = len(expected_fields)
    event_passed = (normalized_matches == total) if total > 0 else True

    return {
        "success": event_passed,
        "parse_success": parse_succeeded,
        "event_passed": event_passed,
        "exact_matches": exact_matches,
        "normalized_matches": normalized_matches,
        "covered_fields": covered_fields,
        "total_fields": total,
        "unmapped_preserved_count": unmapped_preserved,
        "expected_unmapped_count": len(expected_unmapped_keys),
        "mismatches": mismatches,
        "error": parse_error,
    }


def evaluate_parser_accuracy(
    samples: List[Dict[str, Any]],
    parser_spec: Dict[str, Any],
    accuracy_threshold: float = 100.0,
) -> Dict[str, Any]:
    """
    Evaluate a parser specification against multiple labelled samples across all 6 accuracy metrics.
    
    Returns structured results:
    - exact_field_match (%)
    - normalized_field_match (%)
    - event_level_match (%)
    - field_coverage (%)
    - unknown_field_preservation (%)
    - parse_success (%)
    - accuracy (%) -> primary gate metric
    - passed_gate (bool) -> True if accuracy >= accuracy_threshold
    - failing_fields -> list of failing field descriptions for targeted repair
    """
    if not samples:
        return {
            "success": False,
            "passed_gate": False,
            "accuracy": 0.0,
            "exact_field_match": 0.0,
            "normalized_field_match": 0.0,
            "event_level_match": 0.0,
            "field_coverage": 0.0,
            "unknown_field_preservation": 100.0,
            "parse_success": 0.0,
            "samples_tested": 0,
            "samples_passed": 0,
            "sample_results": [],
            "failing_fields": [],
            "error": "No samples supplied for accuracy evaluation.",
        }

    sample_results: List[Dict[str, Any]] = []
    total_exact = 0
    total_normalized = 0
    total_covered = 0
    total_fields = 0
    total_parsed_success = 0
    total_events_passed = 0
    total_unmapped_preserved = 0
    total_unmapped_expected = 0
    failing_fields: List[Dict[str, Any]] = []

    for index, sample in enumerate(samples, start=1):
        raw_log = sample.get("raw", "")
        expected = sample.get("expected", {})

        result = check_sample_accuracy(
            raw_log=raw_log,
            parser_spec=parser_spec,
            expected=expected,
        )

        result["sample_number"] = index
        sample_results.append(result)

        if result.get("parse_success"):
            total_parsed_success += 1
        if result.get("event_passed"):
            total_events_passed += 1

        total_exact += result.get("exact_matches", 0)
        total_normalized += result.get("normalized_matches", 0)
        total_covered += result.get("covered_fields", 0)
        total_fields += result.get("total_fields", 0)
        total_unmapped_preserved += result.get("unmapped_preserved_count", 0)
        total_unmapped_expected += result.get("expected_unmapped_count", 0)

        for mismatch in result.get("mismatches", []):
            failing_fields.append({
                "sample_number": index,
                "field": mismatch.get("field"),
                "expected": mismatch.get("expected"),
                "extracted": mismatch.get("extracted"),
                "reason": mismatch.get("reason"),
            })

    total_samples = len(samples)

    exact_pct = round((total_exact / total_fields) * 100, 2) if total_fields else 100.0
    normalized_pct = round((total_normalized / total_fields) * 100, 2) if total_fields else 100.0
    event_pct = round((total_events_passed / total_samples) * 100, 2) if total_samples else 100.0
    coverage_pct = round((total_covered / total_fields) * 100, 2) if total_fields else 100.0
    parse_success_pct = round((total_parsed_success / total_samples) * 100, 2) if total_samples else 0.0
    unmapped_pct = (
        round((total_unmapped_preserved / total_unmapped_expected) * 100, 2)
        if total_unmapped_expected
        else 100.0
    )

    # Primary accuracy is normalized_field_match; for strict ground truth target=100 requires 100% event match
    accuracy = normalized_pct
    passed_gate = (accuracy >= accuracy_threshold) and (event_pct >= accuracy_threshold if accuracy_threshold == 100.0 else True)

    return {
        "success": passed_gate,
        "passed_gate": passed_gate,
        "accuracy": accuracy,
        "exact_field_match": exact_pct,
        "normalized_field_match": normalized_pct,
        "event_level_match": event_pct,
        "field_coverage": coverage_pct,
        "unknown_field_preservation": unmapped_pct,
        "parse_success": parse_success_pct,
        "samples_tested": total_samples,
        "samples_passed": total_events_passed,
        "field_matches": total_normalized,
        "field_total": total_fields,
        "failing_fields": failing_fields,
        "sample_results": sample_results,
        "error": None if passed_gate else f"Accuracy {accuracy}% is below target threshold {accuracy_threshold}%.",
    }
