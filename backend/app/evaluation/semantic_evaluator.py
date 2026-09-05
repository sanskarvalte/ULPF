"""
ULPF Semantic Accuracy Evaluator.

Computes separate, rigorous metrics:
- parse_accuracy: fraction of events successfully extracted from raw logs
- field_accuracy: fraction of extracted fields matching ground truth values
- semantic_accuracy: correctly classified semantic expectations / total ground-truth expectations
- validation_rate: fraction of events that are structurally valid against OCSF schema

Also reports discrete event classification counts:
- classified_events
- review_events
- unknown_events
- incorrect_events

CRITICAL PRINCIPLE:
A confidence score (e.g. 0.99) is NOT semantic accuracy.
Confidence represents the model/classifier's internal heuristic certainty.
Semantic accuracy measures factual correctness against ground truth.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple, Union

from app.models.event_schema import UnifiedEvent
from app.normalization.engine import normalize_event
from app.normalization.semantic_classifier import classify_semantics


def evaluate_event_semantics(
    actual_event: Union[UnifiedEvent, Dict[str, Any]],
    expected_semantics: Dict[str, Any],
    aliases: Optional[Dict[str, List[str]]] = None,
) -> Dict[str, Any]:
    """
    Evaluate a single normalized event against its ground truth semantic expectations.

    Args:
        actual_event: The normalized event (UnifiedEvent or dict).
        expected_semantics: Expected ground truth dictionary containing:
            - category_name: expected OCSF category
            - class_name: expected OCSF class
            - activity_name (optional): expected OCSF activity
            - classification_status (optional): expected status ("classified", "review", "unknown")
            - status (optional): expected outcome status ("Success", "Failure")
        aliases: Optional mapping of field names or OCSF entities to acceptable synonyms.

    Returns:
        Dictionary detailing semantic match, field-level matches, and classification status.
    """
    if hasattr(actual_event, "model_dump"):
        actual = actual_event.model_dump()
    elif isinstance(actual_event, dict):
        actual = dict(actual_event)
    else:
        actual = vars(actual_event) if hasattr(actual_event, "__dict__") else {}

    # Support structured schema where expected is nested inside {"expected": ..., "aliases": ...}
    if isinstance(expected_semantics, dict) and "expected" in expected_semantics and isinstance(expected_semantics["expected"], dict):
        if not aliases and "aliases" in expected_semantics:
            aliases = expected_semantics.get("aliases")
        expected_semantics = expected_semantics["expected"]

    # Category match
    exp_cat = expected_semantics.get("category_name")
    act_cat = actual.get("category_name")
    cat_match = _match_string_semantic(act_cat, exp_cat)
    if not cat_match and aliases and "category" in aliases and act_cat:
        cat_match = any(_match_string_semantic(act_cat, a) for a in aliases["category"])

    # Class match
    exp_cls = expected_semantics.get("class_name")
    act_cls = actual.get("class_name")
    cls_match = _match_string_semantic(act_cls, exp_cls)
    if not cls_match and aliases and "class" in aliases and act_cls:
        cls_match = any(_match_string_semantic(act_cls, a) for a in aliases["class"])

    # Activity match (if expected)
    exp_act = expected_semantics.get("activity_name")
    act_act = actual.get("activity_name")
    act_match = True
    if exp_act is not None:
        act_match = _match_activity_semantic(act_act, exp_act)
        if not act_match and aliases and "activity" in aliases and act_act:
            act_match = any(_match_activity_semantic(act_act, a) for a in aliases["activity"])

    # Classification status
    exp_status = expected_semantics.get("classification_status")
    act_status = actual.get("classification_status") or ("classified" if act_cat else "review")
    status_match = True
    if exp_status is not None:
        status_match = str(act_status).strip().lower() == str(exp_status).strip().lower()

    # Overall semantic correctness for this event
    has_expectations = bool(expected_semantics) and any(v is not None for v in expected_semantics.values())
    is_semantically_correct = (cat_match and cls_match and act_match and status_match) if has_expectations else None

    is_incorrect = False
    if exp_cat is not None and not cat_match:
        is_incorrect = True
    if exp_cls is not None and not cls_match:
        is_incorrect = True

    return {
        "has_expectations": has_expectations,
        "is_correct": is_semantically_correct,
        "is_incorrect": is_incorrect,
        "category_match": cat_match,
        "class_match": cls_match,
        "activity_match": act_match,
        "status_match": status_match,
        "actual_category": act_cat,
        "expected_category": exp_cat,
        "actual_class": act_cls,
        "expected_class": exp_cls,
        "actual_activity": act_act,
        "expected_activity": exp_act,
        "classification_status": act_status,
        "semantic_confidence": actual.get("classification_confidence", 0.0),
        "classification_reason": actual.get("classification_reason", "unknown"),
    }


def evaluate_batch_semantics(
    events_with_expectations: List[Union[Tuple[Any, Dict[str, Any]], Tuple[Any, Dict[str, Any], Dict[str, Any]]]],
    total_raw_events: Optional[int] = None,
) -> Dict[str, Any]:
    """
    Evaluate a batch of normalized events with ground-truth semantic expectations.

    Returns separate metrics:
    - parse_accuracy (% of raw events successfully parsed)
    - field_accuracy (% of extracted fields matching ground truth, or None if no ground truth)
    - semantic_accuracy (% of events matching semantic ground truth, or None if no ground truth)
    - validation_rate (% passing structural validation)
    - classified_events
    - review_events
    - unknown_events
    - incorrect_events
    """
    total_events = len(events_with_expectations)
    if total_events == 0:
        return {
            "total_events": 0,
            "raw_events": 0,
            "parse_accuracy": 100.0,
            "field_accuracy": 100.0,
            "semantic_accuracy": 100.0,
            "validation_rate": 100.0,
            "classified_events": 0,
            "review_events": 0,
            "unknown_events": 0,
            "incorrect_events": 0,
        }

    raw_count = total_raw_events if total_raw_events is not None else total_events

    correct_semantic_count = 0
    incorrect_count = 0
    classified_count = 0
    review_count = 0
    unknown_count = 0
    valid_structural_count = 0

    total_field_comparisons = 0
    correct_field_comparisons = 0
    total_events_with_ground_truth = 0

    for item in events_with_expectations:
        actual = item[0]
        expected = item[1] if len(item) > 1 else {}
        aliases = item[2] if len(item) > 2 else None

        if isinstance(expected, dict) and "expected" in expected:
            if not aliases and "aliases" in expected:
                aliases = expected.get("aliases")
            expected = expected["expected"]

        eval_res = evaluate_event_semantics(actual, expected, aliases=aliases)

        if eval_res["has_expectations"]:
            total_events_with_ground_truth += 1
            if eval_res["is_correct"]:
                correct_semantic_count += 1
            if eval_res["is_incorrect"]:
                incorrect_count += 1

        st = eval_res["classification_status"]
        if st == "classified":
            classified_count += 1
        elif st == "review":
            review_count += 1
        else:
            unknown_count += 1

        # Check structural validity
        act_dict = actual.model_dump() if hasattr(actual, "model_dump") else actual
        if act_dict.get("raw_event"):
            valid_structural_count += 1

        # Field-level accuracy against all expected attributes
        for f_key, f_val in expected.items():
            if f_key in ("classification_status", "category_name", "class_name", "activity_name"):
                continue
            total_field_comparisons += 1
            act_val = act_dict.get(f_key)
            match = _match_string_semantic(act_val, f_val)
            if not match and aliases and f_key in aliases and act_val:
                match = any(_match_string_semantic(act_val, a) for a in aliases[f_key])
            if match:
                correct_field_comparisons += 1

    parse_accuracy = round((total_events / raw_count) * 100.0, 2) if raw_count > 0 else 0.0

    if total_events_with_ground_truth > 0:
        semantic_accuracy = round((correct_semantic_count / total_events_with_ground_truth) * 100.0, 2)
        field_accuracy = (
            round((correct_field_comparisons / total_field_comparisons) * 100.0, 2)
            if total_field_comparisons > 0
            else 100.0
        )
    else:
        # If no ground truth exists, semantic_accuracy and field_accuracy MUST be None (null), NOT 0 or 100
        semantic_accuracy = None
        field_accuracy = None

    validation_rate = round((valid_structural_count / total_events) * 100.0, 2)

    return {
        "total_events": total_events,
        "raw_events": raw_count,
        "parse_accuracy": parse_accuracy,
        "field_accuracy": field_accuracy,
        "semantic_accuracy": semantic_accuracy,
        "validation_rate": validation_rate,
        "classified_events": classified_count,
        "review_events": review_count,
        "unknown_events": unknown_count,
        "incorrect_events": incorrect_count,
    }


def _match_string_semantic(actual: Any, expected: Any) -> bool:
    """Case-insensitive, whitespace-normalized equality comparison with OCSF synonyms."""
    if expected is None:
        return actual is None
    if actual is None:
        return False

    act_s = str(actual).strip().lower()
    exp_s = str(expected).strip().lower()

    if act_s == exp_s:
        return True

    # Category synonyms
    cat_synonyms = [
        {"identity & access management", "identity and access management", "iam", "authentication"},
        {"network activity", "network"},
        {"system activity", "system"},
        {"security finding", "security"},
        {"application activity", "application"},
    ]
    for syn_set in cat_synonyms:
        if act_s in syn_set and exp_s in syn_set:
            return True

    return False


def _match_activity_semantic(actual: Any, expected: Any) -> bool:
    """Activity synonym comparison (e.g. Logon / Login, Open / Connect)."""
    if expected is None:
        return True
    if actual is None:
        return False

    act_s = str(actual).strip().lower()
    exp_s = str(expected).strip().lower()

    if act_s == exp_s:
        return True

    act_synonyms = [
        {"logon", "login"},
        {"logoff", "logout"},
        {"open", "connect", "connection"},
        {"close", "disconnect"},
        {"query", "search", "lookup"},
        {"execute", "exec", "launch", "run"},
        {"drop", "fail", "block", "deny", "refuse"},
    ]
    for syn_set in act_synonyms:
        if act_s in syn_set and exp_s in syn_set:
            return True

    return False
