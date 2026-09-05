"""
Verification for Semantic Accuracy Evaluator Metrics.

Ensures:
- parse_accuracy, field_accuracy, semantic_accuracy, validation_rate are computed accurately
- confidence is never conflated with accuracy
- classified_events, review_events, unknown_events, incorrect_events are counted
"""

from __future__ import annotations

import pytest
from app.evaluation.semantic_evaluator import (
    evaluate_batch_semantics,
    evaluate_event_semantics,
)
from app.models.event_schema import UnifiedEvent
from app.normalization.engine import normalize_event


def test_semantic_accuracy_metric_calculation():
    # Event 1: Correct Authentication
    ev1 = normalize_event(UnifiedEvent(
        raw_event="User alice logged in successfully",
        user="alice",
        action="login",
    ))
    exp1 = {
        "category_name": "Identity & Access Management",
        "class_name": "Authentication",
        "activity_name": "Logon",
        "classification_status": "classified",
    }

    # Event 2: Correct Ambiguity / Review Event
    ev2 = normalize_event(UnifiedEvent(
        raw_event="action=update status=SUCCESS",
        action="update",
        status="SUCCESS",
    ))
    exp2 = {
        "category_name": None,
        "class_name": None,
        "classification_status": "review",
    }

    # Event 3: Incorrectly expected class (Ground truth expects DNS, actual is SSH)
    ev3 = normalize_event(UnifiedEvent(
        raw_event="client 10.0.0.1 ssh key exchange",
        protocol="ssh",
        action="key_exchange",
    ))
    exp3 = {
        "category_name": "Network Activity",
        "class_name": "DNS Activity",  # Intentional discrepancy to test metric calculation
        "classification_status": "classified",
    }

    results = evaluate_batch_semantics([
        (ev1, exp1),
        (ev2, exp2),
        (ev3, exp3),
    ], total_raw_events=3)

    assert results["total_events"] == 3
    assert results["raw_events"] == 3
    assert results["parse_accuracy"] == 100.0
    # 2 out of 3 match ground truth semantics exactly
    assert results["semantic_accuracy"] == 66.67
    assert results["classified_events"] == 2
    assert results["review_events"] == 1
    assert results["unknown_events"] == 0
    assert results["incorrect_events"] == 1
    assert results["validation_rate"] == 100.0


def test_case_a_parse_high_semantic_low():
    """Case A: Parsing is 100% correct, but semantic classification differs from ground truth."""
    ev = normalize_event(UnifiedEvent(
        raw_event="Oct 11 22:15:00 myhost sshd[1234]: Accepted password for root from 192.168.1.50 port 22",
        user="root",
        src_ip="192.168.1.50",
        src_port=22,
        action="login",
        status="Success",
    ))
    # Ground truth deliberately expects DNS Activity
    exp = {
        "category_name": "Network Activity",
        "class_name": "DNS Activity",
        "activity_name": "Query",
    }
    results = evaluate_batch_semantics([(ev, exp)], total_raw_events=1)
    assert results["parse_accuracy"] == 100.0
    assert results["semantic_accuracy"] == 0.0
    assert results["incorrect_events"] == 1


def test_case_b_review_count_increases():
    """Case B: Event enters review (e.g. ambiguous action=update) without being marked incorrect."""
    ev = normalize_event(UnifiedEvent(
        raw_event="action=update status=SUCCESS",
        action="update",
        status="SUCCESS",
    ))
    exp = {
        "category_name": None,
        "class_name": None,
        "classification_status": "review",
    }
    results = evaluate_batch_semantics([(ev, exp)], total_raw_events=1)
    assert results["parse_accuracy"] == 100.0
    assert results["semantic_accuracy"] == 100.0
    assert results["review_events"] == 1
    assert results["incorrect_events"] == 0


def test_case_c_confidence_not_accuracy():
    """Case C: High internal confidence (0.99) does NOT dictate semantic accuracy against ground truth."""
    ev = normalize_event(UnifiedEvent(
        raw_event="Oct 11 22:15:00 myhost sshd[1234]: Accepted password for root from 192.168.1.50 port 22",
        user="root",
        src_ip="192.168.1.50",
        src_port=22,
        action="login",
        status="Success",
    ))
    assert ev.classification_confidence >= 0.95

    # Ground truth expects Security Finding
    exp = {
        "category_name": "Security Finding",
        "class_name": "Security Finding",
        "activity_name": "Alert",
    }
    results = evaluate_batch_semantics([(ev, exp)], total_raw_events=1)
    # Even though classifier confidence was 0.99, semantic accuracy must be 0.0%, NEVER 99%
    assert results["semantic_accuracy"] == 0.0
    assert results["semantic_accuracy"] != 99.0


def test_case_d_all_expected_labels_match():
    """Case D: Perfect match against all ground-truth semantic expectations."""
    ev = normalize_event(UnifiedEvent(
        raw_event="Oct 11 22:15:00 myhost sshd[1234]: Accepted password for root from 192.168.1.50 port 22",
        user="root",
        src_ip="192.168.1.50",
        src_port=22,
        action="login",
        status="Success",
    ))
    exp = {
        "category_name": "Identity & Access Management",
        "class_name": "Authentication",
        "activity_name": "Logon",
        "status": "Success",
    }
    results = evaluate_batch_semantics([(ev, exp)], total_raw_events=1)
    assert results["parse_accuracy"] == 100.0
    assert results["semantic_accuracy"] == 100.0
    assert results["incorrect_events"] == 0
    assert results["classified_events"] == 1
