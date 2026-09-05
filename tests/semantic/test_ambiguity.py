"""
Semantic Verification: Ambiguity Handling & Anti-Hallucination.

Cases:
7. Ambiguous event (action=update status=SUCCESS)
- Must NOT be forced into System Activity or arbitrary OCSF class
- Returns classification_status = review
- Returns classification_reason = insufficient semantic evidence
"""

from __future__ import annotations

import pytest
from app.models.event_schema import UnifiedEvent
from app.normalization.engine import normalize_event
from app.normalization.semantic_classifier import classify_semantics


def test_ambiguous_action_update():
    """Case 7: Ambiguous event with action=update status=SUCCESS."""
    raw = "2026-09-05T12:04:00Z action=update status=SUCCESS"
    ev = normalize_event(UnifiedEvent(
        raw_event=raw,
        action="update",
        status="SUCCESS",
        message="action update status SUCCESS",
    ))

    # Strict Anti-Fabrication Requirement:
    # Must NOT be forced into System Activity or any other category!
    assert ev.category_name is None
    assert ev.category_uid is None
    assert ev.class_name is None
    assert ev.class_uid is None
    assert ev.classification_status == "review"
    assert ev.classification_confidence == 0.0
    assert ev.classification_reason == "insufficient_semantic_evidence"

    # Direct classifier test
    sem = classify_semantics({
        "raw_event": raw,
        "action": "update",
        "status": "SUCCESS",
    })
    assert sem["category_name"] is None
    assert sem["class_name"] is None
    assert sem["classification_status"] == "review"
    assert sem["classification_reason"] == "insufficient_semantic_evidence"
    assert sem["semantic_confidence"] == 0.0


def test_generic_event_activity_not_system_activity():
    """event=activity must not automatically become System Activity."""
    raw = "2026-09-05T12:04:30Z event=activity host=srv-1"
    ev = normalize_event(UnifiedEvent(
        raw_event=raw,
        src_hostname="srv-1",
        action="activity",
    ))

    assert ev.category_name is None
    assert ev.class_name is None
    assert ev.classification_status == "review"
    assert ev.classification_confidence == 0.0
    assert ev.classification_reason == "insufficient_semantic_evidence"
