"""
Semantic Verification: Security Finding.

Cases:
6. Security finding with threat indicator, severity, malware detection
"""

from __future__ import annotations

import pytest
from app.models.event_schema import UnifiedEvent
from app.normalization.engine import normalize_event


def test_security_finding_malware():
    """Case 6: Security finding."""
    raw = "2026-09-05T12:03:00Z host=FW-1 finding=malware_detected severity=HIGH indicator=bad.example"
    ev = normalize_event(UnifiedEvent(
        raw_event=raw,
        src_hostname="FW-1",
        action="threat_detected",
        severity="HIGH",
        unmapped={"finding": "malware_detected", "indicator": "bad.example"},
    ))

    assert ev.category_name == "Security Finding"
    assert ev.category_uid == 2
    assert ev.class_name == "Security Finding"
    assert ev.class_uid == 2001
    assert ev.severity == "High"
    assert ev.severity_id == 4
    assert ev.classification_status == "classified"
    assert ev.classification_confidence >= 0.95

    # Field-level preservation
    assert ev.src_hostname == "FW-1"
    assert ev.unmapped.get("finding") == "malware_detected"
    assert ev.unmapped.get("indicator") == "bad.example"
