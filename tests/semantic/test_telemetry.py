"""
Semantic Verification: Sensor & Machine Telemetry Logs.

Cases:
8. Turbine telemetry and Factory Machine telemetry
- Must NOT be classified as Authentication or Network or forced into System Activity
- Preserves all unmapped sensor attributes
- Marks classification_status = review with reason = insufficient semantic evidence
"""

from __future__ import annotations

import pytest
from app.models.event_schema import UnifiedEvent
from app.normalization.engine import normalize_event
from app.normalization.semantic_classifier import classify_semantics


def test_turbine_telemetry_no_fabrication():
    """Case 8: Turbine telemetry must not fabricate OCSF class."""
    raw = "2026-09-05T11:31:02Z turbine=T-884 location=ZONE-A rpm=1840 vibration=0.031 condition=NORMAL"
    ev = normalize_event(UnifiedEvent(
        raw_event=raw,
        action=None,
        unmapped={
            "turbine": "T-884",
            "location": "ZONE-A",
            "rpm": 1840,
            "vibration": 0.031,
            "condition": "NORMAL",
        },
    ))

    # Anti-Fabrication:
    assert ev.category_name is None
    assert ev.category_uid is None
    assert ev.class_name is None
    assert ev.class_uid is None
    assert ev.classification_status == "review"
    assert ev.classification_confidence == 0.0
    assert ev.classification_reason == "insufficient_semantic_evidence"

    # Lossless preservation of telemetry attributes
    assert ev.unmapped.get("turbine") == "T-884"
    assert ev.unmapped.get("rpm") == 1840
    assert ev.unmapped.get("vibration") == 0.031
    assert ev.unmapped.get("condition") == "NORMAL"


def test_factory_machine_telemetry_no_fabrication():
    """Factory machine sensor readings must not fabricate OCSF class."""
    raw = "2026-09-05T12:30:11Z machine=M-771 plant=PUNE temp_c=84.6 pressure_kpa=112.4 vibration_mm=3.8 state=OVERHEAT"
    ev = normalize_event(UnifiedEvent(
        raw_event=raw,
        unmapped={
            "machine": "M-771",
            "plant": "PUNE",
            "temp_c": 84.6,
            "pressure_kpa": 112.4,
            "vibration_mm": 3.8,
            "state": "OVERHEAT",
        },
    ))

    assert ev.category_name is None
    assert ev.class_name is None
    assert ev.classification_status == "review"
    assert ev.classification_confidence == 0.0
    assert ev.classification_reason == "insufficient_semantic_evidence"

    # Preserved fields
    assert ev.unmapped.get("temp_c") == 84.6
    assert ev.unmapped.get("pressure_kpa") == 112.4
    assert ev.unmapped.get("state") == "OVERHEAT"
