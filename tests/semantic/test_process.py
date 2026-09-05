"""
Semantic Verification: System Activity (Process Activity).

Cases:
5. Process execution with host, user, executable, pid, command
"""

from __future__ import annotations

import pytest
from app.models.event_schema import UnifiedEvent
from app.normalization.engine import normalize_event


def test_process_execution_basic():
    """Case 5: Process execution."""
    raw = '2026-09-05T12:02:00Z host=NODE-1 user=alice process=python.exe pid=4421 command="python test.py"'
    ev = normalize_event(UnifiedEvent(
        raw_event=raw,
        user="alice",
        src_hostname="NODE-1",
        action="process_execution",
        message="process python.exe started",
        unmapped={"process": "python.exe", "pid": 4421, "command": "python test.py"},
    ))

    assert ev.category_name == "System Activity"
    assert ev.category_uid == 1
    assert ev.class_name == "Process Activity"
    assert ev.class_uid == 1007
    assert ev.activity_name == "Execute"
    assert ev.activity_id == 1
    assert ev.classification_status == "classified"
    assert ev.classification_confidence >= 0.95

    # Field-level preservation
    assert ev.user == "alice"
    assert ev.src_hostname == "NODE-1"
    assert ev.unmapped.get("process") == "python.exe"
    assert ev.unmapped.get("pid") == 4421
    assert ev.unmapped.get("command") == "python test.py"
