"""
Semantic Verification: Identity & Access Management (Authentication).

Cases:
1. Successful SSH authentication
2. Failed SSH authentication
3. Field preservation for SSH auth
"""

from __future__ import annotations

import pytest
from app.models.event_schema import UnifiedEvent
from app.normalization.engine import normalize_event
from app.normalization.semantic_classifier import classify_semantics


def test_ssh_auth_success():
    """Case 1: Successful SSH authentication."""
    raw = "2026-09-05T11:46:31Z client=192.168.10.51 server=10.0.0.8 sport=49287 dport=22 protocol=SSH result=ACCEPTED reason=VALID_CREDENTIALS"
    ev = normalize_event(UnifiedEvent(
        raw_event=raw,
        src_ip="192.168.10.51",
        dst_ip="10.0.0.8",
        src_port=49287,
        dst_port=22,
        protocol="SSH",
        status="ACCEPTED",
        status_detail="VALID_CREDENTIALS",
        action="login",
    ))

    assert ev.category_name == "Identity & Access Management"
    assert ev.category_uid == 3
    assert ev.class_name == "Authentication"
    assert ev.class_uid == 3002
    assert ev.activity_name == "Logon"
    assert ev.status == "Success"
    assert ev.classification_status == "classified"
    assert ev.classification_confidence >= 0.95

    # Field-level preservation
    assert ev.src_ip == "192.168.10.51"
    assert ev.dst_ip == "10.0.0.8"
    assert ev.src_port == 49287
    assert ev.dst_port == 22
    assert ev.protocol == "SSH"
    assert ev.raw_event == raw


def test_ssh_auth_failure():
    """Case 2: Failed SSH authentication."""
    raw = "2026-09-05T11:45:12Z client=192.168.10.44 server=10.0.0.8 sport=49221 dport=22 protocol=SSH result=DENIED reason=INVALID_CREDENTIALS"
    ev = normalize_event(UnifiedEvent(
        raw_event=raw,
        src_ip="192.168.10.44",
        dst_ip="10.0.0.8",
        src_port=49221,
        dst_port=22,
        protocol="SSH",
        status="DENIED",
        status_detail="INVALID_CREDENTIALS",
        action="login_failed",
    ))

    assert ev.category_name == "Identity & Access Management"
    assert ev.category_uid == 3
    assert ev.class_name == "Authentication"
    assert ev.class_uid == 3002
    assert ev.activity_name == "Logon"
    assert ev.status == "Failure"
    assert ev.severity == "High"
    assert ev.classification_status == "classified"
    assert ev.classification_confidence >= 0.95

    # Field-level preservation
    assert ev.src_ip == "192.168.10.44"
    assert ev.dst_ip == "10.0.0.8"
    assert ev.src_port == 49221
    assert ev.dst_port == 22
    assert ev.protocol == "SSH"
