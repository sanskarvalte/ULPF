"""
Semantic Verification: Network Activity & SSH Session Handling.

Cases:
- SSH connection / session without authentication semantics -> SSH Activity (4007)
- General network traffic, firewall drops/permits -> Network Activity (4001)
- Do NOT classify all SSH logs identically
"""

from __future__ import annotations

import pytest
from app.models.event_schema import UnifiedEvent
from app.normalization.engine import normalize_event


def test_ssh_session_disconnect_not_iam():
    """SSH session disconnect without auth semantics must be Network Activity, not IAM."""
    raw = "2026-09-05T11:50:00Z client=192.168.10.51 server=10.0.0.8 sport=49287 dport=22 protocol=SSH action=ssh_disconnect message='ssh session closed'"
    ev = normalize_event(UnifiedEvent(
        raw_event=raw,
        src_ip="192.168.10.51",
        dst_ip="10.0.0.8",
        src_port=49287,
        dst_port=22,
        protocol="SSH",
        action="ssh_disconnect",
        message="ssh session closed",
    ))

    assert ev.category_name == "Network Activity"
    assert ev.category_uid == 4
    assert ev.class_name == "SSH Activity"
    assert ev.class_uid == 4007
    assert ev.activity_name == "Close"
    assert ev.classification_status == "classified"


def test_ssh_key_exchange_not_iam():
    """SSH key exchange must be SSH Activity, not IAM."""
    raw = "2026-09-05T11:40:00Z client=192.168.10.51 server=10.0.0.8 sport=49287 dport=22 protocol=SSH action=key_exchange message='kex algorithm negotiated'"
    ev = normalize_event(UnifiedEvent(
        raw_event=raw,
        src_ip="192.168.10.51",
        dst_ip="10.0.0.8",
        src_port=49287,
        dst_port=22,
        protocol="SSH",
        action="key_exchange",
    ))

    assert ev.category_name == "Network Activity"
    assert ev.class_name == "SSH Activity"
    assert ev.activity_name == "Open"
    assert ev.classification_status == "classified"


def test_firewall_packet_dropped():
    """Firewall drop must be Network Activity / Network Activity."""
    raw = "2026-09-05T11:55:00Z src_ip=192.168.1.10 dst_ip=10.0.0.1 sport=54321 dport=445 protocol=TCP action=packet_dropped message='packet_filtered by rule'"
    ev = normalize_event(UnifiedEvent(
        raw_event=raw,
        src_ip="192.168.1.10",
        dst_ip="10.0.0.1",
        src_port=54321,
        dst_port=445,
        protocol="TCP",
        action="packet_dropped",
    ))

    assert ev.category_name == "Network Activity"
    assert ev.class_name == "Network Activity"
    assert ev.activity_name == "Drop"
    assert ev.status == "Failure"
