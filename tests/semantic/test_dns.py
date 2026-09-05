"""
Semantic Verification: Network Activity (DNS Activity).

Cases:
4. DNS query with domain, query_type, resolver, port 53
"""

from __future__ import annotations

import pytest
from app.models.event_schema import UnifiedEvent
from app.normalization.engine import normalize_event


def test_dns_query_basic():
    """Case 4: DNS query."""
    raw = "2026-09-05T12:01:03Z src_ip=10.1.1.5 dst_ip=8.8.8.8 sport=53000 dport=53 protocol=DNS query=example.com query_type=A"
    ev = normalize_event(UnifiedEvent(
        raw_event=raw,
        src_ip="10.1.1.5",
        dst_ip="8.8.8.8",
        src_port=53000,
        dst_port=53,
        protocol="DNS",
        action="dns_query",
        unmapped={"query": "example.com", "query_type": "A"},
    ))

    assert ev.category_name == "Network Activity"
    assert ev.category_uid == 4
    assert ev.class_name == "DNS Activity"
    assert ev.class_uid == 4003
    assert ev.activity_name == "Query"
    assert ev.classification_status == "classified"
    assert ev.classification_confidence >= 0.95

    # Field-level preservation
    assert ev.src_ip == "10.1.1.5"
    assert ev.dst_ip == "8.8.8.8"
    assert ev.dst_port == 53
    assert ev.protocol == "DNS"
    assert ev.unmapped.get("query") == "example.com"
    assert ev.unmapped.get("query_type") == "A"
