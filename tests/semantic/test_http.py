"""
Semantic Verification: Network Activity (HTTP Activity).

Cases:
3. HTTP request with GET/POST, path, status, and field preservation
"""

from __future__ import annotations

import pytest
from app.models.event_schema import UnifiedEvent
from app.normalization.engine import normalize_event


def test_http_request_get_200():
    """Case 3: HTTP GET request with 200 OK."""
    raw = "2026-09-05T12:00:01Z src_ip=10.1.1.5 dst_ip=10.1.1.10 sport=53120 dport=80 protocol=HTTP method=GET path=/index.html status=200"
    ev = normalize_event(UnifiedEvent(
        raw_event=raw,
        src_ip="10.1.1.5",
        dst_ip="10.1.1.10",
        src_port=53120,
        dst_port=80,
        protocol="HTTP",
        action="GET",
        status="200",
        unmapped={"path": "/index.html", "user_agent": "curl/7.68.0"},
    ))

    assert ev.category_name == "Network Activity"
    assert ev.category_uid == 4
    assert ev.class_name == "HTTP Activity"
    assert ev.class_uid == 4002
    assert ev.activity_name == "GET"
    assert ev.status == "Success"
    assert ev.status_code == "200"
    assert ev.classification_status == "classified"
    assert ev.classification_confidence >= 0.95

    # Field-level semantic preservation
    assert ev.src_ip == "10.1.1.5"
    assert ev.dst_ip == "10.1.1.10"
    assert ev.src_port == 53120
    assert ev.dst_port == 80
    assert ev.protocol == "HTTP"
    assert ev.unmapped.get("path") == "/index.html"
    assert ev.unmapped.get("user_agent") == "curl/7.68.0"


def test_http_request_post_404():
    """HTTP POST request with 404 Failure status."""
    raw = "2026-09-05T12:00:15Z src_ip=10.1.1.8 dst_ip=10.1.1.10 sport=53125 dport=443 protocol=HTTPS method=POST path=/api/login status=404"
    ev = normalize_event(UnifiedEvent(
        raw_event=raw,
        src_ip="10.1.1.8",
        dst_ip="10.1.1.10",
        src_port=53125,
        dst_port=443,
        protocol="HTTPS",
        action="POST",
        status="404",
    ))

    assert ev.category_name == "Network Activity"
    assert ev.class_name == "HTTP Activity"
    assert ev.activity_name == "POST"
    assert ev.status == "Failure"
    assert ev.status_code == "404"
