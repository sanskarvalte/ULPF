"""
Diagnostic Tests for Real Normalized UnifiedEvent Objects (Phases 5 & 6).

Verifies:
1. SSH AUTH SUCCESS -> IAM / Authentication / Logon / Success
2. SSH AUTH FAILURE -> IAM / Authentication / Logon / Failure
3. SSH SESSION -> Network Activity / SSH Activity / Close (NOT IAM/Authentication)
4. HTTP REQUEST -> Network Activity / HTTP Activity / GET / Success
5. DNS QUERY -> Network Activity / DNS Activity / Query
6. PROCESS EXECUTION -> System Activity / Process Activity / Execute
7. SECURITY FINDING -> Security Finding / Security Finding / Alert
8. AMBIGUOUS EVENT -> Review status, NO arbitrary category/class fabrication
9. Field-level preservation (src/dst IP, ports, protocol, user, host, unmapped custom fields)
"""

from __future__ import annotations

import pytest
from app.models.event_schema import UnifiedEvent
from app.normalization.engine import normalize_event
from app.parsers.generic_parser import GenericParser


@pytest.fixture
def parser():
    return GenericParser()


def test_real_event_01_ssh_auth_success(parser):
    """Case 1: SSH Authentication Success."""
    raw = "2026-09-05T11:46:31Z client=192.168.10.51 server=10.0.0.8 sport=49287 dport=22 protocol=SSH result=ACCEPTED reason=VALID_CREDENTIALS"
    parsed = parser.parse(raw)
    norm = normalize_event(parsed)

    # OCSF Semantic Domain Verification
    assert norm.category_name == "Identity & Access Management"
    assert norm.category_uid == 3
    assert norm.class_name == "Authentication"
    assert norm.class_uid == 3002
    assert norm.activity_name == "Logon"
    assert norm.activity_id == 1
    assert norm.status == "Success"
    assert norm.status_id == 1
    assert norm.classification_status == "classified"
    assert norm.classification_confidence >= 0.95

    # Field-Level Source Preservation
    assert norm.src_ip == "192.168.10.51"
    assert norm.dst_ip == "10.0.0.8"
    assert norm.src_port == 49287
    assert norm.dst_port == 22
    assert norm.protocol == "SSH"
    assert norm.status_detail == "VALID_CREDENTIALS"
    assert norm.raw_event == raw


def test_real_event_02_ssh_auth_failure(parser):
    """Case 2: SSH Authentication Failure."""
    raw = "2026-09-05T11:45:12Z client=192.168.10.44 server=10.0.0.8 sport=49221 dport=22 protocol=SSH result=DENIED reason=INVALID_CREDENTIALS"
    parsed = parser.parse(raw)
    norm = normalize_event(parsed)

    # OCSF Semantic Domain Verification
    assert norm.category_name == "Identity & Access Management"
    assert norm.category_uid == 3
    assert norm.class_name == "Authentication"
    assert norm.class_uid == 3002
    assert norm.activity_name == "Logon"
    assert norm.activity_id == 1
    assert norm.status == "Failure"
    assert norm.status_id == 2
    assert norm.classification_status == "classified"

    # Field-Level Source Preservation
    assert norm.src_ip == "192.168.10.44"
    assert norm.dst_ip == "10.0.0.8"
    assert norm.src_port == 49221
    assert norm.dst_port == 22
    assert norm.protocol == "SSH"
    assert norm.status_detail == "INVALID_CREDENTIALS"


def test_real_event_03_ssh_session_disconnect(parser):
    """Case 3: SSH Session Disconnect (Must be Network Activity, NOT Authentication)."""
    raw = "protocol=SSH action=disconnect status=SUCCESS"
    parsed = parser.parse(raw)
    norm = normalize_event(parsed)

    assert norm.category_name == "Network Activity"
    assert norm.category_uid == 4
    assert norm.class_name == "SSH Activity"
    assert norm.class_uid == 4007
    assert norm.activity_name == "Close"
    assert norm.activity_id == 2
    assert norm.status == "Success"
    assert norm.classification_status == "classified"


def test_real_event_04_http_request(parser):
    """Case 4: HTTP Request."""
    raw = "src_ip=10.1.1.5 dst_ip=10.1.1.10 sport=53120 dport=80 protocol=HTTP method=GET path=/index.html status=200"
    parsed = parser.parse(raw)
    norm = normalize_event(parsed)

    # OCSF Semantic Domain Verification
    assert norm.category_name == "Network Activity"
    assert norm.category_uid == 4
    assert norm.class_name == "HTTP Activity"
    assert norm.class_uid == 4002
    assert norm.activity_name == "GET"
    assert norm.activity_id == 1
    assert norm.status == "Success"
    assert norm.status_id == 1
    assert norm.classification_status == "classified"

    # Field-Level Source Preservation
    assert norm.src_ip == "10.1.1.5"
    assert norm.dst_ip == "10.1.1.10"
    assert norm.src_port == 53120
    assert norm.dst_port == 80
    assert norm.protocol == "HTTP"
    assert norm.unmapped is not None
    assert norm.unmapped.get("path") == "/index.html"


def test_real_event_05_dns_query(parser):
    """Case 5: DNS Query."""
    raw = "src_ip=10.1.1.5 dst_ip=8.8.8.8 sport=53000 dport=53 protocol=DNS query=example.com query_type=A"
    parsed = parser.parse(raw)
    norm = normalize_event(parsed)

    # OCSF Semantic Domain Verification
    assert norm.category_name == "Network Activity"
    assert norm.category_uid == 4
    assert norm.class_name == "DNS Activity"
    assert norm.class_uid == 4003
    assert norm.activity_name == "Query"
    assert norm.activity_id == 1
    assert norm.classification_status == "classified"

    # Field-Level Source Preservation
    assert norm.src_ip == "10.1.1.5"
    assert norm.dst_ip == "8.8.8.8"
    assert norm.src_port == 53000
    assert norm.dst_port == 53
    assert norm.protocol == "DNS"
    assert norm.unmapped is not None
    assert norm.unmapped.get("query") == "example.com"
    assert norm.unmapped.get("query_type") == "A"


def test_real_event_06_process_execution(parser):
    """Case 6: Process Execution."""
    raw = 'host=NODE-1 user=alice process=python.exe pid=4421 command="python test.py"'
    parsed = parser.parse(raw)
    norm = normalize_event(parsed)

    # OCSF Semantic Domain Verification
    assert norm.category_name == "System Activity"
    assert norm.category_uid == 1
    assert norm.class_name == "Process Activity"
    assert norm.class_uid == 1007
    assert norm.activity_name == "Execute"
    assert norm.activity_id == 1
    assert norm.classification_status == "classified"

    # Field-Level Source Preservation
    assert norm.src_hostname == "NODE-1"
    assert norm.user == "alice"
    assert norm.unmapped is not None
    assert norm.unmapped.get("process") == "python.exe"
    assert norm.unmapped.get("pid") == "4421"
    assert norm.unmapped.get("command") == "python test.py"


def test_real_event_07_security_finding(parser):
    """Case 7: Security Finding."""
    raw = "host=FW-1 finding=malware_detected severity=HIGH indicator=bad.example"
    parsed = parser.parse(raw)
    norm = normalize_event(parsed)

    # OCSF Semantic Domain Verification
    assert norm.category_name == "Security Finding"
    assert norm.category_uid == 2
    assert norm.class_name == "Security Finding"
    assert norm.class_uid == 2001
    assert norm.activity_name in ("Alert", "Deny")
    assert norm.severity == "High"
    assert norm.severity_id == 4
    assert norm.classification_status == "classified"

    # Field-Level Source Preservation
    assert norm.src_hostname == "FW-1"
    assert norm.unmapped is not None
    assert norm.unmapped.get("finding") == "malware_detected"
    assert norm.unmapped.get("indicator") == "bad.example"


def test_real_event_08_ambiguous_event(parser):
    """Case 8: Ambiguous Event (action=update status=SUCCESS)."""
    raw = "action=update status=SUCCESS"
    parsed = parser.parse(raw)
    norm = normalize_event(parsed)

    # Anti-Fabrication Requirement:
    # Must NOT be forced into System Activity or any other category!
    assert norm.category_name is None
    assert norm.category_uid is None
    assert norm.class_name is None
    assert norm.class_uid is None
    assert norm.classification_status == "review"
    assert norm.classification_reason == "insufficient_semantic_evidence"
    assert norm.classification_confidence == 0.0
