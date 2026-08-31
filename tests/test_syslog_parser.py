"""
Unit tests for Syslog Parser and Enrichment in ULPF.
"""

from app.normalization.engine import normalize_event
from app.parsers.syslog_parser import parse_syslog_log


def test_syslog_auth_failure_ip_rhost():
    """Test standard Linux auth failure line with IP rhost."""
    raw = (
        "Jan 04 15:16:01 combo sshd(pam_unix)[24047]: "
        "authentication failure; logname= uid=0 euid=0 tty=NODEVssh ruser= rhost=218.188.2.4"
    )
    event = parse_syslog_log(raw)
    enriched = normalize_event(event)

    # 1. Timestamp matches raw log exactly (15:16:01, not shifted by +05:30)
    assert enriched.timestamp is not None
    assert enriched.timestamp.hour == 15
    assert enriched.timestamp.minute == 16
    assert enriched.timestamp.second == 1
    assert enriched.timestamp.month == 1
    assert enriched.timestamp.day == 4

    # 2. Message is populated
    assert enriched.message == "authentication failure; logname= uid=0 euid=0 tty=NODEVssh ruser= rhost=218.188.2.4"

    # 3. Local machine goes to log_name, NOT vendor or src_hostname
    assert enriched.log_name == "combo"
    assert enriched.src_hostname != "combo"
    assert enriched.vendor != "combo"

    # 4. src_ip extracted from rhost IP
    assert enriched.src_ip == "218.188.2.4"

    # 5. Enrichment sets correct vendor, category, severity
    assert enriched.vendor in ("OpenSSH", "OpenBSD", "Linux")
    assert enriched.category_name in ("Identity & Access Management", "authentication")
    assert enriched.severity in ("High", "high")


def test_syslog_user_unknown():
    """Test syslog line with check pass; user unknown."""
    raw = "Jan 04 15:16:01 combo sshd(pam_unix)[24047]: check pass; user unknown"
    event = parse_syslog_log(raw)
    enriched = normalize_event(event)

    # Timestamp
    assert enriched.timestamp is not None
    assert enriched.timestamp.hour == 15
    assert enriched.timestamp.minute == 16
    assert enriched.timestamp.second == 1

    # Message
    assert enriched.message == "check pass; user unknown"

    # User
    assert enriched.user == "unknown"

    # Vendor & log_name
    assert enriched.log_name == "combo"
    assert enriched.vendor != "combo"


def test_syslog_hostname_rhost_and_user_root():
    """Test line with user=root and hostname-style rhost."""
    raw = (
        "Jan 04 15:16:01 combo sshd(pam_unix)[24055]: "
        "authentication failure; logname= uid=0 euid=0 tty=NODEVssh ruser= rhost=220-135-151-1.hinet-ip.hinet.net  user=root"
    )
    event = parse_syslog_log(raw)
    enriched = normalize_event(event)

    # Timestamp
    assert enriched.timestamp is not None
    assert enriched.timestamp.hour == 15
    assert enriched.timestamp.minute == 16
    assert enriched.timestamp.second == 1

    # Message
    assert "authentication failure" in enriched.message

    # User
    assert enriched.user == "root"

    # Hostname-style rhost should populate src_endpoint_name / src_hostname, not src_ip
    assert enriched.src_ip is None
    assert enriched.src_endpoint_name == "220-135-151-1.hinet-ip.hinet.net"
    assert enriched.src_hostname == "220-135-151-1.hinet-ip.hinet.net"

    # Vendor is not hostname
    assert enriched.log_name == "combo"
    assert enriched.vendor != "combo"

