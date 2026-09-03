"""
Validation and data-integrity verification module for ULPF.
Validates extracted log attributes against strict OCSF and cybersecurity schemas:
- IP addresses (valid IPv4 / IPv6 addresses using standard ipaddress library)
- Port numbers (valid TCP/UDP range: 1..65535)
- Timestamps (valid ISO UTC datetimes)
- Severity (strict OCSF severity scale without fabricated defaults)
- Status (strict OCSF status scale: Success, Failure, Other, Unknown)
"""

from __future__ import annotations

import ipaddress
import re
from datetime import datetime, timezone
from typing import Any, Optional, Tuple

# OCSF Canonical Severity Scale
# 0: Unknown, 1: Informational, 2: Low, 3: Medium, 4: High, 5: Critical, 6: Fatal
OCSF_SEVERITY_MAP: dict[str, tuple[str, int]] = {
    "informational": ("Informational", 1),
    "info": ("Informational", 1),
    "debug": ("Informational", 1),
    "trace": ("Informational", 1),
    "notice": ("Informational", 1),
    "low": ("Low", 2),
    "medium": ("Medium", 3),
    "med": ("Medium", 3),
    "warn": ("Medium", 3),
    "warning": ("Medium", 3),
    "high": ("High", 4),
    "err": ("High", 4),
    "error": ("High", 4),
    "alert": ("High", 4),
    "critical": ("Critical", 5),
    "crit": ("Critical", 5),
    "fatal": ("Fatal", 6),
    "emerg": ("Fatal", 6),
    "emergency": ("Fatal", 6),
}

# OCSF Numeric ID to (Name, ID)
OCSF_SEVERITY_BY_ID: dict[int, tuple[str, int]] = {
    0: ("Unknown", 0),
    1: ("Informational", 1),
    2: ("Low", 2),
    3: ("Medium", 3),
    4: ("High", 4),
    5: ("Critical", 5),
    6: ("Fatal", 6),
}

# OCSF Canonical Status Scale
# 1: Success, 2: Failure, 99: Other, 0: Unknown
OCSF_STATUS_MAP: dict[str, tuple[str, int]] = {
    "success": ("Success", 1),
    "successful": ("Success", 1),
    "passed": ("Success", 1),
    "allow": ("Success", 1),
    "allowed": ("Success", 1),
    "permit": ("Success", 1),
    "permitted": ("Success", 1),
    "accept": ("Success", 1),
    "accepted": ("Success", 1),
    "ok": ("Success", 1),
    "failure": ("Failure", 2),
    "failed": ("Failure", 2),
    "fail": ("Failure", 2),
    "denied": ("Failure", 2),
    "deny": ("Failure", 2),
    "block": ("Failure", 2),
    "blocked": ("Failure", 2),
    "drop": ("Failure", 2),
    "dropped": ("Failure", 2),
    "reject": ("Failure", 2),
    "rejected": ("Failure", 2),
    "error": ("Failure", 2),
    "timeout": ("Failure", 2),
    "other": ("Other", 99),
}

OCSF_STATUS_BY_ID: dict[int, tuple[str, int]] = {
    0: ("Unknown", 0),
    1: ("Success", 1),
    2: ("Failure", 2),
    99: ("Other", 99),
}


def validate_ip(value: Optional[Any]) -> Optional[str]:
    """
    Validate that an IP string is a valid IPv4 or IPv6 address.
    Rejects malformed strings, ports appended with colons, or arbitrary numbers.
    """
    if value is None:
        return None
    val_str = str(value).strip().strip("\"'[]")
    if not val_str:
        return None

    # Handle IP:Port notation if passed as a single string (extract just the IP)
    if ":" in val_str and "." in val_str:
        # e.g., "192.168.1.1:8080"
        parts = val_str.rsplit(":", 1)
        if len(parts) == 2 and parts[1].isdigit():
            val_str = parts[0]

    try:
        ip = ipaddress.ip_address(val_str)
        return str(ip)
    except ValueError:
        return None


def validate_port(value: Optional[Any]) -> Optional[int]:
    """
    Validate that a port is an integer in the valid TCP/UDP range: 1..65535.
    Returns None for 0 or out-of-bounds numbers.
    """
    if value is None:
        return None
    try:
        if isinstance(value, str):
            value = value.strip().strip("\"'")
        p = int(value)
        if 1 <= p <= 65535:
            return p
        return None
    except (ValueError, TypeError):
        return None


def validate_timestamp(value: Optional[Any]) -> Optional[datetime]:
    """
    Ensure the timestamp is a valid datetime instance in UTC.
    Accepts datetime objects or parseable ISO/syslog timestamp strings.
    """
    if value is None:
        return None
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)
    if isinstance(value, (str, int, float)):
        from app.normalization.field_mapping import parse_timestamp
        return parse_timestamp(value)
    return None


def validate_severity(
    severity: Optional[str] = None,
    severity_id: Optional[int] = None,
) -> Tuple[Optional[str], Optional[int]]:
    """
    Validate and canonicalize severity against OCSF standard.
    Never invents default 'Informational' if neither was provided.
    """
    if severity_id is not None:
        try:
            sid = int(severity_id)
            if sid in OCSF_SEVERITY_BY_ID:
                return OCSF_SEVERITY_BY_ID[sid]
        except (ValueError, TypeError):
            pass

    if severity is not None and isinstance(severity, str):
        sev_clean = severity.strip().lower()
        if sev_clean in OCSF_SEVERITY_MAP:
            return OCSF_SEVERITY_MAP[sev_clean]
        # Check if it was a numeric string
        if sev_clean.isdigit():
            sid = int(sev_clean)
            if sid in OCSF_SEVERITY_BY_ID:
                return OCSF_SEVERITY_BY_ID[sid]

    return None, None


def validate_status(
    status: Optional[str] = None,
    status_id: Optional[int] = None,
) -> Tuple[Optional[str], Optional[int]]:
    """
    Validate and canonicalize status against OCSF standard.
    Never invents default status if neither was provided.
    """
    if status_id is not None:
        try:
            sid = int(status_id)
            if sid in OCSF_STATUS_BY_ID:
                return OCSF_STATUS_BY_ID[sid]
        except (ValueError, TypeError):
            pass

    if status is not None and isinstance(status, str):
        st_clean = status.strip().lower()
        if st_clean in OCSF_STATUS_MAP:
            return OCSF_STATUS_MAP[st_clean]
        if st_clean.isdigit():
            sid = int(st_clean)
            if sid in OCSF_STATUS_BY_ID:
                return OCSF_STATUS_BY_ID[sid]

    return None, None


# Deterministic Severity Keywords Patterns (Minimum Severity Floors)
SEVERITY_KEYWORDS_PATTERNS: list[tuple[re.Pattern, str, int]] = [
    (re.compile(r"\b(?:FATAL|PANIC|EMERGENCY|EMERG)\b", re.IGNORECASE), "Fatal", 6),
    (re.compile(r"\b(?:CRITICAL|CRIT|ALERT)\b", re.IGNORECASE), "Critical", 5),
    (re.compile(r"\b(?:ERROR|ERR|FAIL|FAILED|EXCEPTION)\b", re.IGNORECASE), "High", 4),
    (re.compile(r"\b(?:WARN|WARNING)\b", re.IGNORECASE), "Medium", 3),
]


def get_severity_keyword_floor(raw_text: str) -> Tuple[Optional[str], Optional[int]]:
    """
    Deterministically scan raw text for explicit severity keywords.
    Returns (canonical_name, severity_id) representing the minimum severity floor.
    Ensures that clear error/failure indicators are never downgraded to Informational.
    """
    if not raw_text:
        return None, None
    for pattern, name, sid in SEVERITY_KEYWORDS_PATTERNS:
        if pattern.search(raw_text):
            return name, sid
    return None, None
