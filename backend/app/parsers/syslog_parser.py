"""
Syslog log parser for ULPF.
Handles RFC 3164 and RFC 5424 syslog messages (including macOS / BSD system.log formats).
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any, Dict, Optional

from app.models.event_schema import UnifiedEvent
from app.normalization.engine import enrich_classification
from app.normalization.field_mapping import (
    COMMON_FIELD_MAP,
    coerce_bool,
    coerce_int,
)
from app.parsers.base import BaseParser

_FIELD_MAP: Dict[str, str] = {**COMMON_FIELD_MAP}

# Supports standard BSD/RFC3164 syslog, RFC5424 timestamps, and macOS parenthetical context
# e.g.: "Mon DD HH:MM:SS hostname process[pid] (extra_context): message"
_SYSLOG_RE = re.compile(
    r"^"
    r"(?:<(?P<priority>\d{1,3})>)?"
    r"(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<hostname>\S+)\s+"
    r"(?P<process>[^\[:]+?)"
    r"(?:\[(?P<pid>\d+)\])?"
    r"(?:\s*\((?P<context>[^)]*)\))?"
    r":\s*"
    r"(?P<message>.*)$",
    re.DOTALL,
)

_KV_RE = re.compile(
    r"""(?P<key>[a-zA-Z_]\w*)=(?P<val>"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|\S*)""",
)

_IPV4_RE = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
_IPV6_RE = re.compile(r"^[0-9a-fA-F:]+$")

_SSHD_FROM_RE = re.compile(
    r"\bfrom\s+(?P<host>[^\s:]+)(?:\s+port\s+(?P<port>\d+))?",
    re.IGNORECASE,
)

# Known auth daemon / subsystem processes for explicit auth parsing
_AUTH_PROCESS_NAMES = {
    "sshd",
    "sudo",
    "login",
    "su",
    "pam_unix",
    "authorizationhost",
    "securityd",
    "secd",
    "com.apple.securityserver",
}


def _parse_syslog_timestamp(
    ts: str,
    default_year: int | None = None,
    reference_date: datetime | None = None,
) -> tuple[datetime | None, bool]:
    """
    Parse BSD syslog timestamp ("Mmm DD HH:MM:SS").
    Returns (datetime, is_year_inferred).
    BSD syslog does not contain a year field; the year is inferred from
    default_year, reference_date, or the current calendar year.
    """
    if not ts:
        return None, False
    clean_ts = " ".join(ts.split())
    if default_year is not None:
        target_year = default_year
    elif reference_date is not None:
        target_year = reference_date.year
    else:
        target_year = datetime.now().year

    try:
        dt = datetime.strptime(clean_ts, "%b %d %H:%M:%S")
        return dt.replace(year=target_year), True
    except ValueError:
        return None, False


class SyslogParser(BaseParser):
    format_name = "syslog"

    def __init__(self, default_year: int | None = None, reference_date: datetime | None = None):
        self.default_year = default_year
        self.reference_date = reference_date

    def parse(self, raw: str, **kwargs) -> UnifiedEvent:
        default_year = kwargs.get("default_year", self.default_year)
        reference_date = kwargs.get("reference_date", self.reference_date)
        return parse_syslog_log(raw, default_year=default_year, reference_date=reference_date)


def parse_syslog_log(
    raw: str,
    default_year: int | None = None,
    reference_date: datetime | None = None,
) -> UnifiedEvent:
    mapped: Dict[str, Any] = {}
    unmapped: Dict[str, Any] = {}
    raw_stripped = raw.strip()

    m = _SYSLOG_RE.match(raw_stripped)
    if m:
        ts, year_inferred = _parse_syslog_timestamp(
            m.group("timestamp"),
            default_year=default_year,
            reference_date=reference_date,
        )
        if ts:
            mapped["timestamp"] = ts
            if year_inferred:
                unmapped["timestamp_year_inferred"] = True

        hostname = m.group("hostname")
        process = m.group("process")
        pid = m.group("pid")
        context = m.group("context")

        if hostname:
            mapped["log_name"] = hostname.strip()
        if process:
            mapped["product"] = process.strip()
        if pid:
            unmapped["pid"] = pid
        if context:
            unmapped["context"] = context.strip()

        raw_message = (m.group("message") or "").strip()
        mapped["message"] = raw_message

        # Extract explicit key-value pairs
        for kv_match in _KV_RE.finditer(raw_message):
            key = kv_match.group("key").lower()
            val = kv_match.group("val").strip("\"';,")
            if not val:
                continue

            if key == "rhost":
                if _IPV4_RE.match(val) or _IPV6_RE.match(val):
                    mapped["src_ip"] = val
                else:
                    mapped["src_endpoint_name"] = val
                    mapped["src_hostname"] = val
                continue

            if key in ("user", "ruser", "username"):
                if "user" not in mapped or key == "user":
                    mapped["user"] = val
                continue

            unified_key = _FIELD_MAP.get(key)
            if unified_key is None or unified_key in mapped:
                continue

            if unified_key == "severity_id":
                val = coerce_int(val)
                if val is None:
                    continue
            elif unified_key in ("src_port", "dst_port", "traffic_bytes", "traffic_packets"):
                val = coerce_int(val)
                if val is None:
                    continue
            elif unified_key in ("is_mfa", "is_remote"):
                val = coerce_bool(val)

            if val is not None:
                mapped[unified_key] = val

        # Network extraction for sshd / auth messages
        if "src_ip" not in mapped and "src_endpoint_name" not in mapped:
            from_match = _SSHD_FROM_RE.search(raw_message)
            if from_match:
                host_val = from_match.group("host")
                if _IPV4_RE.match(host_val) or _IPV6_RE.match(host_val):
                    mapped["src_ip"] = host_val
                else:
                    mapped["src_endpoint_name"] = host_val
                    mapped["src_hostname"] = host_val
                if from_match.group("port") and "src_port" not in mapped:
                    mapped["src_port"] = int(from_match.group("port"))

        # User extraction: ONLY for explicit user identity markers in auth-related daemons
        if "user" not in mapped:
            proc_clean = (process or "").split("(")[0].strip().lower()
            if proc_clean in _AUTH_PROCESS_NAMES or "sshd" in proc_clean:
                if re.search(r"\buser\s+unknown\b", raw_message, re.IGNORECASE):
                    mapped["user"] = "unknown"
                else:
                    # SSH auth patterns
                    auth_match = re.search(
                        r"\b(?:Failed|Accepted)\s+(?:password|publickey|none)\s+for\s+(?:invalid\s+user\s+)?(?P<user>[a-zA-Z0-9_\-\.\$]+)\s+from\b",
                        raw_message,
                        re.IGNORECASE,
                    )
                    if auth_match:
                        mapped["user"] = auth_match.group("user")
                    else:
                        inv_match = re.search(r"\bInvalid\s+user\s+(?P<user>[a-zA-Z0-9_\-\.\$]+)\s+from\b", raw_message, re.IGNORECASE)
                        if inv_match:
                            mapped["user"] = inv_match.group("user")
                        else:
                            sess_match = re.search(r"\bsession\s+opened\s+for\s+user\s+(?P<user>[a-zA-Z0-9_\-\.\$]+)\b", raw_message, re.IGNORECASE)
                            if sess_match:
                                mapped["user"] = sess_match.group("user")
                            else:
                                sudo_match = re.search(r"^\s*(?P<user>[a-zA-Z0-9_\-\.\$]+)\s*:\s+TTY=", raw_message)
                                if sudo_match:
                                    mapped["user"] = sudo_match.group("user")

    if unmapped:
        mapped["unmapped"] = unmapped

    enrich_classification(mapped)
    mapped["log_format"] = "syslog"
    mapped["raw_event"] = raw

    return UnifiedEvent(**mapped)

