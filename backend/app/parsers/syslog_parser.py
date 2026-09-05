"""
Syslog log parser for ULPF.
Handles RFC 3164, RFC 5424, and Vendor-Specific Syslog Formats
(Fortinet FortiOS, Cisco ASA, pfSense filterlog, Linux system/auth/sshd/sudo logs).
Integrates dynamic YAML mappings without hardcoding rigid logic.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from app.mapping.engine import apply_custom_mapping, find_matching_vendor_mapping
from app.models.event_schema import UnifiedEvent
from app.normalization.engine import enrich_classification
from app.normalization.field_mapping import (
    COMMON_FIELD_MAP,
    coerce_bool,
    coerce_int,
    parse_timestamp,
)
from app.parsers.base import BaseParser

_FIELD_MAP: Dict[str, str] = {**COMMON_FIELD_MAP}

# Supports BSD RFC3164 syslog, RFC5424 timestamps, and process[pid] markers
_SYSLOG_RE = re.compile(
    r"^"
    r"(?:<(?P<priority>\d{1,3})>\s*)?"
    r"(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}(?:\s+\d{4})?\s+\d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+"
    r"(?P<hostname>\S+)\s+"
    r"(?P<process>[^\[:]+?)"
    r"(?:\[(?P<pid>\d+)\])?"
    r"(?:\s*\((?P<context>[^)]*)\))?"
    r":\s*"
    r"(?P<message>.*)$",
    re.DOTALL,
)

_RFC5424_RE = re.compile(
    r"^<(?P<priority>\d{1,3})>(?P<version>\d+)\s+"
    r"(?P<timestamp>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+"
    r"(?P<hostname>\S+)\s+"
    r"(?P<process>[^\[:\s]+)\s+"
    r"(?P<pid>\S+)\s+"
    r"(?P<msgid>\S+)\s+"
    r"(?:\[(?P<structured_data>.*?)\]\s*)?"
    r"(?P<message>.*)$",
    re.DOTALL,
)

_KV_RE = re.compile(
    r"""([a-zA-Z_][a-zA-Z0-9_\-\.]*)=("(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|[^\s,;()]+)""",
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
    Parse BSD or RFC5424 syslog timestamp.
    Returns (datetime, is_year_inferred).
    """
    if not ts:
        return None, False
    clean_ts = " ".join(ts.split())
    if default_year is not None:
        target_year = default_year
    elif reference_date is not None:
        target_year = reference_date.year
    else:
        target_year = datetime.now(timezone.utc).year

    # Try ISO timestamp
    if "-" in clean_ts:
        parsed_iso = parse_timestamp(clean_ts)
        if parsed_iso:
            return parsed_iso, False

    try:
        parts = clean_ts.split()
        if len(parts) == 4:
            dt = datetime.strptime(clean_ts, "%b %d %Y %H:%M:%S")
            return dt.replace(tzinfo=timezone.utc), False
        dt = datetime.strptime(clean_ts, "%b %d %H:%M:%S")
        return dt.replace(year=target_year, tzinfo=timezone.utc), True
    except ValueError:
        return None, False


_CISCO_SEV_MAP = {
    1: ("Critical", 5),
    2: ("Critical", 5),
    3: ("High", 4),
    4: ("Medium", 3),
    5: ("Informational", 1),
    6: ("Informational", 1),
    7: ("Informational", 1),
}


def _is_valid_ip(addr: str) -> bool:
    """Check if string is a valid IPv4 or IPv6 address."""
    if not addr:
        return False
    # IPv4 check
    if _IPV4_RE.match(addr):
        parts = addr.split(".")
        try:
            return all(0 <= int(p) <= 255 for p in parts)
        except ValueError:
            return False
    # IPv6 check (e.g. fe80::2205:baff:fe9d:f637, ::1)
    if ":" in addr:
        clean = addr.replace("::", ":")
        parts = clean.split(":")
        if all(bool(re.match(r"^[0-9a-fA-F]{0,4}$", p)) for p in parts):
            return True
    return False


def _assign_endpoint_fields(mapped: Dict[str, Any], ep_str: Optional[str], port_val: Optional[Any], is_src: bool) -> None:
    """Assign source or destination endpoint as IP (if valid IPv4/IPv6) or Hostname, plus port."""
    if not ep_str:
        return
    clean_ep = ep_str.strip().strip("()")
    port_int = None
    if port_val is not None:
        try:
            port_int = int(str(port_val).strip())
        except (ValueError, TypeError):
            pass

    if _is_valid_ip(clean_ep):
        if is_src:
            mapped["src_ip"] = clean_ep
            if port_int is not None:
                mapped["src_port"] = port_int
        else:
            mapped["dst_ip"] = clean_ep
            if port_int is not None:
                mapped["dst_port"] = port_int
    else:
        # Endpoint is a hostname (e.g. OCSP_Server, identity, webserver1)
        if is_src:
            mapped["src_hostname"] = clean_ep
            if port_int is not None:
                mapped["src_port"] = port_int
        else:
            mapped["dst_hostname"] = clean_ep
            if port_int is not None:
                mapped["dst_port"] = port_int


def _parse_cisco_asa(
    raw_text: str,
    default_year: int | None = None,
    reference_date: datetime | None = None,
) -> Optional[Dict[str, Any]]:
    """
    Parse Cisco ASA syslog (%ASA-level-id: message or %ASA-session-level-id: message).
    Extracts timestamps (with/without TZ, hostnames, PRI), event code, severity,
    and message-specific fields across all ASA event types.
    """
    asa_m = re.search(r"%ASA-(?:session-)?(?P<level>\d)-(?P<tag>\d{6})(?::|\s)\s*(?P<msg>.*)", raw_text, re.DOTALL)
    if not asa_m:
        return None

    level = int(asa_m.group("level"))
    tag = asa_m.group("tag")
    body = asa_m.group("msg").strip()

    sev_label, sev_id = _CISCO_SEV_MAP.get(level, ("Informational", 1))

    mapped: Dict[str, Any] = {
        "vendor": "Cisco",
        "product": "ASA",
        "category_name": "Network Activity",
        "category_uid": 4,
        "class_name": "Network Activity",
        "class_uid": 4001,
        "severity": sev_label,
        "severity_id": sev_id,
        "status_code": f"%ASA-{level}-{tag}",
        "message": body,
    }
    unmapped: Dict[str, Any] = {}

    # Extract Timestamp from prefix preceding %ASA-
    prefix = raw_text[:asa_m.start()].strip()
    if prefix:
        # Remove leading <PRI> if present (e.g. <13>)
        if prefix.startswith("<") and ">" in prefix[:6]:
            close_idx = prefix.find(">")
            prefix = prefix[close_idx + 1:].strip()

        # Match timestamp patterns in prefix (supports Apr 15 2013 09:36:50:, Apr 15 2014 09:34:34 EDT:, etc.)
        ts_m = re.search(r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?:(?P<year>\d{4})\s+)?(?P<time>\d{2}:\d{2}:\d{2})", prefix)
        if ts_m:
            month = ts_m.group("month")
            day = int(ts_m.group("day"))
            time_str = ts_m.group("time")
            year_str = ts_m.group("year")
            if year_str:
                yr = int(year_str)
                is_inferred = False
            elif default_year is not None:
                yr = default_year
                is_inferred = True
            elif reference_date is not None:
                yr = reference_date.year
                is_inferred = True
            else:
                yr = datetime.now(timezone.utc).year
                is_inferred = True

            try:
                dt_str = f"{month} {day:02d} {yr} {time_str}"
                dt = datetime.strptime(dt_str, "%b %d %Y %H:%M:%S").replace(tzinfo=timezone.utc)
                mapped["timestamp"] = dt
                if is_inferred:
                    unmapped["timestamp_year_inferred"] = True
            except ValueError:
                pass
        else:
            parsed_iso = parse_timestamp(prefix)
            if parsed_iso:
                mapped["timestamp"] = parsed_iso

    # 1. Access-list permitted / denied / est-allowed (Event 106100)
    acl_m = re.search(
        r"access-list\s+(?P<acl>\S+)\s+(?P<action>permitted|denied|est-allowed)\s+(?P<proto>\S+)\s+(?:(?P<src_zone>[^/]+)/)?(?P<src_ep>[^\s(]+)(?:\((?P<src_port>\d+)\))?\s*(?:->|-&gt;)\s*(?:(?P<dst_zone>[^/]+)/)?(?P<dst_ep>[^\s(]+)(?:\((?P<dst_port>\d+)\))?",
        body,
        re.IGNORECASE,
    )
    if acl_m:
        act = acl_m.group("action").lower()
        if act in ("permitted", "est-allowed"):
            mapped["activity_name"] = "Permit"
            mapped["status"] = "Success"
            mapped["status_id"] = 1
        else:
            mapped["activity_name"] = "Deny"
            mapped["status"] = "Failure"
            mapped["status_id"] = 2
        mapped["protocol"] = acl_m.group("proto").lower()
        _assign_endpoint_fields(mapped, acl_m.group("src_ep"), acl_m.group("src_port"), is_src=True)
        _assign_endpoint_fields(mapped, acl_m.group("dst_ep"), acl_m.group("dst_port"), is_src=False)
        unmapped["acl_name"] = acl_m.group("acl")
        if acl_m.group("src_zone"):
            unmapped["src_zone"] = acl_m.group("src_zone")
        if acl_m.group("dst_zone"):
            unmapped["dst_zone"] = acl_m.group("dst_zone")

    # 2. Built / Teardown dynamic translation (Event 305011 / 305012)
    elif re.search(r"\b(?:Built|Teardown)\s+dynamic\b", body, re.IGNORECASE):
        trans_m = re.search(
            r"(?P<action>Built|Teardown)\s+dynamic\s+(?P<proto>\S+)\s+translation\s+from\s+(?:(?P<src_zone>[^:]+):)?(?P<src_ep>[^/:\s]+)/(?P<src_port>\d+)\s+to\s+(?:(?P<dst_zone>[^:]+):)?(?P<dst_ep>[^/:\s]+)/(?P<dst_port>\d+)",
            body,
            re.IGNORECASE,
        )
        if trans_m:
            act = trans_m.group("action").capitalize()
            mapped["activity_name"] = "Translate" if act == "Built" else "Teardown"
            mapped["status"] = "Success"
            mapped["status_id"] = 1
            mapped["protocol"] = trans_m.group("proto").lower()
            _assign_endpoint_fields(mapped, trans_m.group("src_ep"), trans_m.group("src_port"), is_src=True)
            _assign_endpoint_fields(mapped, trans_m.group("dst_ep"), trans_m.group("dst_port"), is_src=False)
            if trans_m.group("src_zone"):
                unmapped["src_zone"] = trans_m.group("src_zone")
            if trans_m.group("dst_zone"):
                unmapped["dst_zone"] = trans_m.group("dst_zone")

    # 3. Built connection (Event 302013 / 302015 / 302020)
    elif re.search(r"^Built\s+(?:outbound|inbound)?\s*(?:TCP|UDP|ICMP|IP)\s+connection", body, re.IGNORECASE):
        conn_m = re.search(
            r"Built\s+(?P<dir>outbound|inbound)?\s*(?P<proto>\S+)\s+connection\s+(?P<conn_id>\d+)\s+for\s+(?:(?P<src_zone>[^:]+):)?(?P<src_ep>[^/:\s]+)/(?P<src_port>\d+)(?:\s*\([^)]*\))?\s+to\s+(?:(?P<dst_zone>[^:]+):)?(?P<dst_ep>[^/:\s]+)/(?P<dst_port>\d+)",
            body,
            re.IGNORECASE,
        )
        if conn_m:
            mapped["activity_name"] = "Logon"
            mapped["status"] = "Success"
            mapped["status_id"] = 1
            mapped["protocol"] = conn_m.group("proto").lower()
            _assign_endpoint_fields(mapped, conn_m.group("src_ep"), conn_m.group("src_port"), is_src=True)
            _assign_endpoint_fields(mapped, conn_m.group("dst_ep"), conn_m.group("dst_port"), is_src=False)
            unmapped["connection_id"] = conn_m.group("conn_id")
            if conn_m.group("src_zone"):
                unmapped["src_zone"] = conn_m.group("src_zone")
            if conn_m.group("dst_zone"):
                unmapped["dst_zone"] = conn_m.group("dst_zone")

    # 4. Teardown connection (Event 302014 / 302016 / 302021)
    elif re.search(r"^Teardown\s+(?:TCP|UDP|ICMP|IP)\s+connection", body, re.IGNORECASE):
        td_m = re.search(
            r"Teardown\s+(?P<proto>\S+)\s+connection\s+(?P<conn_id>\d+)\s+for\s+(?:(?P<src_zone>[^:]+):)?(?P<src_ep>[^/:\s]+)/(?P<src_port>\d+)\s+to\s+(?:(?P<dst_zone>[^:]+):)?(?P<dst_ep>[^/:\s]+)/(?P<dst_port>\d+)",
            body,
            re.IGNORECASE,
        )
        if td_m:
            mapped["activity_name"] = "Teardown"
            mapped["status"] = "Success"
            mapped["status_id"] = 1
            mapped["protocol"] = td_m.group("proto").lower()
            _assign_endpoint_fields(mapped, td_m.group("src_ep"), td_m.group("src_port"), is_src=True)
            _assign_endpoint_fields(mapped, td_m.group("dst_ep"), td_m.group("dst_port"), is_src=False)
            unmapped["connection_id"] = td_m.group("conn_id")
            if td_m.group("src_zone"):
                unmapped["src_zone"] = td_m.group("src_zone")
            if td_m.group("dst_zone"):
                unmapped["dst_zone"] = td_m.group("dst_zone")

        bytes_m = re.search(r"\bbytes\s+(?P<bytes>\d+)\b", body, re.IGNORECASE)
        if bytes_m:
            mapped["traffic_bytes"] = int(bytes_m.group("bytes"))

        dur_m = re.search(r"\bduration\s+(?P<dur>[^\s]+)\b", body, re.IGNORECASE)
        if dur_m:
            unmapped["duration"] = dur_m.group("dur")

    # 5. Deny inbound/outbound UDP/TCP (Event 106006 / 106007)
    elif re.search(r"^Deny\s+(?:inbound|outbound)\b", body, re.IGNORECASE):
        deny_in_m = re.search(
            r"Deny\s+(?:inbound|outbound)?\s*(?P<proto>\S+)\s+from\s+(?P<src_ep>[^/:\s]+)/(?P<src_port>\d+)\s+to\s+(?P<dst_ep>[^/:\s]+)/(?P<dst_port>\d+)",
            body,
            re.IGNORECASE,
        )
        if deny_in_m:
            mapped["activity_name"] = "Deny"
            mapped["status"] = "Failure"
            mapped["status_id"] = 2
            mapped["protocol"] = deny_in_m.group("proto").lower()
            _assign_endpoint_fields(mapped, deny_in_m.group("src_ep"), deny_in_m.group("src_port"), is_src=True)
            _assign_endpoint_fields(mapped, deny_in_m.group("dst_ep"), deny_in_m.group("dst_port"), is_src=False)

    # 6. Deny IP spoof (Event 106016)
    elif re.search(r"\bDeny\s+IP\s+spoof\b", body, re.IGNORECASE):
        spoof_m = re.search(
            r"Deny\s+IP\s+spoof\s+from\s+\(?(?P<src_ep>[^\s\)]+)\)?\s+to\s+(?P<dst_ep>[^\s]+)(?:\s+on\s+interface\s+(?P<intf>\S+))?",
            body,
            re.IGNORECASE,
        )
        if spoof_m:
            mapped["activity_name"] = "Deny"
            mapped["status"] = "Failure"
            mapped["status_id"] = 2
            _assign_endpoint_fields(mapped, spoof_m.group("dst_ep"), None, is_src=False)
            src_ep = spoof_m.group("src_ep")
            if src_ep and src_ep not in ("0.0.0.0", "unknown", "(0.0.0.0)"):
                _assign_endpoint_fields(mapped, src_ep, None, is_src=True)
            if spoof_m.group("intf"):
                unmapped["interface"] = spoof_m.group("intf")

    # 7. Deny proto src ... dst ... by access-group (Event 106023)
    elif re.search(r"\bDeny\s+(?:tcp|udp|icmp|ip)\s+src\b", body, re.IGNORECASE):
        deny_m = re.search(
            r"Deny\s+(?P<proto>tcp|udp|icmp|ip)\s+src\s+(?:(?P<src_zone>[^:]+):)?(?P<src_ep>[^/:\s]+)(?:/(?P<src_port>\d+))?\s+dst\s+(?:(?P<dst_zone>[^:]+):)?(?P<dst_ep>[^/:\s]+)(?:/(?P<dst_port>\d+))?",
            body,
            re.IGNORECASE,
        )
        if deny_m:
            mapped["activity_name"] = "Deny"
            mapped["status"] = "Failure"
            mapped["status_id"] = 2
            mapped["protocol"] = deny_m.group("proto").lower()
            _assign_endpoint_fields(mapped, deny_m.group("src_ep"), deny_m.group("src_port"), is_src=True)
            _assign_endpoint_fields(mapped, deny_m.group("dst_ep"), deny_m.group("dst_port"), is_src=False)
            if deny_m.group("src_zone"):
                unmapped["src_zone"] = deny_m.group("src_zone")
            if deny_m.group("dst_zone"):
                unmapped["dst_zone"] = deny_m.group("dst_zone")

    # Generic Fallback: If endpoints not yet mapped, check for standard src ... dst patterns
    if "src_ip" not in mapped and "src_hostname" not in mapped:
        src_m = re.search(r"\bsrc\s+(?:[a-zA-Z0-9_\-]+:)?(?P<ep>[^/:\s]+)(?:/(?P<port>\d+))?", body)
        if src_m:
            _assign_endpoint_fields(mapped, src_m.group("ep"), src_m.group("port"), is_src=True)

    if "dst_ip" not in mapped and "dst_hostname" not in mapped:
        dst_m = re.search(r"\bdst\s+(?:[a-zA-Z0-9_\-]+:)?(?P<ep>[^/:\s]+)(?:/(?P<port>\d+))?", body)
        if dst_m:
            _assign_endpoint_fields(mapped, dst_m.group("ep"), dst_m.group("port"), is_src=False)

    # Check for faddr / gaddr / laddr fallback
    if "src_ip" not in mapped and "src_hostname" not in mapped:
        faddr_m = re.search(r"faddr\s+(?P<ep>[^/:\s]+)/(?P<port>\d+)", body)
        if faddr_m:
            _assign_endpoint_fields(mapped, faddr_m.group("ep"), faddr_m.group("port"), is_src=True)
    if "dst_ip" not in mapped and "dst_hostname" not in mapped:
        gaddr_m = re.search(r"gaddr\s+(?P<ep>[^/:\s]+)/(?P<port>\d+)", body)
        if gaddr_m:
            _assign_endpoint_fields(mapped, gaddr_m.group("ep"), gaddr_m.group("port"), is_src=False)

    # General Action and Protocol Fallbacks if not set
    if "activity_name" not in mapped:
        if re.search(r"\b(?:Deny|denied|blocked|drop|dropped)\b", body, re.IGNORECASE):
            mapped["activity_name"] = "Deny"
            mapped["status"] = "Failure"
            mapped["status_id"] = 2
        elif re.search(r"\b(?:Permit|permitted|built|allowed|accept)\b", body, re.IGNORECASE):
            mapped["activity_name"] = "Permit"
            mapped["status"] = "Success"
            mapped["status_id"] = 1
        elif re.search(r"\bTeardown\b", body, re.IGNORECASE):
            mapped["activity_name"] = "Teardown"
            mapped["status"] = "Success"
            mapped["status_id"] = 1

    if "protocol" not in mapped:
        proto_m = re.search(r"\b(tcp|udp|icmp|ip)\b", body, re.IGNORECASE)
        if proto_m:
            mapped["protocol"] = proto_m.group(1).lower()

    # Extract User if present
    user_m = re.search(r"\buser\s+([a-zA-Z0-9_\-\.\$]+)", body, re.IGNORECASE)
    if user_m:
        mapped["user"] = user_m.group(1)

    if unmapped:
        mapped["unmapped"] = unmapped

    return mapped


def _parse_pfsense_filterlog(raw_text: str) -> Optional[Dict[str, Any]]:
    """Parse pfSense filterlog CSV output."""
    idx = raw_text.find("filterlog:")
    if idx == -1:
        return None
    csv_payload = raw_text[idx + len("filterlog:"):].strip()
    fields = [f.strip() for f in csv_payload.split(",")]
    if len(fields) < 15:
        return None

    # pfSense filterlog fields:
    # 0: rule_number, 1: sub_rule, 2: anchor, 3: tracker, 4: interface, 5: reason, 6: action, 7: direction, 8: ip_version
    # for IPv4 (ip_version=4):
    # 9: tos, 10: ecn, 11: ttl, 12: id, 13: offset, 14: flags, 15: proto_id, 16: proto, 17: length, 18: src_ip, 19: dst_ip, 20: src_port, 21: dst_port
    mapped: Dict[str, Any] = {
        "vendor": "pfSense",
        "product": "Filterlog",
        "category_name": "Network Activity",
        "class_name": "Network Activity",
        "message": raw_text.strip(),
    }

    if len(fields) > 4:
        mapped["src_endpoint_name"] = fields[4]
    if len(fields) > 6:
        act = fields[6].lower()
        mapped["activity_name"] = act.capitalize()
        mapped["status"] = "Success" if act in ("pass", "permit", "allow") else "Failure"
        mapped["status_id"] = 1 if act in ("pass", "permit", "allow") else 2

    # Check for IP fields
    for i, field_val in enumerate(fields):
        if _IPV4_RE.match(field_val) and "src_ip" not in mapped:
            mapped["src_ip"] = field_val
            if i + 1 < len(fields) and _IPV4_RE.match(fields[i + 1]):
                mapped["dst_ip"] = fields[i + 1]
            if i + 2 < len(fields) and fields[i + 2].isdigit():
                mapped["src_port"] = int(fields[i + 2])
            if i + 3 < len(fields) and fields[i + 3].isdigit():
                mapped["dst_port"] = int(fields[i + 3])
            break

    return mapped


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

    # 1. Check Cisco ASA Pattern
    cisco_mapped = _parse_cisco_asa(raw_stripped, default_year=default_year, reference_date=reference_date)
    if cisco_mapped:
        mapped.update(cisco_mapped)

    # 2. Check pfSense Filterlog Pattern
    if not mapped and "filterlog:" in raw_stripped:
        pfsense_mapped = _parse_pfsense_filterlog(raw_stripped)
        if pfsense_mapped:
            mapped.update(pfsense_mapped)

    # 3. Standard Syslog Header Regex (BSD or RFC 5424)
    m = _SYSLOG_RE.match(raw_stripped) or _RFC5424_RE.match(raw_stripped)
    raw_message = ""
    if m:
        ts, year_inferred = _parse_syslog_timestamp(
            m.group("timestamp"),
            default_year=default_year,
            reference_date=reference_date,
        )
        if ts and "timestamp" not in mapped:
            mapped["timestamp"] = ts
            if year_inferred:
                unmapped["timestamp_year_inferred"] = True

        hostname = m.group("hostname")
        process = m.group("process")
        pid = m.group("pid")
        context = m.groupdict().get("context")
        sd = m.groupdict().get("structured_data")

        if hostname and "log_name" not in mapped:
            mapped["log_name"] = hostname.strip()
        if process and "product" not in mapped:
            mapped["product"] = process.strip()
        if pid:
            unmapped["pid"] = pid
        if context:
            unmapped["context"] = context.strip()
        if sd:
            unmapped["structured_data"] = sd.strip()

        raw_message = (m.group("message") or "").strip()
        if "message" not in mapped:
            mapped["message"] = raw_message
    else:
        raw_message = raw_stripped
        if "message" not in mapped:
            mapped["message"] = raw_stripped

    # 4. Check Dynamic YAML Mapping
    vendor_match = find_matching_vendor_mapping(raw_stripped)
    if vendor_match:
        mapping_name, mapping_def = vendor_match
        mapped.setdefault("vendor", mapping_def.get("vendor"))
        mapped.setdefault("product", mapping_def.get("product"))
        if mapping_def.get("category") and "category_name" not in mapped:
            mapped["category_name"] = mapping_def["category"]

    # 5. Extract Key-Value Pairs from Syslog message (e.g. Fortinet, Linux pam/sshd)
    # Check sudo user first so that target USER=root does not overwrite actor
    if (mapped.get("product") or "").lower() == "sudo" or "TTY=" in raw_message:
        sudo_match = re.search(r"^\s*(?P<user>[a-zA-Z0-9_\-\.\$]+)\s*:\s+TTY=", raw_message)
        if sudo_match:
            mapped["user"] = sudo_match.group("user")
            mapped["vendor"] = "Linux"
            mapped["category_name"] = "Identity & Access Management"
            mapped["activity_name"] = "Elevate"
            mapped["severity"] = "Informational"
            mapped["severity_id"] = 1

    # Extract Embedded JSON if message payload contains a JSON object (e.g. mixed syslog + JSON)
    msg_trimmed = raw_message.strip()
    json_start = msg_trimmed.find("{")
    json_end = msg_trimmed.rfind("}")
    if json_start != -1 and json_end > json_start:
        try:
            parsed_json = json.loads(msg_trimmed[json_start : json_end + 1])
            if isinstance(parsed_json, dict):
                for jk, jv in parsed_json.items():
                    norm_jk = jk.lower()
                    canon_jk = _FIELD_MAP.get(norm_jk, norm_jk)
                    if canon_jk in ("src_ip", "dst_ip", "user", "action", "status", "severity", "protocol", "service_name") and canon_jk not in mapped:
                        mapped[canon_jk] = jv
                    elif canon_jk in ("src_port", "dst_port"):
                        pv = coerce_int(jv)
                        if pv is not None and canon_jk not in mapped:
                            mapped[canon_jk] = pv
                    else:
                        unmapped[jk] = jv
        except Exception:
            pass

    for kv_match in _KV_RE.finditer(raw_message):
        key = kv_match.group(1).lower()
        val = kv_match.group(2).strip("\"';,")
        if not val or val.lower() in ("null", "none", "-", ""):
            continue

        if key in ("srcip", "srcaddr", "rhost", "src", "source_ip", "sourceip") and "src_ip" not in mapped:
            if _IPV4_RE.match(val) or _IPV6_RE.match(val):
                mapped["src_ip"] = val
            else:
                mapped["src_hostname"] = val
                mapped["src_endpoint_name"] = val
            continue

        if key in ("dstip", "dstaddr", "dst", "destination_ip", "destip") and "dst_ip" not in mapped:
            if _IPV4_RE.match(val) or _IPV6_RE.match(val):
                mapped["dst_ip"] = val
            else:
                mapped["dst_hostname"] = val
                mapped["dst_endpoint_name"] = val
            continue

        if key in ("srcport", "sport", "spt", "source_port") and "src_port" not in mapped:
            p = coerce_int(val)
            if p is not None:
                mapped["src_port"] = p
            continue

        if key in ("dstport", "dport", "dpt", "destination_port") and "dst_port" not in mapped:
            p = coerce_int(val)
            if p is not None:
                mapped["dst_port"] = p
            continue

        if key in ("user", "ruser", "username", "usrname"):
            if "user" not in mapped:
                mapped["user"] = val
            elif key == "user" and (mapped.get("product") or "").lower() != "sudo":
                mapped["user"] = val
            else:
                unmapped[key] = val
            continue

        if key in ("action", "act") and "activity_name" not in mapped:
            mapped["activity_name"] = val
            continue

        if key == "status" and "status" not in mapped:
            mapped["status"] = val
            continue

        if key in ("level", "lvl", "severity", "sev") and "severity" not in mapped:
            mapped["severity"] = val
            continue

        if key in ("date", "time"):
            unmapped[key] = val
            continue

        unified_key = _FIELD_MAP.get(key)
        if unified_key and unified_key not in mapped:
            if unified_key in ("src_port", "dst_port", "traffic_bytes", "traffic_packets"):
                iv = coerce_int(val)
                if iv is not None:
                    mapped[unified_key] = iv
                else:
                    unmapped[key] = val
            elif unified_key in ("is_mfa", "is_remote"):
                mapped[unified_key] = coerce_bool(val)
            else:
                mapped[unified_key] = val
        else:
            unmapped[key] = val

    # Combine Fortinet date + time if timestamp missing
    if "timestamp" not in mapped and "date" in unmapped and "time" in unmapped:
        combined_ts_str = f"{unmapped['date']} {unmapped['time']}"
        parsed_dt = parse_timestamp(combined_ts_str)
        if parsed_dt:
            mapped["timestamp"] = parsed_dt

    # 6. Network extraction for sshd / auth messages
    proc_clean = (mapped.get("product") or "").split("(")[0].strip().lower()
    if "src_ip" not in mapped and "src_endpoint_name" not in mapped:
        from_match = _SSHD_FROM_RE.search(raw_message)
        if from_match:
            host_val = from_match.group("host")
            if _IPV4_RE.match(host_val) or _IPV6_RE.match(host_val):
                mapped["src_ip"] = host_val
                if from_match.group("port") and "src_port" not in mapped:
                    mapped["src_port"] = int(from_match.group("port"))
            elif from_match.group("port") or (proc_clean in _AUTH_PROCESS_NAMES and ("." in host_val or host_val.isalnum())):
                # Exclude SQL keywords like FROM users
                if host_val.lower() not in ("users", "table", "dual", "where", "select", "accounts", "orders"):
                    mapped["src_endpoint_name"] = host_val
                    mapped["src_hostname"] = host_val
                    if from_match.group("port") and "src_port" not in mapped:
                        mapped["src_port"] = int(from_match.group("port"))

    # Also check generic "from <ip> port <port>"
    if "src_ip" not in mapped:
        gen_from_match = re.search(r"\bfrom\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})(?:\s+port\s+(?P<port>\d+))?", raw_message, re.IGNORECASE)
        if gen_from_match:
            mapped["src_ip"] = gen_from_match.group("ip")
            if gen_from_match.group("port") and "src_port" not in mapped:
                mapped["src_port"] = int(gen_from_match.group("port"))

    # 7. User extraction and status for Linux Auth / SSH / Sudo daemons
    if proc_clean in _AUTH_PROCESS_NAMES or "sshd" in proc_clean:
        if "vendor" not in mapped and proc_clean in ("sshd", "sudo", "pam_unix", "su", "login"):
            mapped["vendor"] = "Linux"
        if "category_name" not in mapped:
            mapped["category_name"] = "Identity & Access Management"
        if "activity_name" not in mapped:
            mapped["activity_name"] = "Logon"

        if "authentication failure" in raw_message.lower():
            mapped["status"] = "Failure"
            mapped["status_id"] = 2
            mapped["severity"] = "High"
            mapped["severity_id"] = 4

        if "user" not in mapped:
            if re.search(r"\buser\s+unknown\b", raw_message, re.IGNORECASE):
                mapped["user"] = "unknown"
            else:
                auth_match = re.search(
                    r"\b(?:Failed|Accepted)\s+(?:password|publickey|none)\s+for\s+(?:invalid\s+user\s+)?(?P<user>[a-zA-Z0-9_\-\.\$]+)\s+from\b",
                    raw_message,
                    re.IGNORECASE,
                )
                if auth_match:
                    mapped["user"] = auth_match.group("user")
                    if "Failed" in auth_match.group(0):
                        mapped["status"] = "Failure"
                        mapped["status_id"] = 2
                        mapped["severity"] = "High"
                        mapped["severity_id"] = 4
                    elif "Accepted" in auth_match.group(0):
                        mapped["status"] = "Success"
                        mapped["status_id"] = 1
                        mapped["severity"] = "Informational"
                        mapped["severity_id"] = 1
                else:
                    inv_match = re.search(r"\bInvalid\s+user\s+(?P<user>[a-zA-Z0-9_\-\.\$]+)\s+from\b", raw_message, re.IGNORECASE)
                    if inv_match:
                        mapped["user"] = inv_match.group("user")
                        mapped["status"] = "Failure"
                        mapped["status_id"] = 2
                        mapped["severity"] = "High"
                        mapped["severity_id"] = 4
                    else:
                        sess_match = re.search(r"\bsession\s+opened\s+for\s+user\s+(?P<user>[a-zA-Z0-9_\-\.\$]+)\b", raw_message, re.IGNORECASE)
                        if sess_match:
                            mapped["user"] = sess_match.group("user")
                            mapped["status"] = "Success"
                            mapped["status_id"] = 1
                        elif "disconnect" in raw_message.lower():
                            mapped["activity_name"] = "Disconnect"
                            mapped["status"] = "Success"
                            mapped["status_id"] = 1
                            mapped["severity"] = "Informational"
                            mapped["severity_id"] = 1

    # Database authentication failure pattern (e.g. MySQL)
    if "user" not in mapped and "access denied for user" in raw_message.lower():
        ad_match = re.search(r"Access denied for user '(?P<user>[^']+)'@'(?P<host>[^']+)'", raw_message, re.IGNORECASE)
        if ad_match:
            mapped["user"] = ad_match.group("user")
            h = ad_match.group("host")
            if _IPV4_RE.match(h) or _IPV6_RE.match(h):
                mapped["src_ip"] = h
            else:
                mapped["src_hostname"] = h
            mapped["category_name"] = "Identity & Access Management"
            mapped["activity_name"] = "Logon"
            mapped["status"] = "Failure"
            mapped["status_id"] = 2
            mapped["severity"] = "High"
            mapped["severity_id"] = 4

    # Standard Linux daemons default
    if proc_clean == "firewalld":
        if "vendor" not in mapped:
            mapped["vendor"] = "Linux"
        if "category_name" not in mapped:
            mapped["category_name"] = "System Activity"
        if "activity_name" not in mapped:
            mapped["activity_name"] = "Log"
        if "severity" not in mapped:
            mapped["severity"] = "Informational"
            mapped["severity_id"] = 1

    if proc_clean == "cron":
        if "category_name" not in mapped:
            mapped["category_name"] = "System Activity"
        if "activity_name" not in mapped:
            mapped["activity_name"] = "Scheduled Activity"
        if "severity" not in mapped:
            mapped["severity"] = "Informational"
            mapped["severity_id"] = 1
        cron_user_match = re.search(r"^\((?P<user>[^)]+)\)\s+CMD", raw_message)
        if cron_user_match and "user" not in mapped:
            mapped["user"] = cron_user_match.group("user")

    if proc_clean == "newsyslog":
        if "category_name" not in mapped:
            mapped["category_name"] = "System Activity"
        if "activity_name" not in mapped:
            mapped["activity_name"] = "Log"
        if "severity" not in mapped:
            mapped["severity"] = "Informational"
            mapped["severity_id"] = 1

    if proc_clean == "systemd":
        if "category_name" not in mapped:
            mapped["category_name"] = "System Activity"
        if "severity" not in mapped:
            mapped["severity"] = "Informational"
            mapped["severity_id"] = 1
        if "started" in raw_message.lower() and "activity_name" not in mapped:
            mapped["activity_name"] = "Service Start"

    if unmapped:
        mapped["unmapped"] = unmapped

    enrich_classification(mapped)
    mapped["log_format"] = "syslog"
    mapped["raw_event"] = raw

    return UnifiedEvent(**mapped)
