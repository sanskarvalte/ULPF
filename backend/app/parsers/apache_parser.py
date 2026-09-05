"""
Apache HTTP Server Access Log Parser for ULPF.
Supports NCSA Common Log Format (CLF) and NCSA Combined Log Format.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from app.models.event_schema import UnifiedEvent
from app.normalization.field_mapping import coerce_int, parse_timestamp
from app.parsers.base import BaseParser

_APACHE_COMBINED_RE = re.compile(
    r'^(?P<ip>\S+)\s+(?P<ident>\S+)\s+(?P<user>\S+)\s+\[(?P<time>[^\]]+)\]\s+"(?P<method>[A-Z]+)\s+(?P<uri>\S+)(?:\s+(?P<protocol>[^"]+))?"\s+(?P<status>\d{3})\s+(?P<bytes>\S+)(?:\s+"(?P<referer>[^"]*)"\s+"(?P<user_agent>[^"]*)")?'
)

_IPV4_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
_IPV6_RE = re.compile(r"^[0-9a-fA-F:]+$")


def _parse_apache_timestamp(ts_str: str) -> Optional[datetime]:
    """Parse Apache timestamp format, e.g. '10/Oct/2000:13:55:36 -0700'."""
    try:
        return datetime.strptime(ts_str.strip(), "%d/%b/%Y:%H:%M:%S %z")
    except Exception:
        return parse_timestamp(ts_str)


def parse_apache_log(raw: str) -> UnifiedEvent:
    raw_clean = raw.strip()
    m = _APACHE_COMBINED_RE.match(raw_clean)
    if not m:
        # Fallback if quotes or formatting vary slightly
        from app.parsers.generic_parser import parse_generic_log
        ev = parse_generic_log(raw)
        ev.log_format = "apache"
        return ev

    gd = m.groupdict()
    mapped: Dict[str, Any] = {}
    unmapped: Dict[str, Any] = {}

    # Source IP
    ip = gd.get("ip") or ""
    if _IPV4_RE.match(ip) or _IPV6_RE.match(ip):
        mapped["src_ip"] = ip
    elif ip and ip != "-":
        mapped["src_hostname"] = ip

    # User
    user = gd.get("user")
    if user and user != "-":
        mapped["user"] = user

    # Timestamp
    time_str = gd.get("time")
    if time_str:
        mapped["timestamp"] = _parse_apache_timestamp(time_str)

    # HTTP method / activity
    method = gd.get("method")
    if method:
        mapped["activity_name"] = method
        mapped["action"] = method

    # Status code & Status
    status_str = gd.get("status")
    if status_str:
        mapped["status_code"] = status_str
        status_num = coerce_int(status_str)
        if status_num is not None:
            if status_num < 400:
                mapped["status"] = "Success"
                mapped["status_id"] = 1
                mapped["severity"] = "Informational"
                mapped["severity_id"] = 1
            elif status_num < 500:
                mapped["status"] = "Failure"
                mapped["status_id"] = 2
                mapped["severity"] = "Medium"
                mapped["severity_id"] = 3
            else:
                mapped["status"] = "Failure"
                mapped["status_id"] = 2
                mapped["severity"] = "High"
                mapped["severity_id"] = 4

    # Bytes
    bytes_str = gd.get("bytes")
    if bytes_str and bytes_str != "-":
        bytes_val = coerce_int(bytes_str)
        if bytes_val is not None:
            mapped["traffic_bytes"] = bytes_val

    # Message
    uri = gd.get("uri") or ""
    proto = gd.get("protocol") or ""
    mapped["message"] = f"{method} {uri} {proto}".strip()

    # Vendor & Taxonomy
    mapped["vendor"] = "Apache"
    mapped["product"] = "HTTP Server"
    mapped["category_name"] = "Network Activity"
    mapped["category_uid"] = 4
    mapped["class_name"] = "HTTP Activity"
    mapped["class_uid"] = 4002

    # Unmapped metadata preservation
    ident = gd.get("ident")
    if ident and ident != "-":
        unmapped["ident"] = ident
    if uri:
        unmapped["uri"] = uri
    if proto:
        unmapped["http_version"] = proto
    referer = gd.get("referer")
    if referer and referer != "-":
        unmapped["referer"] = referer
    user_agent = gd.get("user_agent")
    if user_agent and user_agent != "-":
        unmapped["user_agent"] = user_agent

    mapped["log_format"] = "apache"
    mapped["raw_event"] = raw
    if unmapped:
        mapped["unmapped"] = unmapped

    return UnifiedEvent(**mapped)


class ApacheParser(BaseParser):
    format_name = "apache"

    def parse(self, raw: str) -> UnifiedEvent:
        return parse_apache_log(raw)
