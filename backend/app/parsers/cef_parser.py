"""
CEF (Common Event Format) log parser for ULPF.
Parses standard ArcSight/CheckPoint CEF headers and extensions.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Dict

from app.models.event_schema import UnifiedEvent
from app.normalization.engine import enrich_classification
from app.normalization.field_mapping import coerce_int, parse_timestamp
from app.normalization.taxonomy import SEVERITY_ID_MAP
from app.parsers.base import BaseParser

_EXT_MAP: Dict[str, str] = {
    "rt": "timestamp",
    "end": "timestamp",
    "start": "timestamp",
    "devicereceipttime": "timestamp",
    "cat": "category_name",
    "act": "activity_name",
    "action": "activity_name",
    "outcome": "status",
    "msg": "message",
    "message": "message",
    "src": "src_ip",
    "sourceaddress": "src_ip",
    "shost": "src_hostname",
    "sourcehostname": "src_hostname",
    "dst": "dst_ip",
    "destinationaddress": "dst_ip",
    "dhost": "dst_hostname",
    "destinationhostname": "dst_hostname",
    "spt": "src_port",
    "sourceport": "src_port",
    "dpt": "dst_port",
    "destinationport": "dst_port",
    "proto": "protocol",
    "in": "traffic_bytes",
    "out": "traffic_bytes",
    "bytesin": "traffic_bytes",
    "suser": "user",
    "duser": "user",
    "sourceusername": "user",
    "destinationusername": "user",
    "suid": "user_uid",
    "duid": "user_uid",
    "request": "message",
    "requestmethod": "activity_name",
    "app": "service_name",
}


def _cef_severity_label(raw: str) -> tuple[str, int]:
    """Map CEF numeric 0-10 or string severity to OCSF Severity."""
    raw = raw.strip().lower()
    if raw in SEVERITY_ID_MAP:
        return raw.capitalize(), SEVERITY_ID_MAP[raw]
    try:
        n = int(raw)
    except ValueError:
        return "Informational", 1
    if n == 0:
        return "Informational", 1
    if n <= 3:
        return "Low", 2
    if n <= 6:
        return "Medium", 3
    if n <= 8:
        return "High", 4
    return "Critical", 5


def _parse_cef_timestamp(value: str) -> datetime | None:
    value = value.strip()
    if not value:
        return None
    try:
        ms = int(value)
        if ms > 1e11:
            return datetime.fromtimestamp(ms / 1000, tz=timezone.utc)
        return datetime.fromtimestamp(ms, tz=timezone.utc)
    except ValueError:
        pass
    return parse_timestamp(value)


def _split_cef_header(raw: str) -> list[str]:
    """
    Split CEF header by unescaped pipe characters (|).
    CEF:Version|Device Vendor|Device Product|Device Version|Device Event Class ID|Name|Severity|Extension
    """
    parts = []
    current: list[str] = []
    escaped = False
    for char in raw:
        if escaped:
            current.append(char)
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == "|" and len(parts) < 7:
            parts.append("".join(current))
            current = []
        else:
            current.append(char)
    parts.append("".join(current))
    return parts


class CefParser(BaseParser):
    format_name = "cef"

    def parse(self, raw: str) -> UnifiedEvent:
        return parse_cef_log(raw)


def parse_cef_log(raw: str) -> UnifiedEvent:
    raw_stripped = raw.strip()
    if not raw_stripped.upper().startswith("CEF:"):
        raise ValueError("Not a valid CEF line (must start with 'CEF:')")

    parts = _split_cef_header(raw_stripped)
    if len(parts) < 7:
        raise ValueError(f"CEF header incomplete — expected 7+ pipe fields, got {len(parts)}")

    vendor = parts[1].strip() or None
    product_name = parts[2].strip() or None
    dev_version = parts[3].strip() or None
    sig_id = parts[4].strip() or None
    name = parts[5].strip() or None
    sev_raw = parts[6].strip()
    extension = parts[7].strip() if len(parts) > 7 else ""

    severity_label, severity_id = _cef_severity_label(sev_raw)

    mapped: Dict[str, Any] = {
        "activity_name": name,
        "severity": severity_label,
        "severity_id": severity_id,
        "vendor": vendor,
        "product": product_name,
        "product_version": dev_version,
        "status_code": sig_id,
        "message": name,
    }
    unmapped: Dict[str, Any] = {}

    if sig_id:
        unmapped["signature_id"] = sig_id

    # Parse Extension Key=Value pairs
    for m in re.finditer(r"([a-zA-Z0-9_\-\.]+)=(.*?)(?=\s+[a-zA-Z0-9_\-\.]+=|$)", extension):
        key = m.group(1).strip()
        val = m.group(2).strip().replace("\\=", "=").replace("\\|", "|").replace("\\\\", "\\")

        k_lower = key.lower()
        unified_key = _EXT_MAP.get(k_lower)
        if unified_key is None:
            unmapped[key] = val
            continue
        if unified_key in mapped and mapped[unified_key] is not None and unified_key != "message":
            unmapped[key] = val
            continue

        if unified_key == "timestamp":
            parsed_t = _parse_cef_timestamp(val)
            if parsed_t:
                mapped[unified_key] = parsed_t
            else:
                unmapped[key] = val
        elif unified_key in ("src_port", "dst_port", "traffic_bytes"):
            p = coerce_int(val)
            if p is not None:
                mapped[unified_key] = p
            else:
                unmapped[key] = val
        else:
            mapped[unified_key] = val

    if unmapped:
        mapped["unmapped"] = unmapped

    # Category and Status classification for firewall / network events
    if not mapped.get("category_name"):
        if mapped.get("product") and "firewall" in str(mapped["product"]).lower():
            mapped["category_name"] = "Network Activity"
            mapped["class_name"] = "Network Activity"
        elif "src_ip" in mapped and "dst_ip" in mapped:
            mapped["category_name"] = "Network Activity"
            mapped["class_name"] = "Network Activity"

    if not mapped.get("status"):
        act_lower = str(mapped.get("activity_name") or "").lower()
        if act_lower in ("drop", "block", "deny", "reject", "fail"):
            mapped["status"] = "Failure"
            mapped["status_id"] = 2
        elif act_lower in ("allow", "accept", "permit", "pass"):
            mapped["status"] = "Success"
            mapped["status_id"] = 1

    mapped = {k: v for k, v in mapped.items() if v is not None}
    enrich_classification(mapped)
    mapped["log_format"] = "cef"
    mapped["raw_event"] = raw

    return UnifiedEvent(**mapped)
