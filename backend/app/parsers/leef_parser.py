"""
LEEF (Log Event Extended Format - IBM QRadar) log parser for ULPF.
Parses standard LEEF 1.0 and LEEF 2.0 log payloads.
"""

from __future__ import annotations

import re
from typing import Any, Dict

from app.models.event_schema import UnifiedEvent
from app.normalization.engine import enrich_classification
from app.normalization.field_mapping import coerce_int, parse_timestamp
from app.parsers.base import BaseParser

_LEEF_FIELD_MAP: Dict[str, str] = {
    "src": "src_ip",
    "dst": "dst_ip",
    "srcip": "src_ip",
    "dstip": "dst_ip",
    "srcport": "src_port",
    "dstport": "dst_port",
    "src_port": "src_port",
    "dst_port": "dst_port",
    "usrname": "user",
    "username": "user",
    "user": "user",
    "proto": "protocol",
    "protocol": "protocol",
    "devtime": "timestamp",
    "devicetime": "timestamp",
    "msg": "message",
    "message": "message",
    "sev": "severity_id",
    "severity": "severity_id",
    "cat": "category_name",
    "category": "category_name",
    "action": "activity_name",
    "act": "activity_name",
    "status": "status",
}


class LeefParser(BaseParser):
    format_name = "leef"

    def parse(self, raw: str) -> UnifiedEvent:
        return parse_leef_log(raw)


def parse_leef_log(raw: str) -> UnifiedEvent:
    raw_stripped = raw.strip()
    if not raw_stripped.upper().startswith("LEEF:"):
        raise ValueError("Not a valid LEEF line (must start with 'LEEF:')")

    # Split header: LEEF:Version|Vendor|Product|Version|EventID|[Delimiter]|Attributes
    parts = raw_stripped.split("|", 6)
    if len(parts) < 5:
        raise ValueError(f"LEEF header incomplete — expected 5+ pipe fields, got {len(parts)}")

    vendor = parts[1].strip() or None
    product = parts[2].strip() or None
    version = parts[3].strip() or None
    event_id = parts[4].strip() or None

    attributes_str = ""
    if len(parts) >= 6:
        # Check if 6th part is a single custom delimiter or attributes
        if len(parts) == 7:
            attributes_str = parts[6]
        else:
            attributes_str = parts[5]

    mapped: Dict[str, Any] = {
        "vendor": vendor,
        "product": product,
        "product_version": version,
        "status_code": event_id,
        "message": event_id,
    }
    unmapped: Dict[str, Any] = {}

    if event_id:
        unmapped["event_id"] = event_id

    # Parse key=value pairs delimited by Tab, ^, or ;
    # Regex matches key=value across whitespace/tab delimiters
    kv_pairs = re.findall(r"([a-zA-Z0-9_\-\.]+)=([^\t\^\|\n\r]+)", attributes_str)
    for k, v in kv_pairs:
        k_clean = k.strip()
        v_clean = v.strip().strip("\"'")
        k_lower = k_clean.lower()

        unified_k = _LEEF_FIELD_MAP.get(k_lower)
        if unified_k:
            if unified_k == "timestamp":
                parsed_t = parse_timestamp(v_clean)
                if parsed_t:
                    mapped[unified_k] = parsed_t
                else:
                    unmapped[k_clean] = v_clean
            elif unified_k in ("src_port", "dst_port", "severity_id"):
                p = coerce_int(v_clean)
                if p is not None:
                    mapped[unified_k] = p
                else:
                    unmapped[k_clean] = v_clean
            else:
                mapped[unified_k] = v_clean
        else:
            unmapped[k_clean] = v_clean

    if unmapped:
        mapped["unmapped"] = unmapped

    # Category and Activity classification
    if not mapped.get("category_name"):
        ev_id_lower = str(event_id or "").lower()
        if "login" in ev_id_lower or "logon" in ev_id_lower or "auth" in ev_id_lower:
            mapped["category_name"] = "Identity & Access Management"
            mapped["class_name"] = "Authentication"
            mapped.setdefault("activity_name", "Logon")
        elif "src_ip" in mapped and "dst_ip" in mapped:
            mapped["category_name"] = "Network Activity"
            mapped["class_name"] = "Network Activity"

    mapped = {k: v for k, v in mapped.items() if v is not None}
    enrich_classification(mapped)
    mapped["log_format"] = "leef"
    mapped["raw_event"] = raw

    return UnifiedEvent(**mapped)
