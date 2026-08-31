"""
LEEF (Log Event Extended Format - IBM QRadar) log parser for ULPF.
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
    "srcPort": "src_port",
    "dstPort": "dst_port",
    "usrName": "user",
    "proto": "protocol",
    "devTime": "timestamp",
    "msg": "message",
    "sev": "severity_id",
    "cat": "category_name",
    "action": "activity_name",
}


class LeefParser(BaseParser):
    format_name = "leef"

    def parse(self, raw: str) -> UnifiedEvent:
        return parse_leef_log(raw)


def parse_leef_log(raw: str) -> UnifiedEvent:
    raw_stripped = raw.strip()
    if not raw_stripped.upper().startswith("LEEF:"):
        raise ValueError("Not a valid LEEF line (must start with 'LEEF:')")

    parts = raw_stripped.split("|")
    if len(parts) < 5:
        raise ValueError(f"LEEF header incomplete — expected 5+ fields, got {len(parts)}")

    vendor = parts[1].strip() if len(parts) > 1 else None
    product = parts[2].strip() if len(parts) > 2 else None
    version = parts[3].strip() if len(parts) > 3 else None
    event_id = parts[4].strip() if len(parts) > 4 else None

    # Delimiter can be specified or defaults to tab/pipe
    attributes_str = parts[5] if len(parts) > 5 else ""

    mapped: Dict[str, Any] = {
        "raw_event_id": event_id,
        "vendor": vendor,
        "product": product,
        "product_version": version,
    }

    # Extract Key=Value or Key\tValue
    kv_pairs = re.findall(r"([a-zA-Z0-9_]+)=([^\t^|]+)", attributes_str)
    for k, v in kv_pairs:
        k_clean = k.strip()
        v_clean = v.strip()
        unified_k = _LEEF_FIELD_MAP.get(k_clean)
        if unified_k:
            if unified_k == "timestamp":
                mapped[unified_k] = parse_timestamp(v_clean)
            elif unified_k in ("src_port", "dst_port", "severity_id"):
                mapped[unified_k] = coerce_int(v_clean)
            else:
                mapped[unified_k] = v_clean

    mapped = {k: v for k, v in mapped.items() if v is not None}
    enrich_classification(mapped)
    mapped["log_format"] = "leef"
    mapped["raw_event"] = raw

    return UnifiedEvent(**mapped)
