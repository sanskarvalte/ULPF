"""
CEF (Common Event Format) log parser for ULPF.
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
    "externalid": "raw_event_id",
    "rt": "timestamp",
    "end": "timestamp",
    "start": "timestamp",
    "devicereceipttime": "timestamp",
    "cat": "category_name",
    "act": "activity_name",
    "outcome": "status",
    "msg": "message",
    "src": "src_ip",
    "shost": "src_hostname",
    "dst": "dst_ip",
    "dhost": "dst_hostname",
    "spt": "src_port",
    "dpt": "dst_port",
    "proto": "protocol",
    "in": "traffic_bytes",
    "suser": "user",
    "duser": "user",
    "suid": "user_uid",
}


def _cef_severity_label(raw: str) -> tuple[str, int]:
    raw = raw.strip().lower()
    if raw in SEVERITY_ID_MAP:
        return raw.capitalize(), SEVERITY_ID_MAP[raw]
    try:
        n = int(raw)
    except ValueError:
        return raw, 0
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
        return datetime.fromtimestamp(ms / 1000, tz=timezone.utc)
    except ValueError:
        pass
    return parse_timestamp(value)


_CEF_KV_RE = re.compile(r"([a-zA-Z0-9]+)=(.*?)(?=\s+[a-zA-Z0-9]+=|$)")


class CefParser(BaseParser):
    format_name = "cef"

    def parse(self, raw: str) -> UnifiedEvent:
        return parse_cef_log(raw)


def parse_cef_log(raw: str) -> UnifiedEvent:
    raw_stripped = raw.strip()
    if not raw_stripped.upper().startswith("CEF:"):
        raise ValueError("Not a valid CEF line (must start with 'CEF:')")

    parts = raw_stripped.split("|", 7)
    if len(parts) < 7:
        raise ValueError(f"CEF header incomplete — expected 7+ pipe fields, got {len(parts)}")

    vendor = parts[1].strip()
    product_name = parts[2].strip()
    dev_version = parts[3].strip()
    sig_id = parts[4].strip()
    name = parts[5].strip()
    sev_raw = parts[6].strip()
    extension = parts[7].strip() if len(parts) > 7 else ""

    severity_label, severity_id = _cef_severity_label(sev_raw)

    mapped: Dict[str, Any] = {
        "raw_event_id": sig_id or None,
        "activity_name": name or None,
        "severity": severity_label,
        "severity_id": severity_id,
        "vendor": vendor or None,
        "product": product_name or None,
        "product_version": dev_version or None,
    }

    for m in _CEF_KV_RE.finditer(extension):
        key = m.group(1).lower()
        val = m.group(2).strip()

        unified_key = _EXT_MAP.get(key)
        if unified_key is None:
            continue
        if unified_key in mapped and mapped[unified_key] is not None:
            continue

        if unified_key == "timestamp":
            val = _parse_cef_timestamp(val)
        elif unified_key in ("src_port", "dst_port", "traffic_bytes"):
            val = coerce_int(val)
            if val is None:
                continue

        if val is not None:
            mapped[unified_key] = val

    mapped = {k: v for k, v in mapped.items() if v is not None}
    enrich_classification(mapped)
    mapped["log_format"] = "cef"
    mapped["raw_event"] = raw

    return UnifiedEvent(**mapped)
