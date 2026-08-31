"""
JSON log parser for ULPF.
"""

from __future__ import annotations

import json
from typing import Any, Dict

from app.models.event_schema import UnifiedEvent
from app.normalization.field_mapping import (
    COMMON_FIELD_MAP,
    coerce_bool,
    coerce_int,
    parse_timestamp,
)
from app.normalization.engine import enrich_classification
from app.parsers.base import BaseParser


class JsonParser(BaseParser):
    format_name = "json"

    def parse(self, raw: str) -> UnifiedEvent:
        return parse_json_log(raw)


def parse_json_log(raw: str) -> UnifiedEvent:
    data: Dict[str, Any] = json.loads(raw)
    if not isinstance(data, dict):
        raise ValueError(f"Expected a JSON object, got {type(data).__name__}")

    mapped: Dict[str, Any] = {}
    unmapped: Dict[str, Any] = {}

    for src_key, value in data.items():
        unified_key = COMMON_FIELD_MAP.get(src_key)
        if unified_key is None:
            unmapped[src_key] = value
            continue
        if unified_key in mapped:
            unmapped[src_key] = value
            continue

        if unified_key == "timestamp":
            parsed_ts = parse_timestamp(value)
            if parsed_ts is not None:
                value = parsed_ts
            else:
                unmapped[src_key] = value
                continue
        elif unified_key == "severity_id":
            value = coerce_int(value)
        elif unified_key in ("src_port", "dst_port", "traffic_bytes", "traffic_packets"):
            value = coerce_int(value)
        elif unified_key in ("is_mfa", "is_remote"):
            value = coerce_bool(value)

        if value is not None:
            mapped[unified_key] = value
        else:
            unmapped[src_key] = value

    # Construct default message if not explicitly provided
    if "message" not in mapped:
        if "k" in data and "v" in data:
            mapped["message"] = f"{data['k']}: {json.dumps(data['v'])}"
        elif "k" in data:
            mapped["message"] = str(data["k"])
        elif "v" in data:
            mapped["message"] = json.dumps(data["v"])

    # Vendor & product defaults for Tableau Hyper or generic JSON logs
    if "vendor" not in mapped:
        raw_lower = raw.lower()
        if "hyperd" in raw_lower or "hyper" in raw_lower or ("k" in data and ("sev" in data or "ts" in data)):
            mapped.setdefault("vendor", "Tableau")
            mapped.setdefault("product", "Hyper")

    if unmapped:
        mapped["unmapped"] = unmapped

    enrich_classification(mapped)
    mapped["log_format"] = "json"
    mapped["raw_event"] = raw

    return UnifiedEvent(**mapped)
