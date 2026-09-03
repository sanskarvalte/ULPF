"""
JSON log parser for ULPF.
Supports structured JSON event parsing, nested dictionary flattening, and OCSF mapping.
"""

from __future__ import annotations

import json
from typing import Any, Dict

from app.models.event_schema import UnifiedEvent
from app.normalization.engine import enrich_classification
from app.normalization.field_mapping import (
    COMMON_FIELD_MAP,
    coerce_bool,
    coerce_int,
    parse_timestamp,
)
from app.parsers.base import BaseParser


def _flatten_json(d: Dict[str, Any], parent_key: str = "", sep: str = ".") -> Dict[str, Any]:
    """Recursively flatten nested dictionary keys."""
    items: list[tuple[str, Any]] = []
    for k, v in d.items():
        new_key = f"{parent_key}{sep}{k}" if parent_key else k
        if isinstance(v, dict):
            items.extend(_flatten_json(v, new_key, sep=sep).items())
        else:
            items.append((new_key, v))
    return dict(items)


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

    # Extract direct and flattened keys
    flat_data = _flatten_json(data)

    # Process all keys
    for src_key, value in flat_data.items():
        if value is None:
            continue

        # Check exact key, underscored nested key (e.g. "user.name" -> "user_name"), or last segment in nested key (e.g. "network.src_ip" -> "src_ip")
        norm_key = src_key.replace(".", "_").lower()
        leaf_key = src_key.rsplit(".", 1)[-1].lower()
        unified_key = COMMON_FIELD_MAP.get(src_key) or COMMON_FIELD_MAP.get(norm_key) or COMMON_FIELD_MAP.get(leaf_key)

        if unified_key is None:
            unmapped[src_key] = value
            continue
        if unified_key in mapped and mapped[unified_key] is not None and unified_key != "message":
            unmapped[src_key] = value
            continue

        if unified_key == "timestamp":
            parsed_ts = parse_timestamp(value)
            if parsed_ts is not None:
                mapped[unified_key] = parsed_ts
            else:
                unmapped[src_key] = value
        elif unified_key == "severity_id":
            iv = coerce_int(value)
            if iv is not None:
                mapped[unified_key] = iv
            else:
                unmapped[src_key] = value
        elif unified_key in ("src_port", "dst_port", "traffic_bytes", "traffic_packets"):
            iv = coerce_int(value)
            if iv is not None:
                mapped[unified_key] = iv
            else:
                unmapped[src_key] = value
        elif unified_key in ("is_mfa", "is_remote"):
            mapped[unified_key] = coerce_bool(value)
        else:
            mapped[unified_key] = str(value) if isinstance(value, (int, float, bool)) else value

    # Construct message if not explicitly provided
    if "message" not in mapped:
        if "k" in data and "v" in data:
            mapped["message"] = f"{data['k']}: {json.dumps(data['v']) if isinstance(data['v'], dict) else data['v']}"
        elif "message" in data:
            mapped["message"] = str(data["message"])
        elif "msg" in data:
            mapped["message"] = str(data["msg"])
        elif "k" in data:
            mapped["message"] = str(data["k"])
        elif "event" in data:
            mapped["message"] = str(data["event"])

    # Classification inference for standard JSON logs
    if not mapped.get("category_name"):
        act_name = str(mapped.get("activity_name") or "").lower()
        if act_name in ("login", "logon", "auth", "authenticate"):
            mapped["category_name"] = "Identity & Access Management"
            mapped["class_name"] = "Authentication"
            mapped["activity_name"] = "Logon"
        elif "src_ip" in mapped and "dst_ip" in mapped:
            mapped["category_name"] = "Network Activity"
            mapped["class_name"] = "Network Activity"

    # Tableau Hyper detection (k, v, sev structure)
    if "vendor" not in mapped:
        if ("k" in data and ("v" in data or "sev" in data or "ts" in data)) or "hyperd" in raw.lower():
            mapped["vendor"] = "Tableau"
            mapped["product"] = "Hyper"

    if unmapped:
        mapped["unmapped"] = unmapped

    mapped = {k: v for k, v in mapped.items() if v is not None}
    enrich_classification(mapped)
    mapped["log_format"] = "json"
    mapped["raw_event"] = raw

    return UnifiedEvent(**mapped)
