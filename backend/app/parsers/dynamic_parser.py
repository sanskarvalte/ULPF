"""
Dynamic Rule-Based Parser (Node 4 & Node 7).
Instantiates a fast, deterministic parser from human-approved regex patterns and field mappings.
"""

from __future__ import annotations

import re
from typing import Any, Dict, Optional

from app.models.event_schema import UnifiedEvent
from app.normalization.engine import enrich_classification
from app.normalization.field_mapping import (
    COMMON_FIELD_MAP,
    coerce_bool,
    coerce_int,
    parse_timestamp,
)
from app.parsers.base import BaseParser

_KV_RE = re.compile(
    r"""(?P<key>[a-zA-Z_]\w*)=(?P<val>"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|\S*)"""
)


_OCSF_FLAT_ALIASES = {
    "src_endpoint.ip": "src_ip",
    "dst_endpoint.ip": "dst_ip",
    "src_endpoint.port": "src_port",
    "dst_endpoint.port": "dst_port",
    "user.name": "user",
    "device.hostname": "src_hostname",
    "time": "timestamp",
    "activity_name": "activity_name",
    "disposition": "status",
    "status_code": "status_code",
}


class DynamicPatternParser(BaseParser):
    """Dynamically compiled parser for human-approved custom formats."""

    def __init__(
        self,
        format_name: str,
        pattern_regex: str,
        field_mapping: Dict[str, Any],
        vendor: Optional[str] = None,
        product: Optional[str] = None,
    ):
        self.format_name = format_name
        self.pattern_regex = pattern_regex
        self.field_mapping = field_mapping
        self.vendor = vendor
        self.product = product
        try:
            self._compiled = re.compile(pattern_regex, re.DOTALL | re.IGNORECASE)
        except Exception:
            self._compiled = None

    def parse(self, raw: str) -> UnifiedEvent:
        raw_stripped = raw.strip()
        mapped: Dict[str, Any] = {
            "log_format": self.format_name,
            "raw_event": raw,
            "vendor": self.vendor,
            "product": self.product,
        }
        unmapped: Dict[str, Any] = {}

        # 1. Named regex group extraction
        if self._compiled:
            match = self._compiled.search(raw_stripped)
            if match and match.groupdict():
                for group_name, val in match.groupdict().items():
                    if val is None:
                        continue
                    clean_val = val.strip("\"' ")
                    raw_ocsf = self.field_mapping.get(group_name) or COMMON_FIELD_MAP.get(group_name.lower())
                    ocsf_field = _OCSF_FLAT_ALIASES.get(raw_ocsf, raw_ocsf)
                    if ocsf_field and ocsf_field != "unmapped":
                        mapped[ocsf_field] = clean_val
                    else:
                        unmapped[group_name] = clean_val

        # 2. Key-Value token extraction
        for kv in _KV_RE.finditer(raw_stripped):
            k = kv.group("key")
            v = kv.group("val").strip("\"';,")
            if not v:
                continue
            ocsf_field = self.field_mapping.get(k) or COMMON_FIELD_MAP.get(k.lower())
            if ocsf_field and ocsf_field != "unmapped" and ocsf_field not in mapped:
                mapped[ocsf_field] = v
            elif k not in mapped:
                unmapped[k] = v

        # 3. Apply static field overrides from approved mapping
        for target_field, val in self.field_mapping.items():
            if target_field.startswith("_static_"):
                real_field = target_field.replace("_static_", "")
                mapped[real_field] = val

        # 4. Type conversions
        if "timestamp" in mapped and isinstance(mapped["timestamp"], str):
            mapped["timestamp"] = parse_timestamp(mapped["timestamp"])
        for int_field in ("src_port", "dst_port", "severity_id", "status_id", "traffic_bytes"):
            if int_field in mapped:
                mapped[int_field] = coerce_int(mapped[int_field])

        if unmapped:
            mapped["unmapped"] = unmapped

        # 5. Message fallback
        if not mapped.get("message"):
            mapped["message"] = raw_stripped

        enrich_classification(mapped)
        return UnifiedEvent(**mapped)
