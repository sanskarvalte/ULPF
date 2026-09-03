"""
CSV log parser for ULPF.
Supports header-based columnar security log parsing and 1:1 event mapping.
"""

from __future__ import annotations

import csv
import io
from typing import Any, Dict, List

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


def _row_to_event(row: Dict[str, str], raw: str) -> UnifiedEvent:
    mapped: Dict[str, Any] = {}
    unmapped: Dict[str, Any] = {}

    for col_name, value in row.items():
        if col_name is None:
            continue
        c_clean = col_name.strip()
        unified_key = _FIELD_MAP.get(c_clean.lower())

        value_str = value.strip() if isinstance(value, str) else str(value) if value is not None else ""
        if not value_str or value_str.lower() in ("null", "none", "-", ""):
            continue

        if unified_key is None:
            unmapped[c_clean] = value_str
            continue
        if unified_key in mapped and mapped[unified_key] is not None:
            unmapped[c_clean] = value_str
            continue

        if unified_key == "timestamp":
            parsed_ts = parse_timestamp(value_str)
            if parsed_ts:
                mapped[unified_key] = parsed_ts
            else:
                unmapped[c_clean] = value_str
        elif unified_key == "severity_id":
            iv = coerce_int(value_str)
            if iv is not None:
                mapped[unified_key] = iv
            else:
                unmapped[c_clean] = value_str
        elif unified_key in ("src_port", "dst_port", "traffic_bytes", "traffic_packets"):
            iv = coerce_int(value_str)
            if iv is not None:
                mapped[unified_key] = iv
            else:
                unmapped[c_clean] = value_str
        elif unified_key in ("is_mfa", "is_remote"):
            mapped[unified_key] = coerce_bool(value_str)
        else:
            mapped[unified_key] = value_str

    if unmapped:
        mapped["unmapped"] = unmapped

    enrich_classification(mapped)
    mapped["log_format"] = "csv"
    mapped["raw_event"] = raw

    return UnifiedEvent(**mapped)


class CsvParser(BaseParser):
    format_name = "csv"

    def parse(self, raw: str) -> UnifiedEvent:
        return parse_csv_log(raw)

    def parse_all(self, raw: str) -> List[UnifiedEvent]:
        return parse_csv_log_all(raw)


def parse_csv_log(raw: str) -> UnifiedEvent:
    reader = csv.DictReader(io.StringIO(raw), escapechar="\\")
    rows = list(reader)
    if not rows:
        raise ValueError("CSV contains a header but no data rows")
    return _row_to_event(rows[0], raw)


def parse_csv_log_all(raw: str) -> List[UnifiedEvent]:
    reader = csv.DictReader(io.StringIO(raw), escapechar="\\")
    rows = list(reader)
    if not rows:
        raise ValueError("CSV contains a header but no data rows")
    
    events = []
    for row in rows:
        row_raw = ",".join([str(v) for v in row.values() if v is not None]) or raw
        events.append(_row_to_event(row, row_raw))
    return events
