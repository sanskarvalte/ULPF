"""
CSV log parser for ULPF.
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

    for col_name, value in row.items():
        if col_name is None:
            continue
        unified_key = _FIELD_MAP.get(col_name.strip().lower())
        if unified_key is None:
            continue
        if unified_key in mapped:
            continue

        value = value.strip() if isinstance(value, str) else value
        if not value:
            continue

        if unified_key == "timestamp":
            value = parse_timestamp(value)
        elif unified_key == "severity_id":
            value = coerce_int(value)
            if value is None:
                continue
        elif unified_key in ("src_port", "dst_port", "traffic_bytes", "traffic_packets"):
            value = coerce_int(value)
            if value is None:
                continue
        elif unified_key in ("is_mfa", "is_remote"):
            value = coerce_bool(value)

        if value is not None:
            mapped[unified_key] = value

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
    reader = csv.DictReader(io.StringIO(raw))
    rows = list(reader)
    if not rows:
        raise ValueError("CSV contains a header but no data rows")
    return _row_to_event(rows[0], raw)


def parse_csv_log_all(raw: str) -> List[UnifiedEvent]:
    reader = csv.DictReader(io.StringIO(raw))
    rows = list(reader)
    if not rows:
        raise ValueError("CSV contains a header but no data rows")
    return [_row_to_event(row, raw) for row in rows]
