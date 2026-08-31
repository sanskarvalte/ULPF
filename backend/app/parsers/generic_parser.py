"""
Generic (fallback) log parser for ULPF.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Dict

from app.models.event_schema import UnifiedEvent
from app.normalization.engine import enrich_classification
from app.normalization.field_mapping import (
    COMMON_FIELD_MAP,
    coerce_int,
    parse_timestamp,
)
from app.parsers.base import BaseParser

_KV_EQ_RE = re.compile(
    r"""\b([a-zA-Z_][a-zA-Z0-9_-]*)\s*=\s*("(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|[^\s,;()]+)"""
)
_KV_COLON_RE = re.compile(
    r"""\b([a-zA-Z_][a-zA-Z0-9_-]*)\s*:\s+("(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|[^\s,;()]+)"""
)
_IPV4_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
_LEADING_OFFSET_RE = re.compile(r"^\s*\[?(\d{2}:\d{2}:\d{2}(?:\.\d+)?)\]?\s*")
_ISO_TIMESTAMP_RE = re.compile(
    r"\b(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\b"
)
_DATE_TIME_RE = re.compile(
    r"\b([A-Z][a-z]{2}\s+\d{1,2}\s+\d{4}\s+\d{2}:\d{2}:\d{2})\b"
)
_BSD_TIME_RE = re.compile(
    r"\b([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\b"
)


def _extract_timestamp(raw: str) -> datetime | None:
    m_iso = _ISO_TIMESTAMP_RE.search(raw)
    if m_iso:
        ts_str = m_iso.group(1)
        if "." in ts_str:
            base, frac = ts_str.split(".", 1)
            tz = ""
            if frac.endswith("Z"):
                frac = frac[:-1]
                tz = "Z"
            elif "+" in frac or "-" in frac:
                parts = re.split(r"([+-])", frac, maxsplit=1)
                frac = parts[0]
                tz = parts[1] + parts[2]
            frac = frac[:6]
            ts_str = f"{base}.{frac}{tz}"
        if ts_str.endswith("Z"):
            ts_str = ts_str[:-1] + "+00:00"
        try:
            return datetime.fromisoformat(ts_str)
        except Exception:
            pass

    m_dt = _DATE_TIME_RE.search(raw)
    if m_dt:
        try:
            return datetime.strptime(m_dt.group(1), "%b %d %Y %H:%M:%S").replace(tzinfo=timezone.utc)
        except Exception:
            pass

    m_bsd = _BSD_TIME_RE.search(raw)
    if m_bsd:
        try:
            today = datetime.now(timezone.utc)
            parsed = datetime.strptime(m_bsd.group(1), "%b %d %H:%M:%S")
            return parsed.replace(year=today.year, tzinfo=timezone.utc)
        except Exception:
            pass

    m_lead = _LEADING_OFFSET_RE.search(raw)
    if m_lead:
        try:
            t_part = m_lead.group(1)
            today = datetime.now(timezone.utc).date()
            if "." in t_part:
                dt = datetime.strptime(t_part, "%H:%M:%S.%f")
            else:
                dt = datetime.strptime(t_part, "%H:%M:%S")
            return dt.replace(year=today.year, month=today.month, day=today.day, tzinfo=timezone.utc)
        except Exception:
            pass

    return None


class GenericParser(BaseParser):
    format_name = "generic"

    def parse(self, raw: str) -> UnifiedEvent:
        return parse_generic_log(raw)


def parse_generic_log(raw: str) -> UnifiedEvent:
    mapped: Dict[str, Any] = {}
    unmapped: Dict[str, str] = {}

    ts = _extract_timestamp(raw)
    if ts:
        mapped["timestamp"] = ts

    stripped_raw = raw.strip()
    msg_candidate = _LEADING_OFFSET_RE.sub("", stripped_raw)
    comp_match = re.match(r"^([a-zA-Z0-9_-]+)\s{2,}(.*)$", msg_candidate)
    if comp_match:
        mapped.setdefault("log_name", comp_match.group(1))
        body_text = comp_match.group(2).strip()
    else:
        body_text = msg_candidate.strip()

    if body_text:
        mapped["message"] = body_text

    kv_matches = list(_KV_EQ_RE.finditer(raw)) + list(_KV_COLON_RE.finditer(raw))
    for m in kv_matches:
        key = m.group(1).lower()
        val = m.group(2).strip("\"'")

        if key.isdigit() or len(key) < 2:
            continue

        unified_key = COMMON_FIELD_MAP.get(key)
        if unified_key and unified_key not in mapped:
            if unified_key == "timestamp":
                parsed = parse_timestamp(val)
                if parsed:
                    mapped[unified_key] = parsed
                else:
                    unmapped[key] = val
            elif unified_key == "severity_id":
                iv = coerce_int(val)
                if iv is not None:
                    mapped[unified_key] = iv
                else:
                    unmapped[key] = val
            elif unified_key in ("src_port", "dst_port", "traffic_bytes", "traffic_packets"):
                iv = coerce_int(val)
                if iv is not None:
                    mapped[unified_key] = iv
                else:
                    unmapped[key] = val
            else:
                mapped[unified_key] = val
        elif unified_key is None:
            unmapped[key] = val

    if "src_ip" not in mapped:
        ips = _IPV4_RE.findall(raw)
        if ips:
            mapped["src_ip"] = ips[0]
            if len(ips) > 1 and "dst_ip" not in mapped:
                mapped["dst_ip"] = ips[1]

    enrich_classification(mapped)

    if unmapped:
        mapped["unmapped"] = unmapped

    mapped["log_format"] = "generic"
    mapped["raw_event"] = raw

    return UnifiedEvent(**mapped)
