"""
Hadoop / HDFS / YARN Log Parser for ULPF.
Supports standard LogHub Hadoop, MRAppMaster, and HDFS daemon log formats.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from app.models.event_schema import UnifiedEvent
from app.normalization.field_mapping import coerce_int, parse_timestamp
from app.parsers.base import BaseParser

_HADOOP_RE = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}[,\.]\d{3}|\d{6}\s+\d{6}(?:\s+\d+)?)\s+(?P<level>[A-Z]+)\s+(?:\[(?P<thread>[^\]]+)\]\s+)?(?P<component>[^:]+):\s*(?P<message>.*)$",
    re.DOTALL,
)

_LEVEL_MAP = {
    "INFO": ("Informational", 1),
    "WARN": ("Medium", 3),
    "WARNING": ("Medium", 3),
    "ERROR": ("High", 4),
    "FATAL": ("Critical", 5),
    "CRITICAL": ("Critical", 5),
    "DEBUG": ("Informational", 1),
    "TRACE": ("Informational", 1),
}


def _parse_hadoop_timestamp(ts_str: str) -> Optional[datetime]:
    s = ts_str.strip()
    if "," in s:
        try:
            return datetime.strptime(s, "%Y-%m-%d %H:%M:%S,%f").replace(tzinfo=timezone.utc)
        except Exception:
            pass
    if "." in s:
        try:
            return datetime.strptime(s, "%Y-%m-%d %H:%M:%S.%f").replace(tzinfo=timezone.utc)
        except Exception:
            pass
    # Check HDFS compact format: '081109 203615' or '081109 203615 148'
    parts = s.split()
    if len(parts) >= 2 and len(parts[0]) == 6 and len(parts[1]) == 6:
        try:
            return datetime.strptime(f"{parts[0]} {parts[1]}", "%y%m%d %H%M%S").replace(tzinfo=timezone.utc)
        except Exception:
            pass
    return parse_timestamp(s)


def parse_hadoop_log(raw: str) -> UnifiedEvent:
    raw_clean = raw.strip()
    m = _HADOOP_RE.match(raw_clean)
    if not m:
        from app.parsers.generic_parser import parse_generic_log
        ev = parse_generic_log(raw)
        ev.log_format = "hadoop"
        ev.vendor = "Apache"
        ev.product = "Hadoop"
        return ev

    gd = m.groupdict()
    mapped: Dict[str, Any] = {}
    unmapped: Dict[str, Any] = {}

    # Timestamp
    time_str = gd.get("timestamp")
    if time_str:
        mapped["timestamp"] = _parse_hadoop_timestamp(time_str)

    # Severity
    level = (gd.get("level") or "INFO").upper()
    sev_label, sev_id = _LEVEL_MAP.get(level, ("Informational", 1))
    mapped["severity"] = sev_label
    mapped["severity_id"] = sev_id

    # Component
    comp = (gd.get("component") or "").strip()
    if comp:
        mapped["log_name"] = comp

    # Thread
    thread = gd.get("thread")
    if thread:
        unmapped["thread"] = thread

    # Message
    msg = (gd.get("message") or "").strip()
    mapped["message"] = msg

    # Vendor & Taxonomy
    mapped["vendor"] = "Apache"
    mapped["product"] = "Hadoop"
    mapped["category_name"] = "Application Activity"
    mapped["category_uid"] = 6
    mapped["class_name"] = "Application Lifecycle"
    mapped["class_uid"] = 6001
    mapped["activity_name"] = "Log"
    mapped["activity_id"] = 1

    # Extract block ID or app ID if present
    block_match = re.search(r"\b(blk_-?\d+)\b", msg)
    if block_match:
        unmapped["block_id"] = block_match.group(1)
    app_match = re.search(r"\b(application_\d+_\d+|appattempt_\d+_\d+_\d+)\b", msg)
    if app_match:
        unmapped["application_id"] = app_match.group(1)

    mapped["log_format"] = "hadoop"
    mapped["raw_event"] = raw
    if unmapped:
        mapped["unmapped"] = unmapped

    return UnifiedEvent(**mapped)


class HadoopParser(BaseParser):
    format_name = "hadoop"

    def parse(self, raw: str) -> UnifiedEvent:
        return parse_hadoop_log(raw)
