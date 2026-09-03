"""
Format detector for ULPF.
Inspects raw log text and uses offline heuristic detection to route to the correct parser.
Optimized for zero-copy streaming and high-speed header sniffing.
"""

from __future__ import annotations

import csv
import io
import json
import re
from typing import Callable, Tuple

from app.models.event_schema import UnifiedEvent
from app.parsers.android_parser import parse_android_log
from app.parsers.cef_parser import parse_cef_log
from app.parsers.csv_parser import parse_csv_log
from app.parsers.generic_parser import parse_generic_log
from app.parsers.json_parser import parse_json_log
from app.parsers.leef_parser import parse_leef_log
from app.parsers.syslog_parser import parse_syslog_log
from app.parsers.xml_parser import parse_xml_log

ParserFn = Callable[[str], UnifiedEvent]


def _looks_like_android(s: str) -> bool:
    first_line = s.splitlines()[0].strip() if s else ""
    return bool(re.match(r"^\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d{3}\s+\d+\s+\d+\s+[VDIWEF]\s+[^:]+:", first_line))


def _looks_like_syslog_priority(s: str) -> bool:
    if not s.startswith("<"):
        return False
    close = s.find(">")
    if close == -1 or close > 5:
        return False
    return s[1:close].isdigit()


def _looks_like_syslog(s: str) -> bool:
    test = s
    if _looks_like_syslog_priority(test):
        close = test.index(">")
        test = test[close + 1:]
    return bool(re.match(r"^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s", test))


def _looks_like_csv(s: str) -> bool:
    lines = [l for l in s.splitlines() if l.strip()][:10]
    if len(lines) < 2:
        return False
    header_commas = lines[0].count(",")
    if header_commas < 2:
        return False
    check = lines[1: min(4, len(lines))]
    for line in check:
        if abs(line.count(",") - header_commas) > 1:
            return False
    try:
        sample_txt = "\n".join(lines)
        reader = csv.DictReader(io.StringIO(sample_txt))
        fields = reader.fieldnames
        if fields and len(fields) >= 3:
            return True
    except Exception:
        pass
    return False


def detect_format(raw: str) -> Tuple[str, ParserFn]:
    """Detect log format and return (format_name, parser_fn) in < 1ms."""
    # Sniff only the first 64KB for format detection
    sample = raw[:65536].strip()
    if not sample:
        return "generic", parse_generic_log

    # 1. Android Logcat
    if _looks_like_android(sample):
        return "android", parse_android_log

    # 2. CEF
    if sample.upper().startswith("CEF:"):
        return "cef", parse_cef_log

    # 3. LEEF
    if sample.upper().startswith("LEEF:"):
        return "leef", parse_leef_log

    # 4. JSON / JSON-Lines
    if sample.startswith("{") or sample.startswith("["):
        try:
            # If the entire sample or full string is valid JSON
            json.loads(raw if len(raw) < 100000 else sample)
            return "json", parse_json_log
        except json.JSONDecodeError:
            first_line = sample.splitlines()[0].strip()
            if first_line.startswith("{") and first_line.endswith("}"):
                try:
                    json.loads(first_line)
                    return "json", parse_json_log
                except json.JSONDecodeError:
                    pass

    # 5. XML
    if sample.startswith("<?xml") or (
        sample.startswith("<") and not sample[1:2].isdigit() and not _looks_like_syslog_priority(sample)
    ):
        try:
            import xml.etree.ElementTree as ET
            cleaned_check = re.sub(r"<!DOCTYPE[^>]*>", "", sample)
            ET.fromstring(cleaned_check)
            return "xml", parse_xml_log
        except Exception:
            pass

    # 6. Syslog
    if _looks_like_syslog(sample):
        return "syslog", parse_syslog_log

    # 7. CSV
    if _looks_like_csv(sample):
        return "csv", parse_csv_log

    # 8. Generic Fallback
    return "generic", parse_generic_log
