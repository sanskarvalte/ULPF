"""
Format Matcher & Signature Registry (Node 3).
Executes cheap, deterministic signature checks against a runtime-mutable registry.
Zero LLM calls are ever made in this module. Optimized for offline header sniffing and fast detection.
"""

from __future__ import annotations

import csv
import io
import json
import re
from typing import Callable, Dict, List, Optional, Tuple

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
MatcherFn = Callable[[str], bool]


# ── Built-in Signature Matchers ─────────────────────────────────────────

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


def _looks_like_cef(s: str) -> bool:
    stripped = s.strip()
    if not re.match(r"^CEF:\s*\d+\|", stripped, re.IGNORECASE):
        return False
    return stripped.count("|") >= 6


def _looks_like_leef(s: str) -> bool:
    stripped = s.strip()
    if not re.match(r"^LEEF:\s*[\d\.]+\|", stripped, re.IGNORECASE):
        return False
    return stripped.count("|") >= 4


def _looks_like_syslog(s: str) -> bool:
    test = s.strip()
    if _looks_like_syslog_priority(test):
        close = test.index(">")
        test = test[close + 1:].strip()
        # Handle RFC 5424 version prefix like "1 "
        if re.match(r"^\d+\s+", test):
            test = re.sub(r"^\d+\s+", "", test).strip()

    # Cisco ASA Syslog (supports %ASA-level-code, %ASA-session-level-code, optional colon)
    if re.search(r"%ASA-(?:session-)?\d-\d{6}", test):
        return True

    # pfSense filterlog
    if "filterlog:" in test:
        return True

    # Fortinet Syslog
    if "devname=" in test or ("type=traffic" in test and "subtype=" in test):
        return True

    # RFC 3164 BSD syslog (e.g. "Jun 14 15:16:01", "Jun  9 06:06:06", "Apr 15 2013 09:36:50:")
    if re.match(r"^[A-Z][a-z]{2}\s+\d{1,2}(?:\s+\d{4})?\s+\d{2}:\d{2}:\d{2}(?::|\s)", test):
        return True

    # RFC 5424 / ISO timestamp syslog with process/message marker or PRI header
    if re.match(r"^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\s+\S+\s+(?:\[.*\]|[^\[:\s]+(?:\[\d+\])?(?::|\s+\[|\s+\d+\s+))", test):
        return True

    return False


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


def _looks_like_json(s: str) -> bool:
    sample = s[:65536].strip()
    if sample.startswith("{") or sample.startswith("["):
        try:
            parsed = json.loads(s if len(s) < 100000 else sample)
            return isinstance(parsed, (dict, list))
        except (json.JSONDecodeError, ValueError):
            first_line = sample.splitlines()[0].strip()
            if first_line.startswith("{") and first_line.endswith("}"):
                try:
                    parsed = json.loads(first_line)
                    return isinstance(parsed, dict)
                except (json.JSONDecodeError, ValueError):
                    pass
    return False


def _looks_like_xml(s: str) -> bool:
    sample = s[:65536].strip()
    if sample.startswith("<?xml") or (
        sample.startswith("<") and not sample[1:2].isdigit() and not _looks_like_syslog_priority(sample)
    ):
        try:
            import xml.etree.ElementTree as ET
            cleaned_check = re.sub(r"<!DOCTYPE[^>]*>", "", sample)
            ET.fromstring(cleaned_check)
            return True
        except Exception:
            pass
    return False


# ── Runtime-Mutable Format Matcher Registry ────────────────────────────

class FormatMatcherRegistry:
    """Runtime-mutable registry of format signatures and deterministic parser functions."""

    def __init__(self):
        # List of tuples: (format_name, matcher_fn, parser_fn)
        self._entries: List[Tuple[str, MatcherFn, ParserFn]] = []
        self._custom_format_names: set[str] = set()
        self._register_builtins()

    def _register_builtins(self):
        # Priority order for deterministic checking
        self.register("android", _looks_like_android, parse_android_log)
        self.register("cef", _looks_like_cef, parse_cef_log)
        self.register("leef", _looks_like_leef, parse_leef_log)
        self.register("json", _looks_like_json, parse_json_log)
        self.register("xml", _looks_like_xml, parse_xml_log)
        self.register("syslog", _looks_like_syslog, parse_syslog_log)
        self.register("csv", _looks_like_csv, parse_csv_log)

    def register(
        self,
        format_name: str,
        matcher_fn: MatcherFn,
        parser_fn: ParserFn,
        is_custom: bool = False,
    ) -> None:
        """Register or update a format matcher signature."""
        fmt_lower = format_name.lower()
        # Remove existing if overwriting
        self._entries = [e for e in self._entries if e[0].lower() != fmt_lower]
        # Insert custom matchers at the front for highest priority matching
        if is_custom:
            self._entries.insert(0, (fmt_lower, matcher_fn, parser_fn))
            self._custom_format_names.add(fmt_lower)
        else:
            self._entries.append((fmt_lower, matcher_fn, parser_fn))

    def match(self, raw_text: str) -> Tuple[bool, str, ParserFn]:
        """
        Check raw text against all registered signatures.
        Returns: (is_known: bool, format_name: str, parser_fn: Callable)
        """
        stripped = raw_text.strip()
        for fmt_name, matcher_fn, parser_fn in self._entries:
            try:
                if matcher_fn(stripped):
                    return True, fmt_name, parser_fn
            except Exception:
                continue
        # Unknown format -> returns False and generic fallback
        return False, "unknown", parse_generic_log

    def list_formats(self) -> List[str]:
        return [e[0] for e in self._entries]


# Global singleton registry
matcher_registry = FormatMatcherRegistry()


def get_default_registry() -> FormatMatcherRegistry:
    """Return the global singleton format matcher registry."""
    return matcher_registry


def match_format(raw_text: str) -> Tuple[bool, str, ParserFn]:
    """Single dispatch point: runs cheap deterministic signature checks."""
    return matcher_registry.match(raw_text)


def detect_format(raw_text: str) -> Tuple[str, ParserFn]:
    """Compatibility wrapper returning (format_name, parser_fn)."""
    is_known, fmt_name, parser_fn = matcher_registry.match(raw_text)
    if is_known:
        return fmt_name, parser_fn
    return "generic", parse_generic_log


def register_custom_parser_matcher(
    format_name: str,
    pattern_regex: str,
    field_mapping: Dict[str, str],
    vendor: Optional[str] = None,
    product: Optional[str] = None,
) -> None:
    """Dynamically register an approved custom regex pattern and parser into the runtime registry."""
    from app.parsers.dynamic_parser import DynamicPatternParser
    compiled_re = re.compile(pattern_regex, re.DOTALL | re.IGNORECASE)
    parser_instance = DynamicPatternParser(format_name, pattern_regex, field_mapping, vendor, product)

    def custom_matcher(raw: str) -> bool:
        return bool(compiled_re.search(raw.strip()))

    matcher_registry.register(
        format_name=format_name,
        matcher_fn=custom_matcher,
        parser_fn=parser_instance.parse,
        is_custom=True,
    )


def load_and_register_all_custom_parsers(conn=None) -> int:
    """Load all approved custom parsers from persistent storage and register them at startup."""
    try:
        from app.storage.custom_parsers import list_custom_parsers
        custom_list = list_custom_parsers(conn=conn)
        count = 0
        for cp in custom_list:
            register_custom_parser_matcher(
                format_name=cp["format_name"],
                pattern_regex=cp["pattern_regex"],
                field_mapping=cp["field_mapping"],
            )
            count += 1
        return count
    except Exception:
        return 0

