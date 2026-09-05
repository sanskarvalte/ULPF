"""
Structural Log Fingerprinting Engine (Node 5).
Collapses dynamic tokens (IPs, IPv6, timestamps, UUIDs, hashes, URLs, numbers,
durations, quoted strings, user IDs, key-value values) while preserving stable
literal tokens to compute deterministic structural fingerprints.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any, Dict, List, Tuple

# Pre-compiled regular expressions for token collapsing (order of application matters)
_QUOTED_STR_RE = re.compile(r'"(?:[^"\\]|\\.)*"|\'(?:[^\'\\]|\\.)*\'')
_URL_RE = re.compile(r'\b(?:https?|ftp)://[^\s"\'<>]+|\b/(?:api|v\d+|auth|app)/[^\s"\'<>]+', re.IGNORECASE)

# Timestamps (ISO8601 with T or space, BSD syslog, Apache combined, compact)
_TIMESTAMP_RE = re.compile(
    r"\b\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b|"
    r"\b[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?\b|"
    r"\b\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2}(?:\s+[+-]\d{4})?\b"
)
_COMPACT_TIMESTAMP_RE = re.compile(r"^\d{14}|\b20\d{12}\b")

# IPv4 and IPv6
_IPV4_RE = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
_IPV6_RE = re.compile(
    r"(?<![a-zA-Z0-9_])(?:(?:[0-9a-fA-F]{1,4}:){2,7}(?:[0-9a-fA-F]{1,4})?|fe80::[0-9a-fA-F:]*|::1|::|(?:::|:[0-9a-fA-F]{1,4}){1,7})(?![a-zA-Z0-9_])"
)

# UUIDs and cryptographic hashes
_UUID_RE = re.compile(r"\b[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\b", re.IGNORECASE)
_HASH_HEX_RE = re.compile(r"\b[0-9a-fA-F]{32,64}\b")

# Numbers: negative, decimals, integers with units
_NEGATIVE_DECIMAL_RE = re.compile(r"(?<![a-zA-Z0-9_])-?\b\d+\.\d+\b")
_NEGATIVE_INT_RE = re.compile(r"(?<![a-zA-Z0-9_])-?\b\d+(?:\.\d+)?(?:ms|s|us|m|h|bytes|b|kb|mb|gb)?\b", re.IGNORECASE)

# Key-value identifiers and user fields
_USER_KV_RE = re.compile(r'(?<=[=:])([a-zA-Z0-9_\-\.\@]+@[a-zA-Z0-9_\-\.]+)')
_HTTP_USER_RE = re.compile(r'(?<=\s-\s)[a-zA-Z0-9_\-]+(?=\s\[)')
_SEMICOLON_FREE_MSG_RE = re.compile(r'(?<=msg:)([^;]+)')
_KV_VAL_RE = re.compile(r'(?<=[=:])([a-zA-Z0-9_\-\.\@\/]+)')


def compute_log_fingerprint(raw_line: str) -> Tuple[str, str, str]:
    """
    Compute structural template, regex pattern, and SHA-256 fingerprint hash.
    Never uses actual dynamic values as the identity of the template.
    
    Returns:
        (structural_template, regex_pattern, fingerprint_hash)
    """
    line = raw_line.strip()
    if not line:
        return "", "", hashlib.sha256(b"").hexdigest()

    # Step 1: Collapse URLs and quoted strings first to prevent internal punctuation collision
    s = _COMPACT_TIMESTAMP_RE.sub("<TS>", line)
    s = _QUOTED_STR_RE.sub("<STR>", s)
    s = _URL_RE.sub("<URL>", s)
    s = _TIMESTAMP_RE.sub("<TS>", s)
    s = _UUID_RE.sub("<UUID>", s)
    s = _HASH_HEX_RE.sub("<HEX>", s)
    s = _IPV6_RE.sub("<IP>", s)
    s = _IPV4_RE.sub("<IP>", s)
    s = _NEGATIVE_DECIMAL_RE.sub("<NUM>", s)
    s = _NEGATIVE_INT_RE.sub("<NUM>", s)
    s = _HTTP_USER_RE.sub("<USER>", s)
    s = re.sub(r"msg:[^;]+", "msg:<VAL>", s)
    s = _USER_KV_RE.sub("<USER>", s)
    s = _KV_VAL_RE.sub("<VAL>", s)

    # Step 2: Handle pipe-delimited proprietary logs: normalize variable column slots
    if s.count("|") >= 3:
        parts = s.split("|")
        norm_parts = []
        for idx, p in enumerate(parts):
            p_s = p.strip()
            if p_s in ("<TS>", "<IP>", "<HEX>", "<UUID>", "<URL>", "<NUM>", "<STR>", "<VAL>", "<USER>"):
                norm_parts.append(p_s)
            elif idx == 1 and re.match(r"^[A-Z0-9_\-]+$", p_s):
                # Service identifier like AUTH-SVC
                norm_parts.append(p_s)
            else:
                norm_parts.append("<VAL>")
        s = "|".join(norm_parts)

    # Step 3: Handle fixed-width positional logs with multiple internal spaces
    if re.match(r"^<TS>[A-Z0-9]+\s+[A-Z0-9]+\s+[A-Z0-9]+\s+<NUM>$", s):
        s = "<TS><FIXED_COL> <ACTION> <STATUS> <NUM>"

    # Normalize whitespace
    template = " ".join(s.split())
    fingerprint_hash = hashlib.sha256(template.encode("utf-8")).hexdigest()[:16]

    # Step 4: Build a flexible regex matcher for this template
    escaped = re.escape(template)
    regex_pattern = (
        "^"
        + escaped
        .replace(r"\<TS\>", r".*?")
        .replace(r"\<IP\>", r"(?:(?:[0-9]{1,3}\.){3}[0-9]{1,3}|[0-9a-fA-F:]{2,39})")
        .replace(r"\<HEX\>", r"[0-9a-zA-Z\-]+")
        .replace(r"\<UUID\>", r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}")
        .replace(r"\<URL\>", r"\S+")
        .replace(r"\<STR\>", r'".*?"|\'.*?\'|<STR>')
        .replace(r"\<NUM\>", r"-?\d+(?:\.\d+)?.*?")
        .replace(r"\<VAL\>", r"[^\s|;]+")
        .replace(r"\<USER\>", r"[a-zA-Z0-9_\-\.\@]+")
        .replace(r"\<FIXED_COL\>", r"[a-zA-Z0-9_\-]+")
        .replace(r"\<ACTION\>", r"[a-zA-Z0-9_\-]+")
        .replace(r"\<STATUS\>", r"[a-zA-Z0-9_\-]+")
        + "$"
    )

    return template, regex_pattern, fingerprint_hash


def group_templates_by_fingerprint(
    raw_lines: List[str],
) -> Dict[str, Dict[str, Any]]:
    """
    Group raw log lines by their structural template fingerprint.
    
    Returns:
        Dict mapping fingerprint_hash -> {
            "fingerprint": str,
            "template": str,
            "regex_pattern": str,
            "count": int,
            "samples": List[str]
        }
    """
    groups: Dict[str, Dict[str, Any]] = {}
    for line in raw_lines:
        line_clean = line.strip()
        if not line_clean:
            continue
        tmpl, regex, fp = compute_log_fingerprint(line_clean)
        if fp not in groups:
            groups[fp] = {
                "fingerprint": fp,
                "template": tmpl,
                "regex_pattern": regex,
                "count": 0,
                "samples": [],
            }
        groups[fp]["count"] += 1
        if len(groups[fp]["samples"]) < 20:
            groups[fp]["samples"].append(line_clean)
    return groups


def create_fingerprint(
    canonical_spec: dict[str, Any],
) -> str:
    """
    Create a stable SHA-256 fingerprint from a canonical format spec.
    """
    import json

    fingerprint_data = {
        "format_family": canonical_spec.get("format_family", "unknown"),
        "delimiter": canonical_spec.get("delimiter", " "),
        "timestamp_pattern": canonical_spec.get("timestamp_pattern", "unknown"),
        "fields": canonical_spec.get("fields", []),
        "optional_fields": canonical_spec.get("optional_fields", []),
        "structure": canonical_spec.get("structure", []),
    }

    canonical_json = json.dumps(
        fingerprint_data,
        sort_keys=True,
        separators=(",", ":"),
    )

    return hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()


create_spec_fingerprint = create_fingerprint
