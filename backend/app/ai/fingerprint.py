"""
Structural Log Fingerprinting Engine (Node 5).
Collapses dynamic tokens (IPs, timestamps, UUIDs, numbers, durations, quoted strings, key-value values)
to compute a deterministic structural hash and matching regex template.
"""

from __future__ import annotations

import hashlib
import re
from typing import Tuple

_QUOTED_STR_RE = re.compile(r'"(?:[^"\\]|\\.)*"|\'(?:[^\'\\]|\\.)*\'')
_TIMESTAMP_RE = re.compile(
    r"\b\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b|"
    r"\b[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\b|"
    r"\b\d{2}/\w+/\d{4}:\d{2}:\d{2}:\d{2}(?:\s+[+-]\d{4})?\b"
)
_COMPACT_TIMESTAMP_RE = re.compile(r"^\d{14}|\b20\d{12}\b")
_IP_RE = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b|[0-9a-fA-F:]{7,39}")
_UUID_HEX_RE = re.compile(r"\b[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\b|\b[0-9a-fA-F]{16,64}\b")
_DURATION_NUM_RE = re.compile(r"\b\d+(?:\.\d+)?(?:ms|s|us|m|h|bytes|b|kb|mb|gb)?\b", re.IGNORECASE)
_SEMICOLON_FREE_MSG_RE = re.compile(r'(?<=msg:)([^;]+)')
_KV_VAL_RE = re.compile(r'(?<=[=:])([a-zA-Z0-9_\-\.\@\/]+)')
_HTTP_USER_RE = re.compile(r'(?<=\s-\s)[a-zA-Z0-9_\-]+(?=\s\[)')


def compute_log_fingerprint(raw_line: str) -> Tuple[str, str, str]:
    """
    Compute structural template, regex pattern, and SHA-256 fingerprint hash.
    
    Returns:
        (structural_template, regex_pattern, fingerprint_hash)
    """
    line = raw_line.strip()
    if not line:
        return "", "", hashlib.sha256(b"").hexdigest()

    # Step 1: Quoted strings & timestamps first
    s = _COMPACT_TIMESTAMP_RE.sub("<TS>", line)
    s = _QUOTED_STR_RE.sub("<STR>", s)
    s = _TIMESTAMP_RE.sub("<TS>", s)
    s = _IP_RE.sub("<IP>", s)
    s = _UUID_HEX_RE.sub("<HEX>", s)
    s = _DURATION_NUM_RE.sub("<NUM>", s)
    s = _HTTP_USER_RE.sub("<USER>", s)
    s = re.sub(r"msg:[^;]+", "msg:<VAL>", s)
    s = _KV_VAL_RE.sub("<VAL>", s)
    
    # Step 2: Handle pipe-delimited proprietary logs: if 3+ pipes, normalize variable column slots
    if s.count("|") >= 3:
        parts = s.split("|")
        norm_parts = []
        for idx, p in enumerate(parts):
            p_s = p.strip()
            if p_s in ("<TS>", "<IP>", "<HEX>", "<NUM>", "<STR>", "<VAL>", "<USER>"):
                norm_parts.append(p_s)
            elif idx == 1 and re.match(r"^[A-Z0-9_\-]+$", p_s):
                # Service identifier like AUTH-SVC
                norm_parts.append(p_s)
            else:
                norm_parts.append("<VAL>")
        s = "|".join(norm_parts)

    # Step 3: Handle fixed-width positional logs with multiple internal spaces (e.g. <TS>AUTH01JDOE LOGIN SUCCESS <NUM>)
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
        .replace(r"\<IP\>", r"(?:[0-9]{1,3}\.){3}[0-9]{1,3}")
        .replace(r"\<HEX\>", r"[0-9a-zA-Z\-]+")
        .replace(r"\<STR\>", r'".*?"|\'.*?\'|<STR>')
        .replace(r"\<NUM\>", r"\d+.*?")
        .replace(r"\<VAL\>", r"[^\s|;]+")
        .replace(r"\<USER\>", r"[a-zA-Z0-9_\-]+")
        .replace(r"\<FIXED_COL\>", r"[a-zA-Z0-9_\-]+")
        .replace(r"\<ACTION\>", r"[a-zA-Z0-9_\-]+")
        .replace(r"\<STATUS\>", r"[a-zA-Z0-9_\-]+")
        + "$"
    )

    return template, regex_pattern, fingerprint_hash
