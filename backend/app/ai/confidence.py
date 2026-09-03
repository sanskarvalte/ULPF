"""
Confidence scoring calculations and Product Signature Cross-Validation for AI schema inference.
"""

from __future__ import annotations

import re
from typing import Any, Dict, Optional, Tuple

# Known product signature markers for secondary cross-validation
PRODUCT_SIGNATURE_MARKERS: Dict[str, list[re.Pattern]] = {
    "log4j": [
        re.compile(r"\b(?:com|org|net|io|edu|gov)\.[a-zA-Z0-9_.]+\b"),
        re.compile(r"\[[a-zA-Z0-9_\-\s]+\]\s+(?:INFO|WARN|ERROR|DEBUG|TRACE|FATAL)\b"),
        re.compile(r"%\d*[-+]?\d*[a-zA-Z]"),
    ],
    "apache": [
        re.compile(r"\bHTTP/[0-9.]+\b", re.IGNORECASE),
        re.compile(r"\[client\s+(?:[0-9]{1,3}\.){3}[0-9]{1,3}\]", re.IGNORECASE),
        re.compile(r"\b(?:GET|POST|PUT|DELETE|HEAD|OPTIONS)\s+\S+\s+HTTP/", re.IGNORECASE),
        re.compile(r"\bapache\b|\bhttpd\b", re.IGNORECASE),
    ],
    "nginx": [
        re.compile(r"\bnginx\b", re.IGNORECASE),
        re.compile(r"\bHTTP/[0-9.]+\b", re.IGNORECASE),
        re.compile(r"\bclient:\s+[0-9.]+", re.IGNORECASE),
        re.compile(r"\bupstream:\s+", re.IGNORECASE),
    ],
    "mysql": [
        re.compile(r"\b(?:mysql|mysqld|mariadb)\b", re.IGNORECASE),
        re.compile(r"\[(?:Note|Warning|ERROR)\]"),
        re.compile(r"\bInnoDB:\s+", re.IGNORECASE),
    ],
    "postgres": [
        re.compile(r"\b(?:postgres|postgresql|psql)\b", re.IGNORECASE),
        re.compile(r"\b(?:LOG|STATEMENT|FATAL|DETAIL):\s+"),
    ],
    "cisco": [
        re.compile(r"%(?:ASA|PIX|FWSM|IOS)-\d+-\d+", re.IGNORECASE),
        re.compile(r"\bcisco\b", re.IGNORECASE),
    ],
    "windows": [
        re.compile(r"\b(?:EventID|Microsoft-Windows|Security-Auditing)\b", re.IGNORECASE),
        re.compile(r"<Event\b|<EventID\b"),
    ],
    "logfmt": [
        re.compile(r"\b(?:dyno|connect|service|status|fwd|host|path|method|at|bytes|code|request_id)=[a-zA-Z0-9_\"'/\-.:]+"),
    ],
}


def validate_product_signature(
    raw_log: str,
    suggested_vendor: Optional[str],
    suggested_product: Optional[str],
    suggested_format: Optional[str],
    claimed_confidence: float,
) -> Tuple[Optional[str], Optional[str], str, float]:
    """
    Secondary validation pass: Cross-checks suggested vendor/product/format against
    known signature markers. If signature markers are absent in raw_log, downgrades
    confidence (<=0.3) and resets vendor/product to prevent confidently false classifications.
    
    Returns:
        (validated_vendor, validated_product, validated_format, validated_confidence)
    """
    raw = raw_log.strip()
    prod_lower = (suggested_product or "").lower()
    vendor_lower = (suggested_vendor or "").lower()
    fmt_lower = (suggested_format or "").lower()
    combined_name = f"{vendor_lower} {prod_lower} {fmt_lower}"

    # Check if log looks like logfmt (e.g. Heroku router logs: at=info method=GET path=/ ...)
    is_logfmt = bool(re.search(r'\b(?:at|method|path|host|fwd|dyno|connect|service|status|bytes)=[^\s]+', raw))
    is_semicolon_kv = bool(";" in raw and (":" in raw or "=" in raw))

    # 1. Cross-check specific product signatures
    for product_key, patterns in PRODUCT_SIGNATURE_MARKERS.items():
        if product_key in combined_name:
            # Check if any signature pattern matches in raw log
            has_marker = any(p.search(raw) for p in patterns)
            if not has_marker:
                # Signature mismatch! LLM hallucinated a specific product without evidence.
                if is_logfmt:
                    return None, None, "logfmt", 0.35
                if is_semicolon_kv:
                    return None, None, "custom_key_value", 0.3
                return None, None, "unknown_custom", min(claimed_confidence, 0.25)

    # 2. If suggested format is generic or unknown but contains logfmt structure
    if is_logfmt and ("logfmt" in fmt_lower or "custom" in fmt_lower or "unknown" in fmt_lower):
        return "Heroku" if "heroku" in raw.lower() or "dyno=" in raw.lower() else None, "Router" if "router" in raw.lower() else None, "logfmt", max(claimed_confidence, 0.8)

    # 3. If suggested format is generic or unknown but contains semicolon-delimited key-value structure
    if is_semicolon_kv and ("custom" in fmt_lower or "unknown" in fmt_lower or not suggested_format):
        return None, None, "custom_key_value", max(claimed_confidence, 0.6)

    return suggested_vendor, suggested_product, suggested_format or "unknown_custom", claimed_confidence


def calculate_field_confidence(source_key: str, target_ocsf_key: str, sample_value: Any) -> float:
    """Calculates confidence score (0.0 to 1.0) for mapping a source attribute to an OCSF attribute."""
    src = source_key.lower().replace("_", "").replace("-", "")
    tgt = target_ocsf_key.lower().replace("_", "").replace("-", "")

    # Exact string match
    if src == tgt:
        return 1.0

    # Common synonym matches
    synonyms = {
        "srcip": ["sourceip", "srcaddr", "clientip", "src", "fwd"],
        "dstip": ["destinationip", "dstaddr", "serverip", "dst", "host"],
        "user": ["username", "actor", "account", "login"],
        "timestamp": ["time", "eventtime", "datetime", "date", "ts"],
        "srcport": ["sport", "sourceport"],
        "dstport": ["dport", "destinationport"],
        "statuscode": ["status", "statuscode", "code"],
        "trafficbytes": ["bytes", "size", "bytesreceived", "bytessent"],
        "servicename": ["svc", "service", "app", "application"],
    }

    if tgt in synonyms and src in synonyms[tgt]:
        return 0.95

    # Substring inclusion
    if tgt in src or src in tgt:
        return 0.80

    return 0.50
