"""
Confidence scoring calculations for AI schema inference.
"""

from __future__ import annotations

from typing import Any, Dict


def calculate_field_confidence(source_key: str, target_ocsf_key: str, sample_value: Any) -> float:
    """Calculates confidence score (0.0 to 1.0) for mapping a source attribute to an OCSF attribute."""
    src = source_key.lower().replace("_", "").replace("-", "")
    tgt = target_ocsf_key.lower().replace("_", "").replace("-", "")

    # Exact string match
    if src == tgt:
        return 1.0

    # Common synonym matches
    synonyms = {
        "srcip": ["sourceip", "srcaddr", "clientip", "src"],
        "dstip": ["destinationip", "dstaddr", "serverip", "dst"],
        "user": ["username", "actor", "account", "login"],
        "timestamp": ["time", "eventtime", "datetime", "date"],
        "srcport": ["sport", "sourceport"],
        "dstport": ["dport", "destinationport"],
    }

    if tgt in synonyms and src in synonyms[tgt]:
        return 0.95

    # Substring inclusion
    if tgt in src or src in tgt:
        return 0.80

    return 0.50
