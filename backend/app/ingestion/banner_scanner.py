"""
Self-declared banner and stream metadata scanner (Node 1 helper).
Scans early log stream lines for vendor/product banners and anchor timestamps.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from app.mapping.yaml_loader import load_yaml_file
from app.normalization.field_mapping import parse_timestamp

_BANNERS_YAML = Path(__file__).resolve().parent.parent.parent.parent / "mappings" / "banners.yaml"
_CACHED_BANNERS: Optional[List[Dict[str, Any]]] = None


def get_banner_rules() -> List[Dict[str, Any]]:
    """Load banner patterns from YAML configuration."""
    global _CACHED_BANNERS
    if _CACHED_BANNERS is not None:
        return _CACHED_BANNERS
    data = load_yaml_file(_BANNERS_YAML)
    rules = data.get("banners") or []
    # If list is parsed as list of dicts or wrapped
    if isinstance(rules, list):
        _CACHED_BANNERS = rules
    else:
        _CACHED_BANNERS = []
    return _CACHED_BANNERS


def scan_stream_header(lines: List[str], max_lines: int = 25) -> Dict[str, Any]:
    """
    Scan first N lines of a log file/stream for:
    1. Self-declared product/vendor banners & versions.
    2. Anchor absolute timestamp (for relative timestamp conversion).
    """
    meta: Dict[str, Any] = {}
    sample_lines = lines[:max_lines]
    combined_header = "\n".join(sample_lines)

    # 1. Scan for Anchor Timestamp
    anchor_patterns = [
        r"(?:Log\s+opened|Started\s+at|Session\s+Start|Start-Date:)\s*([0-9]{4}-[0-9]{2}-[0-9]{2}[T\s][0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?(?:Z|[+-][0-9]{2}:?[0-9]{2})?)",
        r"([0-9]{4}-[0-9]{2}-[0-9]{2}[T\s][0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?(?:Z|[+-][0-9]{2}:?[0-9]{2})?)",
    ]
    for p in anchor_patterns:
        m = re.search(p, combined_header, re.IGNORECASE)
        if m:
            parsed = parse_timestamp(m.group(1))
            if parsed:
                meta["anchor_timestamp"] = parsed
                break

    # 2. Scan for Self-declared Vendor & Product Banners
    rules = get_banner_rules()
    for rule in rules:
        pat = rule.get("pattern")
        if not pat:
            continue
        m = re.search(pat, combined_header, re.IGNORECASE)
        if m:
            if rule.get("vendor"):
                meta["vendor"] = rule["vendor"]
            elif rule.get("vendor_group"):
                meta["vendor"] = m.group(rule["vendor_group"])

            if rule.get("product"):
                meta["product"] = rule["product"]
            elif rule.get("product_group"):
                meta["product"] = m.group(rule["product_group"])

            if rule.get("version_group"):
                try:
                    meta["product_version"] = m.group(rule["version_group"])
                except IndexError:
                    pass
            break

    # Fallback heuristic for VirtualBox header if YAML isn't loaded
    if not meta.get("product"):
        vbox_m = re.search(r"VirtualBox(?:\s+Base)?\s+([0-9]+\.[0-9]+\.[0-9]+)", combined_header)
        if vbox_m:
            meta["vendor"] = "Oracle"
            meta["product"] = "VirtualBox"
            meta["product_version"] = vbox_m.group(1)

    return meta
