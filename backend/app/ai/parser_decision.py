"""
ULPF parser decision logic.

Determines whether a parser already exists for a canonical format fingerprint.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from app.parsers.registry import get_entry
from app.ai.fingerprint import create_fingerprint


def find_saved_parser(
    canonical_spec: Dict[str, Any],
) -> Optional[Dict[str, Any]]:
    """
    Look for an already registered parser.
    Returns the complete registry entry if found.
    Returns None if no parser exists.
    """
    fingerprint = create_fingerprint(canonical_spec)
    entry = get_entry(fingerprint)

    if entry is None:
        return None

    if entry.get("status") != "active":
        return None

    return entry
