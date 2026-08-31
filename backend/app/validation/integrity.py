"""
Log integrity verification module.
Verifies SHA-256 digests and lossless raw event preservation.
"""

from __future__ import annotations

import hashlib
from typing import Optional

from app.models.event_schema import UnifiedEvent


def verify_raw_integrity(raw_text: str, expected_hash: str) -> bool:
    """Verifies that the raw log string matches its stored SHA-256 hash."""
    computed = hashlib.sha256(raw_text.encode("utf-8")).hexdigest()
    return computed == expected_hash


def verify_event_integrity(event: UnifiedEvent) -> bool:
    """Verifies that the event's raw_event matches raw_event_id if available."""
    if not event.raw_event_id:
        return True
    return verify_raw_integrity(event.raw_event, event.raw_event_id)
