"""
Schema validator verifying UnifiedEvent compliance.
"""

from __future__ import annotations

from typing import Any, Dict, List

from app.models.event_schema import UnifiedEvent
from app.validation.types import is_valid_ip, is_valid_port


def validate_unified_event(event: UnifiedEvent) -> List[str]:
    """Validate event data against security standards and return list of validation warnings/errors."""
    errors: List[str] = []

    if not event.event_id:
        errors.append("Missing required field: event_id")

    if not event.raw_event or not event.raw_event.strip():
        errors.append("Lossless violation: raw_event must not be empty")

    if event.src_ip and not is_valid_ip(event.src_ip):
        errors.append(f"Invalid src_ip format: {event.src_ip}")

    if event.dst_ip and not is_valid_ip(event.dst_ip):
        errors.append(f"Invalid dst_ip format: {event.dst_ip}")

    if event.src_port and not is_valid_port(event.src_port):
        errors.append(f"Invalid src_port out of range: {event.src_port}")

    if event.dst_port and not is_valid_port(event.dst_port):
        errors.append(f"Invalid dst_port out of range: {event.dst_port}")

    return errors
