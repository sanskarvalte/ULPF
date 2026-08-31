"""
Type and format validation for normalized security fields.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Optional


def is_valid_ip(ip_str: Optional[str]) -> bool:
    """Validate IPv4 or IPv6 format."""
    if not ip_str:
        return False
    try:
        ipaddress.ip_address(ip_str.strip())
        return True
    except ValueError:
        return False


def is_valid_port(port: Optional[int]) -> bool:
    """Validate TCP/UDP port range (1 - 65535)."""
    if port is None:
        return False
    return 1 <= port <= 65535


def sanitize_string(val: Optional[str]) -> Optional[str]:
    """Strip dangerous characters or excess whitespace."""
    if not val:
        return None
    return val.strip().replace("\x00", "")
