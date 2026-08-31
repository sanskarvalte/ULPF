"""
Base abstract parser class for ULPF.
All log format parsers implement this interface.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional

from app.models.event_schema import UnifiedEvent


class BaseParser(ABC):
    """Abstract base class for all log format parsers."""

    format_name: str = "generic"

    @abstractmethod
    def parse(self, raw_log: str) -> UnifiedEvent:
        """Parse a single raw log string into a UnifiedEvent."""
        pass

    def parse_batch(self, raw_logs: List[str]) -> List[UnifiedEvent]:
        """Parse a batch of raw log strings."""
        return [self.parse(log) for log in raw_logs if log.strip()]
