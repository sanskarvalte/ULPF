"""
Processing Result Contract for ULPF.
Represents standardized framework outputs across CLI, REST API, and Python SDK.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from app.models.event_schema import UnifiedEvent


class ProcessingStatus(str, Enum):
    """Execution status for framework processing operations."""
    SUCCESS = "SUCCESS"
    PARTIAL = "PARTIAL"
    REVIEW = "REVIEW"
    FAILED = "FAILED"
    SKIPPED = "SKIPPED"


class ProcessingResult(BaseModel):
    """
    Standard framework result object returned by PipelineEngine.
    Preserves backwards-compatibility with existing dictionary access (result["status"]).
    """
    status: ProcessingStatus = Field(default=ProcessingStatus.SUCCESS, description="Overall execution status")
    format: str = Field(default="unknown", description="Detected or parsed format identifier")
    parser_source: str = Field(default="builtin", description="Parser mechanism (builtin, learned_cache, ai_generated, positional_fallback, raw_unparsed)")
    total_events: int = Field(default=0, ge=0, description="Total number of log events processed")
    valid_events: int = Field(default=0, ge=0, description="Number of events passing schema validation")
    invalid_events: int = Field(default=0, ge=0, description="Number of events failing schema validation")
    validation_rate: float = Field(default=0.0, ge=0.0, le=1.0, description="Fraction of valid events")
    confidence: float = Field(default=1.0, ge=0.0, le=1.0, description="Parser or extraction confidence score")
    events: List[UnifiedEvent] = Field(default_factory=list, description="Extracted UnifiedEvents")
    source_name: str = Field(default="", description="Original file name or source stream name")
    quarantined_count: int = Field(default=0, ge=0, description="Number of quarantined events")
    duration_ms: float = Field(default=0.0, ge=0.0, description="Processing duration in milliseconds")
    error: Optional[str] = Field(default=None, description="Error message if status is FAILED")
    details: Dict[str, Any] = Field(default_factory=dict, description="Additional contextual details (e.g. template, metrics)")

    # Dictionary compatibility methods
    def __getitem__(self, item: str) -> Any:
        if self.details and item in self.details:
            return self.details[item]
        if hasattr(self, item):
            val = getattr(self, item)
            if isinstance(val, ProcessingStatus):
                return val.value
            return val
        return self.details[item]

    def __contains__(self, item: str) -> bool:
        return (self.details and item in self.details) or hasattr(self, item)

    def get(self, item: str, default: Any = None) -> Any:
        if self.details and item in self.details:
            return self.details[item]
        if hasattr(self, item):
            val = getattr(self, item)
            if isinstance(val, ProcessingStatus):
                return val.value
            return val
        return default

    def to_dict(self) -> Dict[str, Any]:
        """Export result as a standard Python dictionary."""
        d = self.model_dump()
        d["status"] = self.status.value
        return d
