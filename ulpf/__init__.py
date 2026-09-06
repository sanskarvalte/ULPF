"""
ULPF — Universal Log Pre-processing Framework.
Enterprise log normalization, OCSF mapping, DuckDB storage, and offline AI parsing.
"""

from __future__ import annotations

import sys
from pathlib import Path

# Ensure backend directory containing 'app' package is discoverable
_this_file = Path(__file__).resolve()
_backend_dir = None
for candidate in [
    _this_file.parent.parent / "backend",
    _this_file.parent.parent,
    _this_file.parent / "backend",
    _this_file.parent,
]:
    if (candidate / "app" / "pipeline.py").exists():
        _backend_dir = candidate
        break

if _backend_dir and str(_backend_dir) not in sys.path:
    sys.path.insert(0, str(_backend_dir))

from app.pipeline import PipelineEngine, pipeline
from app.config import ULPFConfig, get_config, set_config
from app.models.result import ProcessingResult, ProcessingStatus
from app.models.event_schema import UnifiedEvent
from app.exceptions import (
    ULPFError,
    InvalidInputError,
    EmptyInputError,
    UnsupportedInputError,
    ParserFailureError,
    AIUnavailableError,
    AITimeoutError,
    ValidationFailureError,
    StorageFailureError,
    InternalFailureError,
)

__version__ = "2.1.0"

__all__ = [
    "PipelineEngine",
    "pipeline",
    "ULPFConfig",
    "get_config",
    "set_config",
    "ProcessingResult",
    "ProcessingStatus",
    "UnifiedEvent",
    "ULPFError",
    "InvalidInputError",
    "EmptyInputError",
    "UnsupportedInputError",
    "ParserFailureError",
    "AIUnavailableError",
    "AITimeoutError",
    "ValidationFailureError",
    "StorageFailureError",
    "InternalFailureError",
]
