"""
Centralized, structured exception hierarchy for the ULPF framework.

Distinguishes between user input errors, operational environment failures,
parser execution issues, and AI inference states.
"""

from __future__ import annotations

from typing import Any, Optional


class ULPFError(Exception):
    """Base exception for all ULPF framework errors."""

    def __init__(self, message: str, code: str = "ULPF_ERROR", details: Optional[Any] = None):
        super().__init__(message)
        self.message = message
        self.code = code
        self.details = details or {}

    def to_dict(self) -> dict[str, Any]:
        return {
            "error": self.message,
            "code": self.code,
            "details": self.details,
        }


class InvalidInputError(ULPFError):
    """Raised when input parameters, format signatures, or data types are invalid."""

    def __init__(self, message: str, details: Optional[Any] = None):
        super().__init__(message, code="INVALID_INPUT", details=details)


class EmptyInputError(ULPFError):
    """Raised when log text, file, or line stream is empty (zero bytes or whitespace only)."""

    def __init__(self, message: str = "Input is empty (zero bytes or blank lines).", details: Optional[Any] = None):
        super().__init__(message, code="EMPTY_INPUT", details=details)


class UnsupportedInputError(ULPFError):
    """Raised when log data is corrupted, binary, or unreadable."""

    def __init__(self, message: str, details: Optional[Any] = None):
        super().__init__(message, code="UNSUPPORTED_INPUT", details=details)


class ParserFailureError(ULPFError):
    """Raised when a selected or dynamic parser encounters an unhandled extraction crash."""

    def __init__(self, message: str, parser_name: Optional[str] = None, details: Optional[Any] = None):
        info = details or {}
        if parser_name:
            info["parser_name"] = parser_name
        super().__init__(message, code="PARSER_FAILURE", details=info)


class AIUnavailableError(ULPFError):
    """Raised when the local Ollama LLM service is offline or unreachable."""

    def __init__(self, message: str = "Local Ollama service is unavailable or unreachable.", details: Optional[Any] = None):
        super().__init__(message, code="AI_UNAVAILABLE", details=details)


class AITimeoutError(ULPFError):
    """Raised when Ollama LLM inference exceeds the configured timeout threshold."""

    def __init__(self, message: str = "Ollama LLM inference timed out.", timeout: Optional[float] = None, details: Optional[Any] = None):
        info = details or {}
        if timeout is not None:
            info["timeout_seconds"] = timeout
        super().__init__(message, code="AI_TIMEOUT", details=info)


class ValidationFailureError(ULPFError):
    """Raised when an event fails strict OCSF schema or structural validation."""

    def __init__(self, message: str, failed_fields: Optional[list[str]] = None, details: Optional[Any] = None):
        info = details or {}
        if failed_fields:
            info["failed_fields"] = failed_fields
        super().__init__(message, code="VALIDATION_FAILURE", details=info)


class StorageFailureError(ULPFError):
    """Raised when DuckDB persistence, blockchain ledger, or disk export encounters an error."""

    def __init__(self, message: str, details: Optional[Any] = None):
        super().__init__(message, code="STORAGE_FAILURE", details=details)


class InternalFailureError(ULPFError):
    """Raised when an unexpected internal invariant or pipeline fault occurs."""

    def __init__(self, message: str, details: Optional[Any] = None):
        super().__init__(message, code="INTERNAL_FAILURE", details=details)
