"""
Backward-compatibility alias for app.normalization.semantic_classifier.
"""

from __future__ import annotations

from app.normalization.semantic_classifier import (
    classify_semantics,
    _extract_all_evidence_tokens,
    _clean_token,
)

__all__ = ["classify_semantics", "_extract_all_evidence_tokens", "_clean_token"]
