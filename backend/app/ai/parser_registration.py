"""
ULPF AI Parser Registration.

Takes a validated AI-generated parser specification,
creates a stable fingerprint, and stores it in the
persistent parser registry.
"""

from __future__ import annotations

from typing import Any, Dict

from app.ai.canonical import build_canonical_spec
from app.ai.fingerprint import create_fingerprint
from app.ai.parser_validator import validate_parser_spec
from app.parsers.registry import register_parser


def register_generated_parser(
    parser_spec: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Validate, canonicalize, fingerprint, and register
    an AI-generated parser specification.
    """
    validation = validate_parser_spec(parser_spec)
    if not validation["valid"]:
        raise ValueError(
            "Cannot register invalid parser specification: "
            f"{validation['errors']}"
        )

    canonical_spec = build_canonical_spec(parser_spec)
    fingerprint = create_fingerprint(canonical_spec)

    register_parser(
        fingerprint=fingerprint,
        parser_spec=parser_spec,
        canonical_spec=canonical_spec,
    )

    return {
        "fingerprint": fingerprint,
        "canonical_spec": canonical_spec,
        "parser_spec": parser_spec,
        "status": "registered",
    }
