"""
ULPF Adaptive Parser.

Uses an existing registered parser when available.
Calls local AI only when the format is unknown.
"""

from __future__ import annotations

from typing import Any, Dict

from app.ai.canonical import build_canonical_spec
from app.ai.fingerprint import create_fingerprint
from app.ai.parser_decision import find_saved_parser
from app.ai.parser_pipeline import generate_valid_parser
from app.ai.parser_registration import register_generated_parser


def get_or_generate_parser(
    canonical_spec: Dict[str, Any],
    log_samples: str,
) -> Dict[str, Any]:
    """
    Get an existing parser or generate/register a new one.
    Local AI is called only when the fingerprint is not
    already present in the registry.
    """
    saved_parser = find_saved_parser(canonical_spec)

    if saved_parser is not None:
        return {
            "action": "use_existing_parser",
            "source": "registry",
            "fingerprint": create_fingerprint(canonical_spec),
            "parser_spec": saved_parser["parser_spec"],
        }

    generated_parser = generate_valid_parser(log_samples)
    registration = register_generated_parser(generated_parser)

    return {
        "action": "generate_and_register",
        "source": "ai",
        "fingerprint": registration["fingerprint"],
        "parser_spec": registration["parser_spec"],
    }
