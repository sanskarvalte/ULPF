"""
ULPF AI Parser Pipeline.

Generates a parser specification, validates it,
and repairs it when necessary.
"""

from __future__ import annotations

from typing import Any, Dict

from app.ai.parser_generator import generate_parser_spec
from app.ai.parser_repair import repair_parser_spec
from app.ai.parser_validator import validate_parser_spec
from app.config import get_config


def generate_valid_parser(
    log_samples: str,
) -> Dict[str, Any]:
    """
    Generate a parser specification and ensure that it
    passes deterministic validation.
    """
    max_repairs = get_config().repair_attempts
    parser_spec = generate_parser_spec(log_samples)
    validation = validate_parser_spec(parser_spec)

    if validation["valid"]:
        return parser_spec

    for _ in range(max_repairs):
        parser_spec = repair_parser_spec(
            log_samples=log_samples,
            parser_spec=parser_spec,
            errors=validation["errors"],
        )

        validation = validate_parser_spec(parser_spec)
        if validation["valid"]:
            return parser_spec

    raise ValueError(
        f"Could not generate a valid parser specification after {max_repairs} repair attempts. "
        f"Errors: {validation['errors']}"
    )
