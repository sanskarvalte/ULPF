"""
ULPF Canonical Format Specification.

Converts an AI-generated parser specification into a stable
structure that can be used for fingerprinting and cataloging.
"""

from __future__ import annotations

from typing import Any, Dict, List


def build_canonical_spec(
    parser_spec: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Convert a parser specification into a stable canonical format.
    """

    fields: List[Dict[str, str]] = []

    for field in parser_spec.get("fields", []):
        if not isinstance(field, dict):
            continue

        name = str(field.get("name", "")).strip().lower()
        field_type = str(
            field.get("type", "string")
        ).strip().lower()

        if not name:
            continue

        fields.append({
            "name": name,
            "type": field_type,
        })

    parser_type = str(
        parser_spec.get("parser_type", "unknown")
    ).strip().lower()

    delimiter = str(
        parser_spec.get("delimiter", "")
    )

    timestamp_field = str(
        parser_spec.get("timestamp_field", "")
    ).strip().lower()

    format_family = _infer_format_family(
        parser_type
    )

    timestamp_pattern = "unknown"

    if timestamp_field:
        for field in fields:
            if field["name"] == timestamp_field:
                if field["type"] == "datetime":
                    timestamp_pattern = "datetime"
                break

    return {
        "format_family": format_family,
        "parser_type": parser_type,
        "delimiter": delimiter,
        "timestamp_pattern": timestamp_pattern,
        "timestamp_field": timestamp_field,
        "fields": fields,
        "optional_fields": sorted(
            str(field).strip().lower()
            for field in parser_spec.get(
                "optional_fields",
                []
            )
        ),
        "structure": [
            field["name"]
            for field in fields
        ],
    }


def _infer_format_family(
    parser_type: str,
) -> str:
    """Convert parser type into a stable format family."""

    mapping = {
        "json": "structured",
        "xml": "structured",
        "csv": "delimited",
        "delimited": "delimited",
        "key_value": "key_value",
        "syslog": "syslog",
        "regex": "text",
    }

    return mapping.get(
        parser_type,
        "unknown",
    )
