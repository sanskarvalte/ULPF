"""
Custom mapping transformation engine for user-defined schema mappings.
"""

from __future__ import annotations

from typing import Any, Dict

from app.mapping.existing import BUILTIN_MAPPINGS
from app.mapping.ocsf_adapter import to_ocsf_json
from app.models.event_schema import UnifiedEvent


def apply_custom_mapping(raw_dict: Dict[str, Any], mapping_name: str) -> Dict[str, Any]:
    """Transform a raw dictionary into standard keys using a predefined or registered mapping."""
    mapping = BUILTIN_MAPPINGS.get(mapping_name)
    if not mapping:
        return raw_dict

    field_maps = mapping.get("field_maps", {})
    transformed: Dict[str, Any] = {
        "vendor": mapping.get("vendor"),
        "product": mapping.get("product"),
    }

    for raw_k, raw_v in raw_dict.items():
        if raw_k in field_maps:
            transformed[field_maps[raw_k]] = raw_v
        else:
            transformed[raw_k] = raw_v

    # Check for specific EventID rule
    event_id = str(raw_dict.get("EventID", ""))
    event_rules = mapping.get("event_id_mappings", {}).get(event_id)
    if event_rules:
        transformed.update(event_rules)

    return transformed
