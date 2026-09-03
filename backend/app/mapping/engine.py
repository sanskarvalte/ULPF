"""
Custom mapping transformation engine for user-defined and YAML schema mappings.
Dynamically loads and applies vendor configurations from mappings/ directory.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from app.mapping.existing import BUILTIN_MAPPINGS
from app.mapping.yaml_loader import load_yaml_file

# Root mappings directory path
_MAPPINGS_DIR = Path(__file__).resolve().parent.parent.parent.parent / "mappings"

_LOADED_YAML_MAPPINGS: Dict[str, Dict[str, Any]] = {}


def load_all_yaml_mappings(mappings_dir: Optional[Path | str] = None) -> Dict[str, Dict[str, Any]]:
    """Scan and load all .yaml and .yml files from mappings directory."""
    global _LOADED_YAML_MAPPINGS
    target_dir = Path(mappings_dir) if mappings_dir else _MAPPINGS_DIR
    mappings: Dict[str, Dict[str, Any]] = {}

    if target_dir.exists():
        for yaml_path in target_dir.rglob("*.yaml"):
            try:
                data = load_yaml_file(yaml_path)
                if data:
                    name = yaml_path.stem
                    mappings[name] = data
            except Exception:
                pass
        for yml_path in target_dir.rglob("*.yml"):
            try:
                data = load_yaml_file(yml_path)
                if data:
                    name = yml_path.stem
                    mappings[name] = data
            except Exception:
                pass

    _LOADED_YAML_MAPPINGS = mappings
    return mappings


def get_all_mappings() -> Dict[str, Dict[str, Any]]:
    """Return combined dictionary of builtin and discovered YAML mappings."""
    if not _LOADED_YAML_MAPPINGS:
        load_all_yaml_mappings()
    combined = dict(BUILTIN_MAPPINGS)
    combined.update(_LOADED_YAML_MAPPINGS)
    return combined


def find_matching_vendor_mapping(raw_log: str) -> Optional[Tuple[str, Dict[str, Any]]]:
    """
    Check if a raw log matches any vendor mapping pattern from YAML definitions.
    Returns (mapping_name, mapping_def) if matched, otherwise None.
    """
    all_maps = get_all_mappings()
    for name, mapping in all_maps.items():
        pattern = mapping.get("match_pattern")
        if pattern:
            try:
                if re.search(pattern, raw_log, re.IGNORECASE):
                    return name, mapping
            except Exception:
                pass
    return None


def apply_custom_mapping(raw_dict: Dict[str, Any], mapping_name: str) -> Dict[str, Any]:
    """Transform a raw dictionary into standard keys using a predefined or registered mapping."""
    all_maps = get_all_mappings()
    mapping = all_maps.get(mapping_name)
    if not mapping:
        return raw_dict

    field_maps = mapping.get("field_mapping") or mapping.get("field_maps") or {}
    transformed: Dict[str, Any] = {}

    if mapping.get("vendor"):
        transformed["vendor"] = mapping["vendor"]
    if mapping.get("product"):
        transformed["product"] = mapping["product"]
    if mapping.get("category"):
        transformed["category_name"] = mapping["category"]
    if mapping.get("class"):
        transformed["class_name"] = mapping["class"]

    for raw_k, raw_v in raw_dict.items():
        if raw_k in field_maps:
            transformed[field_maps[raw_k]] = raw_v
        else:
            transformed[raw_k] = raw_v

    # Check for specific EventID rule
    event_id = str(raw_dict.get("EventID") or raw_dict.get("event_id") or "")
    event_rules = mapping.get("event_id_mappings", {}).get(event_id)
    if event_rules:
        transformed.update(event_rules)

    return transformed
