"""
Lightweight, pure-Python YAML reader for mapping and banner configurations.
100% offline, zero-dependency.
Supports dictionaries, nested dictionaries, scalar types, and lists of dictionaries.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


def _parse_scalar(val: str) -> Any:
    clean_val = val.strip().strip("\"'").replace("\\\\", "\\")
    if clean_val.lower() == "true":
        return True
    elif clean_val.lower() == "false":
        return False
    elif clean_val.lower() in ("null", "none", "~"):
        return None
    elif clean_val.isdigit():
        return int(clean_val)
    return clean_val


def parse_yaml_str(content: str) -> Dict[str, Any]:
    """
    Parse YAML documents used in ULPF mapping and banner definitions.
    Supports comments (#), top-level scalars, nested dictionaries, and lists of dicts.
    """
    result: Dict[str, Any] = {}
    lines = content.splitlines()
    
    current_key: Optional[str] = None
    current_list: Optional[List[Any]] = None
    current_item: Optional[Dict[str, Any]] = None
    current_dict: Dict[str, Any] = result

    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        indent = len(line) - len(line.lstrip(" "))

        # List item header: e.g. "  - name: ..." or "  - "
        if stripped.startswith("- "):
            item_content = stripped[2:].strip()
            if current_key and current_list is None:
                current_list = []
                result[current_key] = current_list

            current_item = {}
            if current_list is not None:
                current_list.append(current_item)

            if ":" in item_content:
                k, v = item_content.split(":", 1)
                current_item[k.strip().strip("\"'")] = _parse_scalar(v)
            continue

        # Property inside a list item
        if current_item is not None and indent >= 4 and ":" in stripped:
            k, v = stripped.split(":", 1)
            current_item[k.strip().strip("\"'")] = _parse_scalar(v)
            continue

        # Top level or regular key-value
        if ":" in stripped:
            current_item = None
            current_list = None
            key_part, val_part = stripped.split(":", 1)
            k = key_part.strip().strip("\"'")
            v = val_part.strip()
            if not v:
                current_key = k
                # could be nested dict or start of a list
            else:
                result[k] = _parse_scalar(v)

    return result


def load_yaml_file(file_path: Path | str) -> Dict[str, Any]:
    """Load and parse YAML file from filesystem."""
    p = Path(file_path)
    if not p.exists():
        return {}
    try:
        content = p.read_text(encoding="utf-8")
    except Exception:
        content = p.read_text(encoding="latin-1", errors="replace")
    return parse_yaml_str(content)
