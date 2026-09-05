"""
Persistent registry and cache for learned and AI-generated ULPF parsers.

Maps a stable format fingerprint to:
1. Parser specification & historical versions
2. Canonical format specification
3. Parser lifecycle status ("active", "rejected", "pending_review")
4. Version number and validation metadata
5. Cache hit/miss metrics
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional


REGISTRY_DIR = Path("data/parsers")
REGISTRY_FILE = REGISTRY_DIR / "registry.json"

_CACHE_HITS: int = 0
_CACHE_MISSES: int = 0


def get_cache_stats() -> Dict[str, int]:
    """Return cache hit and miss statistics."""
    return {"hits": _CACHE_HITS, "misses": _CACHE_MISSES}


def reset_cache_stats() -> None:
    """Reset cache hit/miss counters."""
    global _CACHE_HITS, _CACHE_MISSES
    _CACHE_HITS = 0
    _CACHE_MISSES = 0


def _get_registry_file() -> Path:
    import os
    env_p = os.getenv("ULPF_REGISTRY_FILE")
    if env_p:
        return Path(env_p)
    if REGISTRY_FILE.exists():
        return REGISTRY_FILE
    repo_file = Path(__file__).resolve().parents[3] / "data" / "parsers" / "registry.json"
    if repo_file.exists():
        return repo_file
    return REGISTRY_FILE


def _load_registry() -> Dict[str, Any]:
    """Load the parser registry from disk."""
    reg_file = _get_registry_file()
    if not reg_file.exists():
        return {}

    try:
        with reg_file.open("r", encoding="utf-8") as file:
            return json.load(file)
    except (json.JSONDecodeError, OSError):
        return {}


def _save_registry(registry: Dict[str, Any]) -> None:
    """Save the parser registry to disk."""
    reg_file = _get_registry_file()
    reg_file.parent.mkdir(parents=True, exist_ok=True)

    with reg_file.open("w", encoding="utf-8") as file:
        json.dump(
            registry,
            file,
            indent=2,
        )


def register_parser(
    fingerprint: str,
    parser_spec: Dict[str, Any],
    canonical_spec: Optional[Dict[str, Any]] = None,
    status: str = "active",
    version: Optional[int] = None,
    validation_passed: bool = True,
) -> None:
    """
    Register or update a parser specification with version and lifecycle status.
    A parser becomes trusted (status='active') only after passing validation.
    """
    registry = _load_registry()

    existing = registry.get(fingerprint)
    current_ver = existing.get("version", 0) if existing else 0
    if version is not None:
        new_ver = version
    else:
        new_ver = current_ver + 1 if existing else 1

    versions_map = existing.get("versions", {}) if existing else {}
    versions_map[str(new_ver)] = {
        "parser_spec": parser_spec,
        "status": status,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "validation_passed": validation_passed,
    }

    entry = {
        "parser_spec": parser_spec,
        "status": status,
        "version": new_ver,
        "versions": versions_map,
        "validation_passed": validation_passed,
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }

    if canonical_spec is not None:
        entry["canonical_spec"] = canonical_spec
    elif existing and "canonical_spec" in existing:
        entry["canonical_spec"] = existing["canonical_spec"]

    registry[fingerprint] = entry
    _save_registry(registry)

    # Sync with DuckDB custom_parsers only if active and valid regex is present
    pattern_regex = parser_spec.get("pattern_regex", "")
    if status == "active" and pattern_regex and pattern_regex.strip():
        try:
            from app.storage.custom_parsers import save_custom_parser
            fmt_name = parser_spec.get("format_name") or f"learned_{fingerprint[:8]}"
            save_custom_parser(
                format_name=fmt_name,
                fingerprint=fingerprint,
                pattern_regex=pattern_regex,
                field_mapping=parser_spec.get("field_mapping", {}),
                approved_by="ai_resolver",
            )
        except Exception:
            pass


def promote_parser(
    fingerprint: str,
    version: Optional[int] = None,
) -> bool:
    """Promote a registered parser to active trusted status."""
    registry = _load_registry()
    entry = registry.get(fingerprint)
    if not entry:
        return False
    entry["status"] = "active"
    entry["validation_passed"] = True
    entry["updated_at"] = datetime.now(timezone.utc).isoformat()
    if version is not None and "versions" in entry:
        ver_str = str(version)
        if ver_str in entry["versions"]:
            entry["versions"][ver_str]["status"] = "active"
    _save_registry(registry)
    return True


def reject_parser(
    fingerprint: str,
    reason: str = "",
    version: Optional[int] = None,
) -> bool:
    """Reject an untrusted or failing parser specification."""
    registry = _load_registry()
    entry = registry.get(fingerprint)
    if not entry:
        return False
    entry["status"] = "rejected"
    entry["rejection_reason"] = reason
    entry["updated_at"] = datetime.now(timezone.utc).isoformat()
    if version is not None and "versions" in entry:
        ver_str = str(version)
        if ver_str in entry["versions"]:
            entry["versions"][ver_str]["status"] = "rejected"
    _save_registry(registry)
    return True


def get_parser(
    fingerprint: str,
    version: Optional[int] = None,
) -> Optional[Dict[str, Any]]:
    """
    Return the active trusted parser specification for a fingerprint (and optional version).
    Tracks cache hits and misses.
    """
    global _CACHE_HITS, _CACHE_MISSES
    registry = _load_registry()
    entry = registry.get(fingerprint)

    if entry is None or entry.get("status", "active") != "active" or not entry.get("validation_passed", True):
        _CACHE_MISSES += 1
        return None

    if version is not None:
        versions_map = entry.get("versions", {})
        ver_entry = versions_map.get(str(version))
        if ver_entry and ver_entry.get("status", "active") == "active":
            _CACHE_HITS += 1
            return ver_entry.get("parser_spec")
        _CACHE_MISSES += 1
        return None

    _CACHE_HITS += 1
    return entry.get("parser_spec")


def get_parser_version(
    fingerprint: str,
    version: int,
) -> Optional[Dict[str, Any]]:
    """Return parser specification for an explicit version number if active."""
    return get_parser(fingerprint, version=version)


def get_entry(
    fingerprint: str,
) -> Optional[Dict[str, Any]]:
    """Return the complete registry entry."""
    global _CACHE_HITS, _CACHE_MISSES
    registry = _load_registry()
    entry = registry.get(fingerprint)
    if entry is not None and entry.get("status", "active") == "active":
        _CACHE_HITS += 1
    else:
        _CACHE_MISSES += 1
    return entry


def get_canonical_spec(
    fingerprint: str,
) -> Optional[Dict[str, Any]]:
    """Return the canonical format specification."""
    entry = get_entry(fingerprint)
    if entry is None or entry.get("status", "active") != "active":
        return None
    return entry.get("canonical_spec")


def has_parser(
    fingerprint: str,
    version: Optional[int] = None,
) -> bool:
    """Check whether an active trusted parser is registered."""
    spec = get_parser(fingerprint, version=version)
    return spec is not None


def list_parsers() -> Dict[str, Any]:
    """List all registered parsers."""
    return _load_registry()


def clear_parsers() -> None:
    """Clear all registered parsers and reset cache stats."""
    _save_registry({})
    reset_cache_stats()

