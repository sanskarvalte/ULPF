"""
ULPF Dynamic Parser Engine.

Executes a validated parser specification against raw log lines.
Handles:
- Quoted delimiters (commas, spaces, semicolons inside quotes)
- Escaped characters and Unicode strings
- Mixed delimiters (positional + key/value)
- Reordered key=value and key:value pairs
- Optional, missing, and extra fields
- Preserves all custom and unknown fields losslessly
- Does NOT generate or execute arbitrary Python code.
"""

from __future__ import annotations

import csv
import io
import json
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from app.models.event_schema import UnifiedEvent
from app.normalization.field_mapping import (
    COMMON_FIELD_MAP,
    coerce_int,
    parse_timestamp,
)

# UnifiedEvent fields that can be populated directly.
UNIFIED_FIELDS = {
    "timestamp",
    "action",
    "category_name",
    "category_uid",
    "class_name",
    "class_uid",
    "activity_name",
    "activity_id",
    "type_name",
    "type_uid",
    "severity",
    "severity_id",
    "status",
    "status_id",
    "status_code",
    "status_detail",
    "message",
    "src_ip",
    "src_port",
    "src_hostname",
    "src_endpoint_name",
    "dst_ip",
    "dst_port",
    "dst_hostname",
    "dst_endpoint_name",
    "protocol",
    "direction",
    "traffic_bytes",
    "traffic_packets",
    "user",
    "user_uid",
    "user_type",
    "user_domain",
    "auth_protocol",
    "is_mfa",
    "is_remote",
    "logon_type",
    "service_name",
    "session_uid",
    "vendor",
    "product",
    "product_version",
    "log_format",
    "log_name",
    "classification_confidence",
    "classification_reason",
    "classification_evidence",
}

# Regex for key-value extraction supporting quoted values with escaped quotes and mixed delimiters
_KV_REGEX = re.compile(
    r'([a-zA-Z_][a-zA-Z0-9_\-\.]*)(?:[=:])(?:"((?:[^"\\]|\\.)*)"|\'((?:[^\'\\]|\\.)*)\'|([^\s,;]+))'
)


def _unescape_str(s: str) -> str:
    """Unescape standard string escape sequences like \\\", \\\\, \\n, \\t."""
    if not s:
        return s
    return (
        s.replace(r'\"', '"')
        .replace(r"\'", "'")
        .replace(r"\n", "\n")
        .replace(r"\t", "\t")
        .replace(r"\\", "\\")
    )


def _convert_value(
    value: Any,
    field_type: str,
) -> Any:
    """Convert an extracted value according to the specification field type."""
    if value is None:
        return None

    if field_type.lower() in ("string", "text", "str", "message"):
        return _unescape_str(str(value))

    value_str = str(value).strip()
    if not value_str or value_str.lower() in ("null", "none", "-", "", "nil"):
        return None

    field_type = field_type.lower()

    if field_type == "datetime":
        # Check standard timestamp parser
        parsed = parse_timestamp(value_str)
        if parsed:
            return parsed
        # Check Unix epoch seconds/milliseconds
        try:
            val_f = float(value_str)
            if val_f > 1_000_000_000:
                if val_f > 100_000_000_000:  # ms
                    val_f = val_f / 1000.0
                return datetime.fromtimestamp(val_f, tz=timezone.utc)
        except (ValueError, OSError):
            pass
        # Check ISO / space-separated timestamps
        for fmt in (
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%d %H:%M:%S.%f",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%dT%H:%M:%S.%fZ",
            "%b %d %H:%M:%S",
            "%d/%b/%Y:%H:%M:%S",
        ):
            try:
                dt = datetime.strptime(value_str, fmt)
                if dt.year == 1900:
                    dt = dt.replace(year=datetime.now(timezone.utc).year)
                return dt.replace(tzinfo=timezone.utc)
            except ValueError:
                continue
        try:
            return datetime.fromisoformat(value_str.replace("Z", "+00:00"))
        except Exception:
            return value_str

    if field_type in ("number", "integer", "int"):
        # Check integer (including negative integer)
        if re.match(r"^-?\d+$", value_str):
            return int(value_str)
        # Check decimal / float (including negative float)
        if re.match(r"^-?\d+\.\d+$", value_str):
            return float(value_str)
        return coerce_int(value_str)

    if field_type in ("float", "decimal"):
        try:
            return float(value_str)
        except ValueError:
            return value_str

    if field_type in ("port", "src_port", "dst_port"):
        port_num = coerce_int(value_str)
        if port_num is not None and 0 <= port_num <= 65535:
            return port_num
        return port_num

    return _unescape_str(value_str)


def _map_field_name(
    field_name: str,
) -> str:
    """Map a field name to a ULPF UnifiedEvent field when a mapping exists."""
    normalized = field_name.strip().lower()
    if normalized in UNIFIED_FIELDS:
        return normalized

    return COMMON_FIELD_MAP.get(normalized, normalized)


def _store_field(
    mapped: Dict[str, Any],
    unmapped: Dict[str, Any],
    field_name: str,
    value: Any,
) -> None:
    """Store an extracted field either in mapped UnifiedEvent or unmapped."""
    unified_name = _map_field_name(field_name)
    if unified_name in UNIFIED_FIELDS:
        mapped[unified_name] = value
    else:
        unmapped[field_name] = value
        if unified_name != field_name:
            unmapped[unified_name] = value


def _parse_delimited(
    raw: str,
    parser_spec: Dict[str, Any],
) -> Dict[str, Any]:
    """Parse a delimited log respecting quoted delimiters and escapes."""
    delimiter = parser_spec.get("delimiter", "|") or "|"
    fields: List[Dict[str, Any]] = parser_spec.get("fields", [])

    try:
        reader = csv.reader([raw.strip()], delimiter=delimiter, quotechar='"')
        values = next(reader)
    except Exception:
        values = raw.strip().split(delimiter)

    result: Dict[str, Any] = {}
    for index, field in enumerate(fields):
        name = field.get("name") if isinstance(field, dict) else str(field)
        field_type = field.get("type", "string") if isinstance(field, dict) else "string"
        if not name:
            continue
        if index < len(values):
            result[name] = _convert_value(values[index], field_type)
        else:
            # Missing optional field
            result[name] = None

    # Preserve extra columns beyond defined fields
    if len(values) > len(fields):
        for extra_idx in range(len(fields), len(values)):
            result[f"extra_col_{extra_idx + 1}"] = _unescape_str(values[extra_idx].strip())

    return result


def _parse_csv(
    raw: str,
    parser_spec: Dict[str, Any],
) -> Dict[str, Any]:
    """Parse a CSV line respecting quoted commas, spaces, and escapes."""
    delimiter = parser_spec.get("delimiter", ",") or ","
    fields: List[Dict[str, Any]] = parser_spec.get("fields", [])

    try:
        reader = csv.reader([raw.strip()], delimiter=delimiter, quotechar='"')
        values = next(reader)
    except Exception:
        values = raw.strip().split(delimiter)

    result: Dict[str, Any] = {}
    for index, field in enumerate(fields):
        name = field.get("name") if isinstance(field, dict) else str(field)
        field_type = field.get("type", "string") if isinstance(field, dict) else "string"
        if not name:
            continue
        if index < len(values):
            result[name] = _convert_value(values[index], field_type)
        else:
            result[name] = None

    if len(values) > len(fields):
        for extra_idx in range(len(fields), len(values)):
            result[f"extra_col_{extra_idx + 1}"] = _unescape_str(values[extra_idx].strip())

    return result


def _parse_key_value(
    raw: str,
    parser_spec: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Parse key=value or key:value style logs with support for:
    - Quoted messages containing spaces and commas (msg="hello, world")
    - Escaped quotes (msg="quoted \"text\"")
    - Reordered key-value pairs
    - Missing and extra fields
    """
    fields: List[Dict[str, Any]] = parser_spec.get("fields", [])
    field_types: Dict[str, str] = {}
    for f in fields:
        if isinstance(f, dict) and f.get("name"):
            field_types[f.get("name")] = f.get("type", "string")

    result: Dict[str, Any] = {}
    s_raw = raw.strip()

    # Check for leading timestamp (ISO 8601 or Syslog style)
    ts_lead = re.match(
        r'^(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?|[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s*(.*)$',
        s_raw,
    )
    if ts_lead:
        prefix = ts_lead.group(1).strip()
        s_raw = ts_lead.group(2).strip()
        ts_candidate = parse_timestamp(prefix)
        if ts_candidate:
            result["timestamp"] = ts_candidate

    matches = list(_KV_REGEX.finditer(s_raw))

    if matches:
        first_start = matches[0].start()
        if first_start > 0 and "timestamp" not in result:
            prefix = s_raw[:first_start].strip()
            if prefix:
                ts_candidate = parse_timestamp(prefix)
                if ts_candidate:
                    result["timestamp"] = ts_candidate

        for m in matches:
            k = m.group(1).strip()
            # Double quote, single quote, or unquoted value
            val_raw = m.group(2) if m.group(2) is not None else (m.group(3) if m.group(3) is not None else m.group(4))
            if val_raw is not None:
                ftype = field_types.get(k, "string")
                if ftype in ("string", "text", "str", "message"):
                    val_clean = _unescape_str(val_raw)
                else:
                    val_clean = _unescape_str(val_raw.strip())
                result[k] = _convert_value(val_clean, ftype)
    else:
        # Fallback split on whitespace and delimiters
        separator = parser_spec.get("key_value_separator", "=") or "="
        for token in re.split(r"[\s,;]+", raw.strip()):
            if separator not in token:
                continue
            k, v = token.split(separator, 1)
            k = k.strip()
            v = v.strip().strip('"\'')
            if k:
                result[k] = _convert_value(_unescape_str(v), field_types.get(k, "string"))

    return result


def _parse_json(
    raw: str,
    parser_spec: Dict[str, Any],
) -> Dict[str, Any]:
    """Parse JSON logs according to the specification."""
    try:
        obj = json.loads(raw.strip())
    except Exception:
        return {}

    if not isinstance(obj, dict):
        return {}

    fields: List[Dict[str, Any]] = parser_spec.get("fields", [])
    result: Dict[str, Any] = {}

    if fields:
        field_names = set()
        for field in fields:
            name = field.get("name") if isinstance(field, dict) else str(field)
            if not name:
                continue
            field_names.add(name)
            ftype = field.get("type", "string") if isinstance(field, dict) else "string"
            if name in obj:
                result[name] = _convert_value(obj[name], ftype)
            else:
                result[name] = None
        # Preserve extra keys
        for k, v in obj.items():
            if k not in field_names:
                result[k] = v
    else:
        for k, v in obj.items():
            result[k] = v

    return result


def _parse_regex(
    raw: str,
    parser_spec: Dict[str, Any],
) -> Dict[str, Any]:
    """Parse using named group regex pattern."""
    pattern = parser_spec.get("regex_pattern") or parser_spec.get("pattern_regex")
    if not pattern:
        return {}

    try:
        compiled = re.compile(pattern, re.DOTALL | re.IGNORECASE)
        match = compiled.search(raw.strip())
        if match and match.groupdict():
            fields = {
                f.get("name"): f.get("type", "string")
                for f in parser_spec.get("fields", [])
                if isinstance(f, dict) and f.get("name")
            }
            return {
                k: _convert_value(v, fields.get(k, "string"))
                for k, v in match.groupdict().items()
                if v is not None
            }
    except Exception:
        pass
    return {}


def parse_with_spec(
    raw: str,
    parser_spec: Dict[str, Any],
) -> UnifiedEvent:
    """
    Execute a validated parser specification against a raw log line.
    Returns a normalized UnifiedEvent with unmapped fields preserved.
    """
    parser_type = str(parser_spec.get("parser_type", "delimited")).lower()

    if parser_type == "delimited":
        extracted = _parse_delimited(raw, parser_spec)
    elif parser_type == "csv":
        extracted = _parse_csv(raw, parser_spec)
    elif parser_type in ("key_value", "logfmt"):
        extracted = _parse_key_value(raw, parser_spec)
    elif parser_type == "json":
        extracted = _parse_json(raw, parser_spec)
    elif parser_type == "regex":
        extracted = _parse_regex(raw, parser_spec)
    else:
        extracted = _parse_delimited(raw, parser_spec)

    mapped: Dict[str, Any] = {}
    unmapped: Dict[str, Any] = {}

    for field_name, value in extracted.items():
        if value is None:
            continue
        _store_field(mapped, unmapped, field_name, value)

    # Explicit timestamp field
    timestamp_field = parser_spec.get("timestamp_field")
    if timestamp_field and timestamp_field in extracted:
        ts_val = extracted[timestamp_field]
        if ts_val is not None:
            mapped["timestamp"] = _convert_value(ts_val, "datetime")

    # Ensure message is populated
    if not mapped.get("message"):
        mapped["message"] = raw.strip()

    mapped["log_format"] = parser_spec.get("format_name", "ai_dynamic")
    mapped["raw_event"] = raw

    if unmapped:
        mapped["unmapped"] = unmapped

    from app.normalization.engine import normalize_event
    event = UnifiedEvent(**mapped)
    return normalize_event(event)
