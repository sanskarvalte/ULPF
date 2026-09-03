"""
Ollama AI Assistant (Node 5).
Handles unmatched log lines via local Ollama LLM (llama3.2, temperature: 0, format: json).
Provides non-blocking field mapping suggestions, structural fingerprinting, key-prefix sanitization,
structured custom field extraction, and review queue management.
"""

from __future__ import annotations

import json
import logging
import re
import urllib.error
import urllib.request
from typing import Any, Dict, Optional

from app.ai.confidence import validate_product_signature
from app.ai.fingerprint import compute_log_fingerprint
from app.models.event_schema import UnifiedEvent
from app.normalization.field_mapping import coerce_int, parse_timestamp
from app.storage.review_queue import enqueue_for_review

logger = logging.getLogger("ulpf.ollama")

OLLAMA_API_URL = "http://127.0.0.1:11434/api/generate"
DEFAULT_MODEL = "llama3.2"

PROMPT_TEMPLATE = """You are an expert cybersecurity and systems log parser. Analyze this raw log line and output ONLY a valid JSON object suggesting format name, field mapping, and custom structured key-value pairs.

CRITICAL PARSING RULES:
1. NEVER guess "Apache Log4j" or "Apache" unless the log contains explicit Log4j-characteristic markers (e.g. logger class path like 'org.apache.', thread name in brackets '[main]', or %-style pattern layout tokens). If absent, use 'unknown_custom' or 'logfmt' with vendor null and product null.
2. STRIP KEY PREFIXES: For every extracted value, strip any leading key prefix (e.g. if key is 'ts' and token is 'ts:2026-08-27...', extract ONLY '2026-08-27...'; if key is 'svc' and token is 'svc:inventory-sync', extract ONLY 'inventory-sync'). Never return 'key:value' inside the value.
3. MAP SERVICE NAMES PROPERLY: Map service/application identifiers (like 'svc', 'app', 'service') to 'service_name', NOT to 'action'.
4. STRICT JSON NULL: If a field is absent or not present in the raw log, use actual JSON null (do NOT write the string "null", "None", or "-").
5. CAPTURE ALL CUSTOM FIELDS: Extract every key:value or key=value pair present in the log into 'custom_fields' so no structured attributes are lost.

Raw Log Line:
{raw_log}

Output JSON Format:
{{
  "suggested_format": "name_of_format_or_app",
  "vendor": null,
  "product": null,
  "confidence": 0.75,
  "field_mapping": {{
    "timestamp": "extracted ISO timestamp or null",
    "service_name": "service or application name or null",
    "src_ip": null,
    "src_port": null,
    "dst_ip": null,
    "dst_port": null,
    "user": null,
    "action": null,
    "severity": "Informational | Low | Medium | High | Critical",
    "category_name": "System Activity | Network Activity | Identity & Access Management | Findings",
    "message": "summary message or null"
  }},
  "custom_fields": {{
    "key1": "value1"
  }}
}}
"""

# In-memory cache for fast deduplication of fingerprint suggestions during stream
_FINGERPRINT_SUGGESTION_CACHE: Dict[str, Dict[str, Any]] = {}


def _clean_val(v: Any) -> Optional[Any]:
    """Coerce string 'null', 'None', 'n/a', '-', '' to None."""
    if v is None:
        return None
    if isinstance(v, str):
        s = v.strip()
        if s.lower() in ("null", "none", "n/a", "-", "", "undefined", "nil", "null_value"):
            return None
        return s
    return v


def _strip_key_prefix(key: str, val: Any) -> Optional[Any]:
    """Strip leading key: or key= prefix from extracted values and coerce string nulls."""
    cleaned = _clean_val(val)
    if cleaned is None or not isinstance(cleaned, str):
        return cleaned
    
    # Strip matching key prefix (e.g. "ts:2026-08-27..." -> "2026-08-27...")
    s = cleaned
    pattern = rf"^(?:{re.escape(key)}|ts|svc|time|date|lvl|level|status|msg|sku|warehouse|qty_on_hand|reorder_point|service|app)[:=]\s*"
    s = re.sub(pattern, "", s, flags=re.IGNORECASE).strip()
    return _clean_val(s)


def _extract_all_delimited_key_values(raw_line: str) -> Dict[str, Any]:
    """
    Extract all key:value and key=value pairs from unknown delimited logs (e.g. semicolon, space, comma).
    Preserves all structured custom fields (e.g. sku, warehouse, qty_on_hand, reorder_point).
    """
    pairs: Dict[str, Any] = {}
    
    # 1. Semicolon-delimited key:val or key=val
    if ";" in raw_line and (":" in raw_line or "=" in raw_line):
        segments = [s.strip() for s in raw_line.split(";") if s.strip()]
        for seg in segments:
            if ":" in seg:
                k, v = seg.split(":", 1)
                k_clean = k.strip()
                v_clean = _clean_val(v.strip())
                if k_clean and v_clean is not None:
                    pairs[k_clean] = v_clean
            elif "=" in seg:
                k, v = seg.split("=", 1)
                k_clean = k.strip()
                v_clean = _clean_val(v.strip().strip('"\''))
                if k_clean and v_clean is not None:
                    pairs[k_clean] = v_clean

    # 2. Space-delimited key=val pairs
    if not pairs and "=" in raw_line:
        for match in re.finditer(r'([a-zA-Z0-9_\-\.]+)=(".*?"|\'.*?\'|[^\s]+)', raw_line):
            k_clean = match.group(1).strip()
            v_clean = _clean_val(match.group(2).strip().strip('"\''))
            if k_clean and v_clean is not None:
                pairs[k_clean] = v_clean

    # 3. Space-delimited key:val pairs (e.g. svc:inventory-sync sku:1000 qty:100 status:ok)
    if not pairs and ":" in raw_line:
        for match in re.finditer(r'([a-zA-Z0-9_\-\.]+):([^\s,;]+)', raw_line):
            k_clean = match.group(1).strip()
            v_clean = _clean_val(match.group(2).strip().strip('"\''))
            if k_clean and v_clean is not None:
                pairs[k_clean] = v_clean

    return pairs


def _coerce_primitive(val: Any) -> Any:
    """Coerce string number to int/float if applicable."""
    if not isinstance(val, str):
        return val
    s = val.strip()
    if re.match(r"^-?\d+$", s):
        try:
            return int(s)
        except ValueError:
            pass
    elif re.match(r"^-?\d+\.\d+$", s):
        try:
            return float(s)
        except ValueError:
            pass
    return s


import concurrent.futures

_EXECUTOR = concurrent.futures.ThreadPoolExecutor(max_workers=2)
_PENDING_SUGGESTION_TASKS: set[str] = set()


def _generate_deterministic_suggestion(raw_stripped: str, raw_kv: Dict[str, Any], regex_pattern: str) -> Dict[str, Any]:
    """Generate immediate (<0.01ms) deterministic field mapping and metadata for unknown logs."""
    ts_val = _clean_val(raw_kv.get("ts") or raw_kv.get("time") or raw_kv.get("timestamp") or raw_kv.get("date"))
    svc_val = _clean_val(raw_kv.get("svc") or raw_kv.get("service") or raw_kv.get("app"))
    lvl_val = _clean_val(raw_kv.get("lvl") or raw_kv.get("level") or raw_kv.get("severity") or raw_kv.get("sev"))

    sev_mapped = "Informational"
    if lvl_val:
        lvl_upper = str(lvl_val).upper()
        if any(w in lvl_upper for w in ("CRIT", "FATAL", "EMERG")):
            sev_mapped = "Critical"
        elif any(w in lvl_upper for w in ("ERR", "ALERT")):
            sev_mapped = "High"
        elif "WARN" in lvl_upper:
            sev_mapped = "Medium"
        elif "NOTICE" in lvl_upper:
            sev_mapped = "Low"
        elif any(w in lvl_upper for w in ("INFO", "DEBUG", "TRACE")):
            sev_mapped = "Informational"

    msg_val = _clean_val(raw_kv.get("msg") or raw_kv.get("message") or raw_kv.get("error"))
    if not msg_val:
        msg_val = raw_stripped

    # Search for IPs
    src_ip = _clean_val(raw_kv.get("src") or raw_kv.get("src_ip") or raw_kv.get("fwd") or raw_kv.get("client_ip"))
    dst_ip = _clean_val(raw_kv.get("dst") or raw_kv.get("dst_ip") or raw_kv.get("host"))

    field_mapping: Dict[str, Any] = {
        "timestamp": str(ts_val) if ts_val else None,
        "service_name": str(svc_val) if svc_val else None,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "user": _clean_val(raw_kv.get("usr") or raw_kv.get("user") or raw_kv.get("username")),
        "action": _clean_val(raw_kv.get("action") or raw_kv.get("act") or raw_kv.get("method")),
        "severity": sev_mapped,
        "category_name": "System Activity",
        "message": str(msg_val),
    }

    base_conf = 0.70 if len(raw_kv) >= 2 else 0.50

    return {
        "suggested_format": "unknown_custom",
        "vendor": None,
        "product": None,
        "confidence": base_conf,
        "field_mapping": field_mapping,
        "custom_fields": raw_kv,
    }


def _async_fetch_ollama_suggestion(raw_stripped: str, fp_hash: str, model: str, regex_pattern: str, raw_kv: Dict[str, Any], conn=None):
    """Background task to query Ollama without blocking main log processing stream."""
    try:
        suggestion = query_ollama_suggestion(raw_stripped, model=model)
        if suggestion:
            _FINGERPRINT_SUGGESTION_CACHE[fp_hash] = suggestion

            raw_vendor = _clean_val(suggestion.get("vendor"))
            raw_product = _clean_val(suggestion.get("product"))
            raw_format = _clean_val(suggestion.get("suggested_format"))
            raw_conf = float(suggestion.get("confidence", 0.5))

            vendor, product, suggested_format, confidence = validate_product_signature(
                raw_log=raw_stripped,
                suggested_vendor=raw_vendor,
                suggested_product=raw_product,
                suggested_format=raw_format,
                claimed_confidence=raw_conf,
            )

            raw_field_map = suggestion.get("field_mapping") or {}
            clean_field_map: Dict[str, Any] = {}
            for k, v in raw_field_map.items():
                v_clean = _strip_key_prefix(k, v)
                if v_clean is not None:
                    clean_field_map[k] = v_clean

            extra_custom = suggestion.get("custom_fields") or {}
            combined_kv = dict(raw_kv)
            for k, v in extra_custom.items():
                v_clean = _strip_key_prefix(k, v)
                if v_clean is not None and k not in combined_kv:
                    combined_kv[k] = v_clean

            suggested_payload = {
                "format_name": suggested_format,
                "vendor": vendor,
                "product": product,
                "regex_pattern": regex_pattern,
                "field_mapping": clean_field_map,
                "custom_fields": combined_kv,
            }

            try:
                enqueue_for_review(
                    fingerprint=fp_hash,
                    format_name=suggested_format,
                    suggested_mapping=suggested_payload,
                    confidence=confidence,
                    sample_line=raw_stripped,
                    conn=conn,
                )
            except Exception:
                pass
    except Exception as e:
        logger.debug(f"Async Ollama error for {fp_hash}: {e}")
    finally:
        _PENDING_SUGGESTION_TASKS.discard(fp_hash)


def query_ollama_suggestion(raw_line: str, model: str = DEFAULT_MODEL) -> Optional[Dict[str, Any]]:
    """Query local Ollama with temperature=0 and JSON format."""
    payload = {
        "model": model,
        "prompt": PROMPT_TEMPLATE.format(raw_log=raw_line.strip()[:800]),
        "stream": False,
        "format": "json",
        "options": {
            "temperature": 0.0,
        },
    }

    try:
        req = urllib.request.Request(
            OLLAMA_API_URL,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json", "User-Agent": "ULPF/2.0"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=1.5) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            response_text = data.get("response", "{}")
            return json.loads(response_text)
    except Exception as e:
        logger.debug(f"Ollama query failed or offline: {e}")
        return None


# Alias for backward compatibility
query_ollama_for_log = query_ollama_suggestion


# In-memory cache for fast deduplication of structural fingerprint templates
_FINGERPRINT_SUGGESTION_CACHE: Dict[str, Dict[str, Any]] = {}
_FINGERPRINT_COUNTS: Dict[str, int] = {}


def process_unmatched_log_with_ai(
    raw_line: str,
    model: str = DEFAULT_MODEL,
    conn=None,
    sync_ai: bool = False,
) -> UnifiedEvent:
    """
    Node 5 execution (Non-blocking):
    1. Computes structural fingerprint (<0.01ms).
    2. Extracts all delimited key-value pairs fresh from current line.
    3. Dynamically refines confidence based on repeat occurrences.
    4. Auto-promotes stable templates (>=3 occurrences) to learned format identifier.
    5. Dispatches Ollama LLM suggestion generation in background worker.
    """
    raw_stripped = raw_line.strip()
    template, regex_pattern, fp_hash = compute_log_fingerprint(raw_stripped)

    # Track template frequency for statistical confidence refinement & auto-promotion
    _FINGERPRINT_COUNTS[fp_hash] = _FINGERPRINT_COUNTS.get(fp_hash, 0) + 1
    seen_count = _FINGERPRINT_COUNTS[fp_hash]

    # Pre-extract all raw key-value pairs FRESH from current line
    raw_kv = _extract_all_delimited_key_values(raw_stripped)

    suggestion = _FINGERPRINT_SUGGESTION_CACHE.get(fp_hash)
    if not suggestion:
        suggestion = _generate_deterministic_suggestion(raw_stripped, raw_kv, regex_pattern)
        _FINGERPRINT_SUGGESTION_CACHE[fp_hash] = suggestion

        if sync_ai:
            ai_sugg = query_ollama_suggestion(raw_stripped, model=model)
            if ai_sugg:
                suggestion = ai_sugg
                _FINGERPRINT_SUGGESTION_CACHE[fp_hash] = suggestion
        else:
            if fp_hash not in _PENDING_SUGGESTION_TASKS:
                _PENDING_SUGGESTION_TASKS.add(fp_hash)
                _EXECUTOR.submit(
                    _async_fetch_ollama_suggestion,
                    raw_stripped,
                    fp_hash,
                    model,
                    regex_pattern,
                    raw_kv,
                    conn,
                )

    # Invariant structural properties from template/suggestion
    raw_vendor = _clean_val(suggestion.get("vendor"))
    raw_product = _clean_val(suggestion.get("product"))
    raw_format = _clean_val(suggestion.get("suggested_format")) or "unknown_custom"
    base_conf = float(suggestion.get("confidence", 0.70))

    # Dynamic confidence refinement: increase confidence with repeat consistent observations
    dynamic_conf = min(0.98, round(base_conf + 0.05 * (seen_count - 1), 2))

    vendor, product, suggested_format, confidence = validate_product_signature(
        raw_log=raw_stripped,
        suggested_vendor=raw_vendor,
        suggested_product=raw_product,
        suggested_format=raw_format,
        claimed_confidence=dynamic_conf,
    )

    try:
        enqueue_for_review(
            fingerprint=fp_hash,
            format_name=suggested_format,
            suggested_mapping={
                "format_name": suggested_format,
                "vendor": vendor,
                "product": product,
                "regex_pattern": regex_pattern,
                "custom_fields": raw_kv,
            },
            confidence=confidence,
            sample_line=raw_stripped,
            conn=conn,
        )
    except Exception as e:
        logger.debug(f"Could not enqueue to review table: {e}")

    # Auto-promotion: When a structural pattern repeats >= 5 times with high confidence,
    # promote from 'unknown_pending_review' to stable learned format identifier
    if seen_count >= 5 and confidence >= 0.80:
        clean_fmt = suggested_format.lower().replace(" ", "_").replace("-", "_")
        log_format = f"learned_{clean_fmt}"
    else:
        log_format = "unknown_pending_review"

    # CRITICAL: Re-extract all variable values FRESH from the current line
    # (Never reuse cached literal values from previous events)
    user_val = (
        _clean_val(raw_kv.get("usr") or raw_kv.get("user") or raw_kv.get("username") or raw_kv.get("targetusername") or raw_kv.get("suser"))
    )
    src_ip = _clean_val(raw_kv.get("src") or raw_kv.get("src_ip") or raw_kv.get("client_ip") or raw_kv.get("ip"))
    dst_ip = _clean_val(raw_kv.get("dst") or raw_kv.get("dst_ip") or raw_kv.get("server_ip"))
    src_port = coerce_int(raw_kv.get("src_port") or raw_kv.get("sport"))
    dst_port = coerce_int(raw_kv.get("dst_port") or raw_kv.get("dport"))
    act_val = _clean_val(raw_kv.get("action") or raw_kv.get("act") or raw_kv.get("method") or raw_kv.get("op"))

    # Service / App name
    service_name = (
        _strip_key_prefix("svc", raw_kv.get("svc"))
        or _strip_key_prefix("service", raw_kv.get("service"))
        or _strip_key_prefix("app", raw_kv.get("app"))
    )

    # Timestamp extraction fresh from current line
    raw_ts = (
        _strip_key_prefix("ts", raw_kv.get("ts"))
        or _strip_key_prefix("time", raw_kv.get("time"))
        or _strip_key_prefix("timestamp", raw_kv.get("timestamp"))
    )
    parsed_dt = parse_timestamp(str(raw_ts)) if raw_ts else None

    # Message extraction: specific 'msg'/'message' key or raw_stripped
    msg_from_kv = _strip_key_prefix("msg", raw_kv.get("msg")) or _strip_key_prefix("message", raw_kv.get("message"))
    message = msg_from_kv or raw_stripped

    # Severity resolution
    lvl_from_kv = _strip_key_prefix("lvl", raw_kv.get("lvl")) or _strip_key_prefix("level", raw_kv.get("level"))
    raw_severity = lvl_from_kv or "Informational"
    severity_map = {
        "warn": "Medium",
        "warning": "Medium",
        "err": "High",
        "error": "High",
        "crit": "Critical",
        "critical": "Critical",
        "fatal": "Critical",
        "info": "Informational",
        "informational": "Informational",
        "debug": "Informational",
        "trace": "Informational",
    }
    norm_severity = severity_map.get(str(raw_severity).lower(), str(raw_severity))

    # Build unmapped metadata
    unmapped: Dict[str, Any] = {
        "fingerprint": fp_hash,
        "template_seen_count": seen_count,
        "ollama_suggested_format": suggested_format,
        "ollama_suggested_vendor": vendor,
        "ollama_suggested_product": product,
        "ollama_confidence": confidence,
    }
    for k, v in raw_kv.items():
        k_lower = k.lower()
        if k_lower not in ("ts", "time", "timestamp", "lvl", "level", "msg", "message", "svc", "service", "usr", "user", "username", "src", "src_ip", "dst", "dst_ip", "sport", "dport"):
            unmapped[k] = _coerce_primitive(_strip_key_prefix(k, v))

    # Construct UnifiedEvent
    mapped: Dict[str, Any] = {
        "raw_event": raw_line,
        "log_format": log_format,
        "timestamp": parsed_dt,
        "service_name": _clean_val(service_name),
        "vendor": _clean_val(vendor),
        "product": _clean_val(product),
        "message": _clean_val(message),
        "src_ip": _clean_val(src_ip),
        "dst_ip": _clean_val(dst_ip),
        "src_port": src_port,
        "dst_port": dst_port,
        "user": _clean_val(user_val),
        "activity_name": _clean_val(act_val),
        "severity": norm_severity,
        "category_name": "System Activity",
        "unmapped": unmapped,
    }

    # Clean None values
    mapped = {k: v for k, v in mapped.items() if v is not None}
    return UnifiedEvent(**mapped)
