"""
Normalization and enrichment engine (Node 8).
Applies category, class, activity, severity, and status inference rules.
Enforces strict losslessness substring guard against parser bugs & LLM hallucinations.
"""

from __future__ import annotations

import logging
from typing import Any, Dict

from app.models.event_schema import UnifiedEvent
from app.normalization.taxonomy import (
    ACTIVITY_MAP,
    CATEGORY_MAP,
    CLASS_MAP,
    SEVERITY_ID_MAP,
    SEVERITY_NAME_MAP,
    STATUS_ID_MAP,
    resolve_process_taxonomy,
)

from app.validation.validator import (
    get_severity_keyword_floor,
    validate_ip,
    validate_port,
    validate_severity,
    validate_status,
    validate_timestamp,
)

logger = logging.getLogger("ulpf.normalizer")

# Fields subject to strict raw_event substring verification
_GUARDED_SUBSTRING_FIELDS = (
    "src_ip",
    "dst_ip",
    "user",
    "src_hostname",
    "dst_hostname",
    "src_endpoint_name",
    "dst_endpoint_name",
    "user_domain",
    "user_uid",
    "session_uid",
)


def _apply_losslessness_guard(d: Dict[str, Any], raw_event: str) -> None:
    """
    Losslessness Guard (Node 8 requirement):
    Verify that every non-null extracted literal field value is an exact substring of the record's raw_event.
    If a parser or LLM hallucinates a field value not present in the raw event, it is nulled out,
    logged with a warning, and tracked in unmapped['traceability_warnings'].
    """
    if not raw_event:
        return

    unmapped = d.get("unmapped") or {}
    if not isinstance(unmapped, dict):
        unmapped = {}

    warnings = list(unmapped.get("traceability_warnings") or [])

    for field in _GUARDED_SUBSTRING_FIELDS:
        val = d.get(field)
        if val is not None and isinstance(val, str) and val.strip():
            # Check if literal field value exists in raw_event
            if val not in raw_event:
                # Handle IPv6 compression/expansion differences between parser and raw text
                if field in ("src_ip", "dst_ip") and ":" in val:
                    try:
                        import ipaddress
                        ip_obj = ipaddress.ip_address(val)
                        if ip_obj.exploded in raw_event or ip_obj.compressed in raw_event:
                            continue
                    except Exception:
                        pass
                logger.warning(
                    f"Losslessness guard rejected field '{field}'='{val}': value not found in raw_event."
                )
                warnings.append({
                    "field": field,
                    "rejected_value": val,
                    "reason": "Value is not a substring of raw_event",
                })
                d[field] = None

    if warnings:
        unmapped["traceability_warnings"] = warnings
        d["unmapped"] = unmapped


# ---------------------------------------------------------------------------
# Semantic activity groups
# ---------------------------------------------------------------------------

AUTHENTICATION_ACTIVITIES = {
    "login", "logon", "logout", "logoff", "authentication", "authenticate", "auth",
    "auth_success", "authentication_success", "login_success", "logon_success",
    "successful_login", "successful_logon", "auth_failed", "authentication_failed",
    "login_failed", "logon_failed", "failed_login", "failed_logon", "login_failure",
    "logon_failure", "access_denied", "invalid_login", "invalid_logon", "invalid_credentials",
}

AUTHENTICATION_FAILURE_ACTIVITIES = {
    "auth_failed", "authentication_failed", "login_failed", "logon_failed",
    "failed_login", "failed_logon", "login_failure", "logon_failure",
    "access_denied", "invalid_login", "invalid_logon", "invalid_credentials",
}

AUTHENTICATION_SUCCESS_ACTIVITIES = {
    "auth_success", "authentication_success", "login_success", "logon_success",
    "successful_login", "successful_logon", "mfa_verified",
}

QUERY_ACTIVITIES = {
    "query", "query_executed", "query_execute", "database_query", "db_query",
    "sql_query", "select", "insert", "update", "delete", "execute_query", "executed_query",
}

NETWORK_ACTIVITIES = {
    "connection", "connect", "connected", "connection_open", "open_connection",
    "connection_close", "close_connection", "disconnect", "traffic", "network",
    "packet", "http", "https", "dns", "ssh", "ftp", "rdp", "smb", "firewall",
}

SECURITY_ACTIVITIES = {
    "alert", "threat", "vulnerability", "attack", "exploit", "malware", "incident", "finding",
}


def _normalize_key(value: Any) -> str:
    """Convert a value into a normalized comparison key."""
    if value is None:
        return ""
    return str(value).strip().lower().replace("-", "_").replace(" ", "_")


def _get_activity_candidates(mapped: Dict[str, Any]) -> list[str]:
    """Extract candidate activity strings from mapped event attributes."""
    candidates: list[str] = []
    for key in (
        "activity_name",
        "action",
        "event_action",
        "operation",
        "event_type",
        "type_name",
    ):
        val = mapped.get(key)
        if val is not None and str(val).strip():
            candidates.append(_normalize_key(val))

    # Also check message prefix / keywords
    msg = mapped.get("message")
    if msg and isinstance(msg, str):
        msg_clean = _normalize_key(msg[:120])
        for token in msg_clean.split("_"):
            if len(token) >= 3:
                candidates.append(token)
    return candidates


from app.normalization.classifier import classify_event_semantics


def enrich_classification(mapped: Dict[str, Any]) -> None:
    """Enrich raw mapped fields with OCSF numeric UIDs and standard names."""
    # 1. Process / Subsystem lookup if category, class, activity, or vendor is missing
    proc = mapped.get("product")
    raw_event_lower = (mapped.get("raw_event") or "").lower()
    is_kernel_firewall = (
        proc == "kernel"
        and (
            "iptables" in raw_event_lower
            or "ufw" in raw_event_lower
            or "netfilter" in raw_event_lower
            or "action=drop" in raw_event_lower
            or "proto=" in raw_event_lower
        )
    )
    daemon_matched = False
    if proc and not is_kernel_firewall:
        tax = resolve_process_taxonomy(proc)
        if tax:
            daemon_matched = True
            if not mapped.get("vendor") and tax.get("vendor"):
                mapped["vendor"] = tax["vendor"]
            if not mapped.get("category_name") and tax.get("category_name"):
                mapped["category_name"] = tax["category_name"]
            if not mapped.get("category_uid") and tax.get("category_uid"):
                mapped["category_uid"] = tax["category_uid"]
            if not mapped.get("class_name") and tax.get("class_name"):
                mapped["class_name"] = tax["class_name"]
            if not mapped.get("class_uid") and tax.get("class_uid"):
                mapped["class_uid"] = tax["class_uid"]
            if not mapped.get("activity_name") and tax.get("activity_name"):
                mapped["activity_name"] = tax["activity_name"]
            if not mapped.get("activity_id") and tax.get("activity_id"):
                mapped["activity_id"] = tax["activity_id"]

    # 2. Evidence-based semantic classification if not already authoritatively classified
    has_authoritative_cat = (
        mapped.get("category_name")
        and mapped.get("category_name") not in ("System Activity", "unknown", "generic")
    )
    if (has_authoritative_cat or daemon_matched) and not is_kernel_firewall:
        mapped.setdefault("classification_confidence", 1.0)
        mapped.setdefault("classification_reason", f"authoritative_{mapped.get('category_name', 'daemon')}")
        mapped.setdefault("classification_evidence", [f"specified:{mapped.get('category_name')}"])
        mapped.setdefault("classification_status", "classified")
    else:
        # Evaluate multi-signal evidence across parsed fields, message, verbs, ports, protocols
        classify_event_semantics(mapped)

    # 3. Standardize Category
    cat = mapped.get("category_name")
    if cat:
        key = cat.strip().lower().replace(" ", "_").replace("&", "and")
        if key in CATEGORY_MAP:
            mapped["category_name"] = CATEGORY_MAP[key][0]
            mapped["category_uid"] = CATEGORY_MAP[key][1]

    # 4. Standardize Class
    if cat and not mapped.get("class_name"):
        key = cat.strip().lower().replace(" ", "_").replace("&", "and")
        if key in CLASS_MAP:
            mapped["class_name"], mapped["class_uid"] = CLASS_MAP[key]
    elif mapped.get("class_name") and not mapped.get("class_uid"):
        key = mapped["class_name"].strip().lower().replace(" ", "_").replace("&", "and")
        if key in CLASS_MAP:
            mapped["class_name"], mapped["class_uid"] = CLASS_MAP[key]

    # 5. Standardize Activity
    if not mapped.get("activity_name") and mapped.get("action"):
        mapped["activity_name"] = mapped["action"]
    act = mapped.get("activity_name")
    if act and not mapped.get("activity_id"):
        key = act.strip().lower()
        if key in ACTIVITY_MAP:
            mapped["activity_name"], mapped["activity_id"] = ACTIVITY_MAP[key]

    # 6. Type composite
    if mapped.get("class_name") and mapped.get("activity_name"):
        mapped.setdefault("type_name", f"{mapped['class_name']}: {mapped['activity_name']}")
    if mapped.get("class_uid") is not None and mapped.get("activity_id") is not None:
        mapped.setdefault("type_uid", mapped["class_uid"] * 100 + mapped["activity_id"])

    # 7. Severity canonical validation
    sev_name, sev_id = validate_severity(mapped.get("severity"), mapped.get("severity_id"))
    if sev_name is not None:
        mapped["severity"] = sev_name
        mapped["severity_id"] = sev_id
    elif "severity_id" in mapped and mapped["severity_id"] is None:
        mapped.pop("severity_id")

    # 8. Check if status contains an HTTP status code (e.g. 200, 404, 500)
    curr_status = mapped.get("status")
    if curr_status is not None:
        try:
            status_num = int(curr_status)
            if 100 <= status_num <= 599:
                if not mapped.get("status_code"):
                    mapped["status_code"] = str(status_num)
                if status_num < 400:
                    mapped["status"] = "Success"
                    mapped["status_id"] = 1
                else:
                    mapped["status"] = "Failure"
                    mapped["status_id"] = 2
        except (ValueError, TypeError):
            pass

    # 9. Status canonical validation
    st_name, st_id = validate_status(mapped.get("status"), mapped.get("status_id"))
    if st_name is not None:
        mapped["status"] = st_name
        mapped["status_id"] = st_id
    elif "status_id" in mapped and mapped["status_id"] is None:
        mapped.pop("status_id")

    # 10. Mirror semantic classification metadata into unmapped for backwards compatibility
    unmapped = mapped.get("unmapped")
    if not isinstance(unmapped, dict):
        unmapped = {}
    if mapped.get("classification_confidence") is not None:
        unmapped["classification_confidence"] = mapped["classification_confidence"]
    if mapped.get("classification_reason") is not None:
        unmapped["classification_reason"] = mapped["classification_reason"]
    if mapped.get("classification_evidence") is not None:
        unmapped["classification_evidence"] = mapped["classification_evidence"]
    if mapped.get("classification_status") is not None:
        unmapped["classification_status"] = mapped["classification_status"]
    if unmapped:
        mapped["unmapped"] = unmapped


def normalize_event(event: UnifiedEvent) -> UnifiedEvent:
    """
    Single convergence point for BOTH branches (rule-based parser AND human-approved/Ollama).
    Post-parse normalization, validation, enrichment, and losslessness guard.
    """
    d = event.model_dump()
    raw_event = event.raw_event or ""

    # 1. Validate Network Attributes (IPs & Ports)
    d["src_ip"] = validate_ip(d.get("src_ip"))
    d["dst_ip"] = validate_ip(d.get("dst_ip"))
    d["src_port"] = validate_port(d.get("src_port"))
    d["dst_port"] = validate_port(d.get("dst_port"))

    # 2. Validate Temporal Attributes
    if d.get("timestamp"):
        d["timestamp"] = validate_timestamp(d["timestamp"])

    # 3. Apply Losslessness Substring Guard
    _apply_losslessness_guard(d, raw_event)

    # 4. Enrich standard classifications and OCSF UIDs
    enrich_classification(d)

    # 4b. Enforce Deterministic Severity Keyword Floor
    # Explicit raw keywords (FATAL, ERROR, WARN, FAIL) are never downgraded below their floor,
    # unless an explicit structured field (e.g. "sev": "info") specifically designated it
    kw_sev_name, kw_sev_id = get_severity_keyword_floor(raw_event)
    if kw_sev_id is not None:
        curr_sev_id = d.get("severity_id")
        has_explicit_structured_info = (
            ('"sev": "info"' in raw_event or '"sev":"info"' in raw_event or '"level": "info"' in raw_event or '"level":"info"' in raw_event or '"sev": "trace"' in raw_event or '"sev":"trace"' in raw_event)
            or ('sev=info' in raw_event.lower() or 'level=info' in raw_event.lower())
        )
        is_authoritative_source = (
            d.get("vendor") == "Cisco"
            or has_explicit_structured_info
        )
        if (curr_sev_id is None or curr_sev_id == 0 or curr_sev_id < kw_sev_id) and not is_authoritative_source:
            d["severity"] = kw_sev_name
            d["severity_id"] = kw_sev_id

    # 5. Clean up any empty string fields to None
    for k in ("src_hostname", "dst_hostname", "src_endpoint_name", "dst_endpoint_name", "user", "vendor", "product", "service_name"):
        if d.get(k) is not None and isinstance(d[k], str) and not d[k].strip():
            d[k] = None

    return UnifiedEvent(**d)
