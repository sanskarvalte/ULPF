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


def enrich_classification(mapped: Dict[str, Any]) -> None:
    """Enrich raw mapped fields with OCSF numeric UIDs and standard names."""
    # Process / Subsystem lookup if category, class, activity, or vendor is missing
    proc = mapped.get("product")
    if proc:
        tax = resolve_process_taxonomy(proc)
        if tax:
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

    # Category
    cat = mapped.get("category_name")
    if cat:
        key = cat.strip().lower().replace(" ", "_").replace("&", "and")
        if key in CATEGORY_MAP:
            mapped["category_name"] = CATEGORY_MAP[key][0]
            mapped.setdefault("category_uid", CATEGORY_MAP[key][1])

    # Class
    if cat and "class_name" not in mapped:
        key = cat.strip().lower().replace(" ", "_").replace("&", "and")
        if key in CLASS_MAP:
            mapped["class_name"], mapped["class_uid"] = CLASS_MAP[key]
    elif mapped.get("class_name") and "class_uid" not in mapped:
        key = mapped["class_name"].strip().lower().replace(" ", "_").replace("&", "and")
        if key in CLASS_MAP:
            mapped["class_name"], mapped["class_uid"] = CLASS_MAP[key]

    # Activity
    act = mapped.get("activity_name")
    if act and "activity_id" not in mapped:
        key = act.strip().lower()
        if key in ACTIVITY_MAP:
            mapped["activity_name"], mapped["activity_id"] = ACTIVITY_MAP[key]

    # Type composite
    if "class_name" in mapped and "activity_name" in mapped:
        mapped.setdefault("type_name", f"{mapped['class_name']}: {mapped['activity_name']}")
    if mapped.get("class_uid") is not None and mapped.get("activity_id") is not None:
        mapped.setdefault("type_uid", mapped["class_uid"] * 100 + mapped["activity_id"])

    # Severity canonical validation
    sev_name, sev_id = validate_severity(mapped.get("severity"), mapped.get("severity_id"))
    if sev_name is not None:
        mapped["severity"] = sev_name
        mapped["severity_id"] = sev_id
    elif "severity_id" in mapped and mapped["severity_id"] is None:
        mapped.pop("severity_id")

    # Status canonical validation
    st_name, st_id = validate_status(mapped.get("status"), mapped.get("status_id"))
    if st_name is not None:
        mapped["status"] = st_name
        mapped["status_id"] = st_id
    elif "status_id" in mapped and mapped["status_id"] is None:
        mapped.pop("status_id")


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
