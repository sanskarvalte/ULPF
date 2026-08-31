"""
Normalization and enrichment engine.
Applies category, class, activity, severity, and status inference rules.
"""

from __future__ import annotations

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

    # Severity
    sev = mapped.get("severity")
    if sev:
        sev_key = str(sev).strip().lower()
        if sev_key in SEVERITY_NAME_MAP:
            mapped["severity"], mapped["severity_id"] = SEVERITY_NAME_MAP[sev_key]
        elif "severity_id" not in mapped:
            mapped["severity_id"] = SEVERITY_ID_MAP.get(sev_key, 0)

    # Status
    st = mapped.get("status")
    if st and "status_id" not in mapped:
        mapped["status_id"] = STATUS_ID_MAP.get(st.strip().lower(), 0)


def normalize_event(event: UnifiedEvent) -> UnifiedEvent:
    """Post-parse normalization & heuristic enrichment on UnifiedEvent."""
    d = event.model_dump()
    enrich_classification(d)

    # Heuristic vendor/product inference if missing
    raw_lower = event.raw_event.lower()
    if not d.get("vendor"):
        if "cisco" in raw_lower:
            d["vendor"] = "Cisco"
        elif "fortinet" in raw_lower or "fortigate" in raw_lower:
            d["vendor"] = "Fortinet"
        elif "palo alto" in raw_lower or "pan-os" in raw_lower:
            d["vendor"] = "Palo Alto Networks"
        elif "microsoft" in raw_lower or "windows" in raw_lower or "eventid" in raw_lower:
            d["vendor"] = "Microsoft"
            d.setdefault("product", "Windows")
        elif "sshd" in raw_lower or "sudo" in raw_lower or "systemd" in raw_lower:
            d["vendor"] = "Linux"
            d.setdefault("product", "Syslog")
        elif "zeek" in raw_lower or "bro" in raw_lower:
            d["vendor"] = "Zeek"

    # Severity heuristic fallback (ONLY if severity is not already set)
    if not d.get("severity") or d.get("severity") in ("Unknown", "unknown"):
        if any(w in raw_lower for w in ("error", "fail", "failed", "denied", "block", "refuse", "critical", "fatal", "attack")):
            d["severity"] = "High"
            d["severity_id"] = 4
        elif any(w in raw_lower for w in ("warn", "warning", "suspicious", "timeout")):
            d["severity"] = "Medium"
            d["severity_id"] = 3
        else:
            d["severity"] = "Informational"
            d["severity_id"] = 1

    return UnifiedEvent(**d)
