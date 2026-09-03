"""
Normalization and enrichment engine.
Applies category, class, activity, severity, and status inference rules.
Optimized for in-place mutation without Pydantic serialization round-trips.
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
    """Post-parse normalization & heuristic enrichment on UnifiedEvent directly in-place."""
    proc = event.product
    if proc:
        tax = resolve_process_taxonomy(proc)
        if tax:
            if not event.vendor and tax.get("vendor"):
                event.vendor = tax["vendor"]
            if not event.category_name and tax.get("category_name"):
                event.category_name = tax["category_name"]
            if not event.category_uid and tax.get("category_uid"):
                event.category_uid = tax["category_uid"]
            if not event.class_name and tax.get("class_name"):
                event.class_name = tax["class_name"]
            if not event.class_uid and tax.get("class_uid"):
                event.class_uid = tax["class_uid"]
            if not event.activity_name and tax.get("activity_name"):
                event.activity_name = tax["activity_name"]
            if not event.activity_id and tax.get("activity_id"):
                event.activity_id = tax["activity_id"]

    # Category
    cat = event.category_name
    if cat:
        key = cat.strip().lower().replace(" ", "_").replace("&", "and")
        if key in CATEGORY_MAP:
            event.category_name = CATEGORY_MAP[key][0]
            if not event.category_uid:
                event.category_uid = CATEGORY_MAP[key][1]

    # Class
    if cat and not event.class_name:
        key = cat.strip().lower().replace(" ", "_").replace("&", "and")
        if key in CLASS_MAP:
            event.class_name, event.class_uid = CLASS_MAP[key]
    elif event.class_name and not event.class_uid:
        key = event.class_name.strip().lower().replace(" ", "_").replace("&", "and")
        if key in CLASS_MAP:
            event.class_name, event.class_uid = CLASS_MAP[key]

    # Activity
    act = event.activity_name
    if act and not event.activity_id:
        key = act.strip().lower()
        if key in ACTIVITY_MAP:
            event.activity_name, event.activity_id = ACTIVITY_MAP[key]

    # Type composite
    if event.class_name and event.activity_name and not event.type_name:
        event.type_name = f"{event.class_name}: {event.activity_name}"
    if event.class_uid is not None and event.activity_id is not None and event.type_uid is None:
        event.type_uid = event.class_uid * 100 + event.activity_id

    # Severity
    sev = event.severity
    if sev:
        sev_key = str(sev).strip().lower()
        if sev_key in SEVERITY_NAME_MAP:
            event.severity, event.severity_id = SEVERITY_NAME_MAP[sev_key]
        elif event.severity_id is None:
            event.severity_id = SEVERITY_ID_MAP.get(sev_key, 0)

    # Status
    st = event.status
    if st and event.status_id is None:
        event.status_id = STATUS_ID_MAP.get(st.strip().lower(), 0)

    # Heuristic vendor/product inference if missing
    raw_lower = event.raw_event.lower()
    if not event.vendor:
        if "cisco" in raw_lower:
            event.vendor = "Cisco"
        elif "fortinet" in raw_lower or "fortigate" in raw_lower:
            event.vendor = "Fortinet"
        elif "palo alto" in raw_lower or "pan-os" in raw_lower:
            event.vendor = "Palo Alto Networks"
        elif "microsoft" in raw_lower or "windows" in raw_lower or "eventid" in raw_lower:
            event.vendor = "Microsoft"
            if not event.product:
                event.product = "Windows"
        elif "sshd" in raw_lower or "sudo" in raw_lower or "systemd" in raw_lower:
            event.vendor = "Linux"
            if not event.product:
                event.product = "Syslog"
        elif "zeek" in raw_lower or "bro" in raw_lower:
            event.vendor = "Zeek"

    # Severity heuristic fallback (ONLY if severity is not already set)
    if not event.severity or event.severity in ("Unknown", "unknown"):
        if any(w in raw_lower for w in ("error", "fail", "failed", "denied", "block", "refuse", "critical", "fatal", "attack")):
            event.severity = "High"
            event.severity_id = 4
        elif any(w in raw_lower for w in ("warn", "warning", "suspicious", "timeout")):
            event.severity = "Medium"
            event.severity_id = 3
        else:
            event.severity = "Informational"
            event.severity_id = 1

    return event
