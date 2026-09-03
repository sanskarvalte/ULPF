"""
XML log parser for ULPF.
Supports multi-record XML logs (e.g. IBM InfoSphere Information Server audit logs,
Windows EVTX/EventLog XML, Java logging XMLFormatter) as well as single-record XML payloads.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from app.models.event_schema import UnifiedEvent
from app.normalization.field_mapping import (
    COMMON_FIELD_MAP,
    coerce_bool,
    coerce_int,
    parse_timestamp,
)
from app.parsers.base import BaseParser

# Deterministic Java / XML logging level to OCSF Severity mapping
_JAVA_LEVEL_SEVERITY_MAP: Dict[str, Tuple[str, int]] = {
    "FINEST": ("Informational", 1),
    "FINER": ("Informational", 1),
    "FINE": ("Informational", 1),
    "CONFIG": ("Informational", 1),
    "DEBUG": ("Informational", 1),
    "INFO": ("Informational", 1),
    "INFORMATIONAL": ("Informational", 1),
    "NOTICE": ("Informational", 1),
    "WARNING": ("Medium", 3),
    "WARN": ("Medium", 3),
    "SEVERE": ("High", 4),
    "ERROR": ("High", 4),
    "CRITICAL": ("Critical", 5),
    "FATAL": ("Critical", 5),
}

# Audit & event-type <key> to OCSF Taxonomy mapping
_EVENT_KEY_TAXONOMY: Dict[str, Dict[str, Any]] = {
    "info.audit.session.LOGIN": {
        "category_name": "Identity & Access Management", "category_uid": 3,
        "class_name": "Authentication", "class_uid": 3002,
        "activity_name": "Logon", "activity_id": 1,
    },
    "info.audit.session.LOGOUT": {
        "category_name": "Identity & Access Management", "category_uid": 3,
        "class_name": "Authentication", "class_uid": 3002,
        "activity_name": "Logoff", "activity_id": 2,
    },
    "info.audit.user.ADD_USER": {
        "category_name": "Identity & Access Management", "category_uid": 3,
        "class_name": "Account Change", "class_uid": 3001,
        "activity_name": "Create", "activity_id": 1,
    },
    "info.audit.user.MODIFY_USER": {
        "category_name": "Identity & Access Management", "category_uid": 3,
        "class_name": "Account Change", "class_uid": 3001,
        "activity_name": "Update", "activity_id": 2,
    },
    "info.audit.user.UPDATE_USER": {
        "category_name": "Identity & Access Management", "category_uid": 3,
        "class_name": "Account Change", "class_uid": 3001,
        "activity_name": "Update", "activity_id": 2,
    },
    "info.audit.user.DELETE_USER": {
        "category_name": "Identity & Access Management", "category_uid": 3,
        "class_name": "Account Change", "class_uid": 3001,
        "activity_name": "Delete", "activity_id": 3,
    },
    "info.audit.role.ASSIGN_USER_ROLES": {
        "category_name": "Identity & Access Management", "category_uid": 3,
        "class_name": "Account Change", "class_uid": 3001,
        "activity_name": "Update", "activity_id": 2,
    },
    "info.audit.role.UNASSIGN_USER_ROLES": {
        "category_name": "Identity & Access Management", "category_uid": 3,
        "class_name": "Account Change", "class_uid": 3001,
        "activity_name": "Update", "activity_id": 2,
    },
    "info.audit.user.SET_CREDENTIAL": {
        "category_name": "Identity & Access Management", "category_uid": 3,
        "class_name": "Account Change", "class_uid": 3001,
        "activity_name": "Update", "activity_id": 2,
    },
}


def _resolve_vendor_product(
    logger_val: Optional[str],
    catalog_val: Optional[str],
    source_val: Optional[str],
    explicit_vendor: Optional[str],
    explicit_product: Optional[str],
) -> Tuple[Optional[str], Optional[str]]:
    """Determine vendor and product dynamically from XML content rather than hardcoding."""
    if explicit_vendor:
        return explicit_vendor, (explicit_product or "System")

    indicators = [logger_val or "", catalog_val or "", source_val or ""]
    combined = " ".join(indicators)

    if "com.ibm" in combined or "com.ascential" in combined:
        return "IBM", "InfoSphere Information Server"
    if "org.apache" in combined:
        return "Apache", "Apache Server"
    if "Microsoft-Windows" in combined or "Microsoft.Windows" in combined:
        return "Microsoft", "Windows"

    return None, None


def _resolve_taxonomy_from_key(key_val: Optional[str]) -> Optional[Dict[str, Any]]:
    """Resolve OCSF taxonomy from <key> identifier."""
    if not key_val:
        return None

    # Exact match
    if key_val in _EVENT_KEY_TAXONOMY:
        return _EVENT_KEY_TAXONOMY[key_val]

    # Pattern match
    k_upper = key_val.upper()
    if "LOGIN" in k_upper or "LOGON" in k_upper:
        return {
            "category_name": "Identity & Access Management", "category_uid": 3,
            "class_name": "Authentication", "class_uid": 3002,
            "activity_name": "Logon", "activity_id": 1,
        }
    if "LOGOUT" in k_upper or "LOGOFF" in k_upper:
        return {
            "category_name": "Identity & Access Management", "category_uid": 3,
            "class_name": "Authentication", "class_uid": 3002,
            "activity_name": "Logoff", "activity_id": 2,
        }
    if "ADD_USER" in k_upper or "CREATE_USER" in k_upper:
        return {
            "category_name": "Identity & Access Management", "category_uid": 3,
            "class_name": "Account Change", "class_uid": 3001,
            "activity_name": "Create", "activity_id": 1,
        }
    if "ASSIGN" in k_upper or "ROLE" in k_upper or "CREDENTIAL" in k_upper or "MODIFY" in k_upper:
        return {
            "category_name": "Identity & Access Management", "category_uid": 3,
            "class_name": "Account Change", "class_uid": 3001,
            "activity_name": "Update", "activity_id": 2,
        }
    if "DELETE" in k_upper or "REMOVE" in k_upper:
        return {
            "category_name": "Identity & Access Management", "category_uid": 3,
            "class_name": "Account Change", "class_uid": 3001,
            "activity_name": "Delete", "activity_id": 3,
        }

    return None


def _extract_single_record(elem: ET.Element) -> UnifiedEvent:
    """Parse a single XML record element into a UnifiedEvent."""
    raw_fragment = ET.tostring(elem, encoding="unicode").strip()

    # 1. Collect all elements and attributes, preserving repeating tags as lists
    tag_values: Dict[str, List[str]] = {}

    # Root element attributes
    for attr_name, attr_val in elem.attrib.items():
        if attr_val and attr_val.strip():
            tag_values.setdefault(attr_name.strip(), []).append(attr_val.strip())

    # Child elements and attributes
    for child in elem.iter():
        if child is elem:
            continue
        tag = child.tag.split("}")[-1] if "}" in child.tag else child.tag
        c_text = (child.text or "").strip()

        # Handle Sysmon/Windows <Data Name="Key">Value</Data>
        if tag.lower() == "data" and "Name" in child.attrib:
            data_key = child.attrib["Name"].strip()
            if c_text:
                tag_values.setdefault(data_key, []).append(c_text)

        if len(child) == 0 and c_text:
            tag_values.setdefault(tag.strip(), []).append(c_text)

        for attr_name, attr_val in child.attrib.items():
            if attr_val and attr_val.strip():
                tag_values.setdefault(attr_name.strip(), []).append(attr_val.strip())
                # Handle Provider Name=... or TimeCreated SystemTime=...
                if attr_name.lower() in ("systemtime", "timecreated"):
                    tag_values.setdefault("SystemTime", []).append(attr_val.strip())

    mapped: Dict[str, Any] = {}
    unmapped: Dict[str, Any] = {}

    # 2. Timestamp extraction (<date> or <millis> or standard timestamp fields)
    dt: Optional[datetime] = None
    date_val = (
        tag_values.get("date", [None])[0]
        or tag_values.get("SystemTime", [None])[0]
        or tag_values.get("Timestamp", [None])[0]
        or tag_values.get("timestamp", [None])[0]
        or tag_values.get("EventTime", [None])[0]
        or tag_values.get("TimeCreated", [None])[0]
    )
    millis_val = tag_values.get("millis", [None])[0]

    if date_val:
        # ISO 8601 parsing
        try:
            d_clean = date_val.replace("Z", "+00:00")
            dt = datetime.fromisoformat(d_clean)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
        except Exception:
            dt = parse_timestamp(date_val)

    if dt is None and millis_val and millis_val.isdigit():
        try:
            dt = datetime.fromtimestamp(float(millis_val) / 1000.0, tz=timezone.utc)
        except Exception:
            pass

    if dt is not None:
        mapped["timestamp"] = dt

    # 3. Severity extraction (<level> or <severity>)
    level_val = tag_values.get("level", [None])[0] or tag_values.get("Level", [None])[0] or tag_values.get("severity", [None])[0] or tag_values.get("Severity", [None])[0]
    if level_val:
        if level_val.isdigit():
            # Windows EventLog Level mapping: 1=Critical, 2=Error(High), 3=Warning(Med), 4=Info, 5=Verbose
            w_lvl = int(level_val)
            w_map = {1: ("Critical", 5), 2: ("High", 4), 3: ("Medium", 3), 4: ("Informational", 1), 5: ("Informational", 1)}
            sev_tuple = w_map.get(w_lvl, ("Informational", 1))
            mapped["severity"] = sev_tuple[0]
            mapped["severity_id"] = sev_tuple[1]
        else:
            sev_tuple = _JAVA_LEVEL_SEVERITY_MAP.get(level_val.upper())
            if sev_tuple:
                mapped["severity"] = sev_tuple[0]
                mapped["severity_id"] = sev_tuple[1]
            else:
                mapped["severity"] = level_val.capitalize()

    # 4. Message extraction
    msg_val = tag_values.get("message", [None])[0] or tag_values.get("Message", [None])[0] or tag_values.get("msg", [None])[0]
    if msg_val:
        mapped["message"] = msg_val

    # 5. Vendor & Product determination
    logger_val = tag_values.get("logger", [None])[0]
    catalog_val = tag_values.get("catalog", [None])[0]
    source_val = tag_values.get("source", [None])[0] or tag_values.get("Source", [None])[0] or tag_values.get("host", [None])[0]
    explicit_vendor = tag_values.get("vendor", [None])[0] or tag_values.get("Vendor", [None])[0]
    explicit_product = tag_values.get("product", [None])[0] or tag_values.get("Product", [None])[0]
    names_list = tag_values.get("Name", [])

    if any("Sysmon" in n for n in names_list):
        mapped["vendor"] = "Microsoft"
        mapped["product"] = "Sysmon"
    else:
        vendor, product = _resolve_vendor_product(logger_val, catalog_val, source_val, explicit_vendor, explicit_product)
        if vendor:
            mapped["vendor"] = vendor
        if product:
            mapped["product"] = product

    lower_tag_map: Dict[str, Any] = {k.lower(): v[0] if len(v) == 1 else v for k, v in tag_values.items()}

    # 6. Service / Subsystem name
    svc_val = logger_val or lower_tag_map.get("service_name") or lower_tag_map.get("service") or source_val
    if svc_val and "service_name" not in mapped:
        mapped["service_name"] = svc_val

    # 7. Taxonomy resolution from <key> or <Category>/<Action> or <EventID>
    event_id = lower_tag_map.get("eventid")
    if event_id == "3" or (mapped.get("product") == "Sysmon" and event_id == "3"):
        mapped["category_name"] = "Network Activity"
        mapped["class_name"] = "Network Activity"
        mapped["activity_name"] = "Connect"
    elif event_id == "1":
        mapped["category_name"] = "System Activity"
        mapped["class_name"] = "Process Activity"
        mapped["activity_name"] = "Launch"
    elif event_id == "4624":
        mapped["category_name"] = "Identity & Access Management"
        mapped["class_name"] = "Authentication"
        mapped["activity_name"] = "Logon"
    else:
        key_val = lower_tag_map.get("key") or lower_tag_map.get("action")
        tax = _resolve_taxonomy_from_key(key_val)
        if tax:
            mapped["category_name"] = tax["category_name"]
            mapped["category_uid"] = tax["category_uid"]
            mapped["class_name"] = tax["class_name"]
            mapped["class_uid"] = tax["class_uid"]
            mapped["activity_name"] = tax["activity_name"]
            mapped["activity_id"] = tax["activity_id"]
            mapped["type_name"] = f"{tax['class_name']}: {tax['activity_name']}"
            mapped["type_uid"] = tax["class_uid"] * 100 + tax["activity_id"]
        else:
            cat_val = lower_tag_map.get("category")
            act_val = lower_tag_map.get("action")
            if cat_val:
                mapped["category_name"] = cat_val
            if act_val:
                mapped["activity_name"] = act_val

    # 8. User Identity extraction
    user_val = (
        lower_tag_map.get("user")
        or lower_tag_map.get("username")
        or lower_tag_map.get("targetusername")
        or lower_tag_map.get("userid")
        or lower_tag_map.get("suser")
    )
    if not user_val and "param" in tag_values and tag_values["param"]:
        # In audit logs, param[0] is typically the principal username
        user_val = tag_values["param"][0]

    if user_val:
        mapped["user"] = user_val

    # 9. Network / Host / Session fields
    src_ip = (
        lower_tag_map.get("source_ip")
        or lower_tag_map.get("sourceip")
        or lower_tag_map.get("src_ip")
        or lower_tag_map.get("ipaddress")
        or lower_tag_map.get("client_ip")
        or lower_tag_map.get("src")
    )
    dst_ip = (
        lower_tag_map.get("destination_ip")
        or lower_tag_map.get("destinationip")
        or lower_tag_map.get("dst_ip")
        or lower_tag_map.get("server_ip")
        or lower_tag_map.get("dst")
    )
    src_port = (
        lower_tag_map.get("source_port")
        or lower_tag_map.get("sourceport")
        or lower_tag_map.get("src_port")
        or lower_tag_map.get("sport")
    )
    dst_port = (
        lower_tag_map.get("destination_port")
        or lower_tag_map.get("destinationport")
        or lower_tag_map.get("dst_port")
        or lower_tag_map.get("dport")
    )
    src_host = lower_tag_map.get("host") or lower_tag_map.get("hostname") or lower_tag_map.get("src_hostname")
    sess_uid = lower_tag_map.get("requestid") or lower_tag_map.get("session_id") or lower_tag_map.get("session_uid")

    if src_ip:
        mapped["src_ip"] = str(src_ip)
    if dst_ip:
        mapped["dst_ip"] = str(dst_ip)
    if src_port:
        mapped["src_port"] = coerce_int(src_port)
    if dst_port:
        mapped["dst_port"] = coerce_int(dst_port)
    if src_host:
        mapped["src_hostname"] = str(src_host)
    if sess_uid:
        mapped["session_uid"] = str(sess_uid)

    # 10. Status
    status_val = lower_tag_map.get("status")
    if status_val:
        mapped["status"] = str(status_val).capitalize()
        mapped["status_id"] = 1 if str(status_val).lower() in ("success", "ok", "0") else 2

    # 11. Preserve ALL tags in unmapped (lists for repeating tags, strings for single tags)
    for tag_k, tag_v_list in tag_values.items():
        if len(tag_v_list) > 1:
            unmapped[tag_k] = tag_v_list
        else:
            unmapped[tag_k] = tag_v_list[0]

    mapped["log_format"] = "xml"
    mapped["raw_event"] = raw_fragment
    if unmapped:
        mapped["unmapped"] = unmapped

    return UnifiedEvent(**mapped)


def parse_xml_log_all(raw: str) -> List[UnifiedEvent]:
    """
    Parse an XML document and emit ONE UnifiedEvent per record element.
    Supports sibling <record>, <Event>, <logEntry> elements under a container root,
    or single-record XML documents.
    """
    cleaned = raw.strip()
    if not cleaned:
        return []

    # Strip DOCTYPE if present to avoid external entity resolution issues
    cleaned_no_doctype = re.sub(r"<!DOCTYPE[^>]*>", "", cleaned)

    try:
        root = ET.fromstring(cleaned_no_doctype)
    except ET.ParseError:
        # Fallback to original text if regex affected it
        root = ET.fromstring(cleaned)

    # Check for repeating record containers
    # Standard record tag names
    record_tags = {"record", "event", "logentry", "entry", "item", "row", "audit"}

    matching_children = [
        child for child in list(root)
        if (child.tag.split("}")[-1] if "}" in child.tag else child.tag).lower() in record_tags
    ]

    if matching_children:
        return [_extract_single_record(child) for child in matching_children]

    # If root has multiple children with identical tag names, treat each as a record
    children = list(root)
    if len(children) > 1:
        first_tag = children[0].tag
        if all(c.tag == first_tag for c in children):
            return [_extract_single_record(c) for c in children]

    # Single-record document
    return [_extract_single_record(root)]


def parse_xml_log(raw: str) -> UnifiedEvent:
    """
    Parse XML and return the first UnifiedEvent.
    """
    events = parse_xml_log_all(raw)
    if events:
        return events[0]
    raise ValueError("No valid XML records found in input.")


class XmlParser(BaseParser):
    format_name = "xml"

    def parse(self, raw: str) -> UnifiedEvent:
        return parse_xml_log(raw)

    def parse_all(self, raw: str) -> List[UnifiedEvent]:
        return parse_xml_log_all(raw)
