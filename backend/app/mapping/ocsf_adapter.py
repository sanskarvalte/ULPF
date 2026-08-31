"""
OCSF JSON Schema Adapter.
Converts UnifiedEvent instances into hierarchical OCSF v1.1.0 JSON format for SIEM/Data Lake integration.
"""

from __future__ import annotations

from typing import Any, Dict

from app.models.event_schema import UnifiedEvent


def to_ocsf_json(event: UnifiedEvent) -> Dict[str, Any]:
    """Convert a flat UnifiedEvent into official hierarchical OCSF JSON object."""
    ocsf: Dict[str, Any] = {
        "metadata": {
            "uid": event.event_id,
            "original_event_uid": event.raw_event_id,
            "version": "1.1.0",
            "product": {
                "vendor_name": event.vendor or "Unknown",
                "name": event.product or "Unknown",
                "version": event.product_version,
            },
            "log_format": event.log_format,
            "log_name": event.log_name,
        },
        "time": event.timestamp.isoformat() if event.timestamp else None,
        "category_name": event.category_name,
        "category_uid": event.category_uid,
        "class_name": event.class_name,
        "class_uid": event.class_uid,
        "activity_name": event.activity_name,
        "activity_id": event.activity_id,
        "type_name": event.type_name,
        "type_uid": event.type_uid,
        "severity": event.severity,
        "severity_id": event.severity_id,
        "status": event.status,
        "status_id": event.status_id,
        "status_code": event.status_code,
        "status_detail": event.status_detail,
        "message": event.message,
        "raw_data": event.raw_event,
    }

    # Network endpoint objects
    if any([event.src_ip, event.src_port, event.src_hostname, event.src_endpoint_name]):
        ocsf["src_endpoint"] = {
            "ip": event.src_ip,
            "port": event.src_port,
            "hostname": event.src_hostname,
            "name": event.src_endpoint_name,
        }

    if any([event.dst_ip, event.dst_port, event.dst_hostname, event.dst_endpoint_name]):
        ocsf["dst_endpoint"] = {
            "ip": event.dst_ip,
            "port": event.dst_port,
            "hostname": event.dst_hostname,
            "name": event.dst_endpoint_name,
        }

    # Connection & Traffic
    if event.protocol or event.direction:
        ocsf["connection_info"] = {
            "protocol_name": event.protocol,
            "direction": event.direction,
        }

    if event.traffic_bytes or event.traffic_packets:
        ocsf["traffic"] = {
            "bytes": event.traffic_bytes,
            "packets": event.traffic_packets,
        }

    # IAM / Actor
    if event.user or event.user_uid or event.user_domain:
        ocsf["actor"] = {
            "user": {
                "name": event.user,
                "uid": event.user_uid,
                "type": event.user_type,
                "domain": event.user_domain,
            }
        }

    if event.unmapped:
        ocsf["unmapped"] = event.unmapped

    return {k: v for k, v in ocsf.items() if v is not None}
