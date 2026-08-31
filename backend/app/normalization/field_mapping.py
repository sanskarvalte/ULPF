"""
Field dictionary mapping heterogeneous log keys to OCSF standard schema.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Optional

COMMON_FIELD_MAP: Dict[str, str] = {
    # Identity
    "event_id": "raw_event_id",
    "eventid": "raw_event_id",
    "id": "raw_event_id",
    "eventId": "raw_event_id",
    # Temporal
    "timestamp": "timestamp",
    "ts": "timestamp",
    "time": "timestamp",
    "event_time": "timestamp",
    "@timestamp": "timestamp",
    "datetime": "timestamp",
    "EventReceivedTime": "timestamp",
    "SourceModuleName": "log_name",
    # Classification
    "category": "category_name",
    "event_category": "category_name",
    "cat": "category_name",
    "action": "activity_name",
    "event_action": "activity_name",
    "act": "activity_name",
    "severity": "severity",
    "level": "severity",
    "sev": "severity",
    "severity_id": "severity_id",
    "status": "status",
    "outcome": "status",
    "status_code": "status_code",
    "status_detail": "status_detail",
    "message": "message",
    "msg": "message",
    "description": "message",
    # Network
    "src_ip": "src_ip",
    "source_ip": "src_ip",
    "srcaddr": "src_ip",
    "client_ip": "src_ip",
    "src": "src_ip",
    "srcIp": "src_ip",
    "ipaddress": "src_ip",
    "ip_address": "src_ip",
    "dst_ip": "dst_ip",
    "destination_ip": "dst_ip",
    "dstaddr": "dst_ip",
    "server_ip": "dst_ip",
    "dst": "dst_ip",
    "dstIp": "dst_ip",
    "src_port": "src_port",
    "source_port": "src_port",
    "sport": "src_port",
    "srcPort": "src_port",
    "ipport": "src_port",
    "dst_port": "dst_port",
    "destination_port": "dst_port",
    "dport": "dst_port",
    "dstPort": "dst_port",
    "src_hostname": "src_hostname",
    "dst_hostname": "dst_hostname",
    "shost": "src_hostname",
    "dhost": "dst_hostname",
    "protocol": "protocol",
    "proto": "protocol",
    "direction": "direction",
    "bytes": "traffic_bytes",
    "in": "traffic_bytes",
    "out": "traffic_bytes",
    "packets": "traffic_packets",
    # Actor / IAM
    "user": "user",
    "username": "user",
    "userid": "user",
    "actor": "user",
    "user_name": "user",
    "targetusername": "user",
    "targetdomainname": "user_domain",
    "suser": "user",
    "duser": "user",
    "user_uid": "user_uid",
    "user_type": "user_type",
    "user_domain": "user_domain",
    "domain": "user_domain",
    "auth_protocol": "auth_protocol",
    "is_mfa": "is_mfa",
    "is_remote": "is_remote",
    "logon_type": "logon_type",
    "service_name": "service_name",
    "service": "service_name",
    "source": "service_name",
    "app": "service_name",
    "host": "src_hostname",
    # Session
    "session_id": "session_uid",
    "session_uid": "session_uid",
    "requestid": "session_uid",
    "request_id": "session_uid",
    "externalId": "session_uid",
    # Metadata
    "vendor": "vendor",
    "DeviceVendor": "vendor",
    "product": "product",
    "DeviceProduct": "product",
    "product_version": "product_version",
    "DeviceVersion": "product_version",
    "log_name": "log_name",
}


def parse_timestamp(
    value: Any,
    default_year: Optional[int] = None,
    reference_date: Optional[datetime] = None,
) -> Optional[datetime]:
    """
    Parse string/numeric timestamp into standard UTC datetime.
    If BSD syslog format is encountered without a year, uses default_year,
    reference_date.year, or current UTC year as inference.
    """
    if value is None:
        return None
    if isinstance(value, datetime):
        return value
    if isinstance(value, (int, float)):
        try:
            return datetime.fromtimestamp(value, tz=timezone.utc)
        except Exception:
            return None
    if isinstance(value, str):
        val = value.strip()
        if not val:
            return None

        # Try fast ISO 8601 parsing
        try:
            return datetime.fromisoformat(val.replace("Z", "+00:00"))
        except Exception:
            pass

        # Determine fallback year for year-less timestamps
        if default_year is not None:
            target_year = default_year
        elif reference_date is not None:
            target_year = reference_date.year
        else:
            target_year = datetime.now(timezone.utc).year

        # Handle ISO and syslog formats
        for fmt in (
            "%Y-%m-%dT%H:%M:%S%z",
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%dT%H:%M:%S.%f%z",
            "%Y-%m-%dT%H:%M:%S.%fZ",
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%d %H:%M:%S,%f",
            "%b %d %H:%M:%S",
            "%b  %d %H:%M:%S",
        ):
            try:
                dt = datetime.strptime(val, fmt)
                if dt.year == 1900:  # Syslog year inference
                    dt = dt.replace(year=target_year)
                return dt
            except ValueError:
                continue
    return None


def coerce_int(value: Any) -> Optional[int]:
    """Safely coerce value to int."""
    if value is None:
        return None
    try:
        return int(value)
    except (ValueError, TypeError):
        return None


def coerce_bool(value: Any) -> Optional[bool]:
    """Safely coerce value to bool."""
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in ("true", "1", "yes", "t", "y")
    return bool(value)
