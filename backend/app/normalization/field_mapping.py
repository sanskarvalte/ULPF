"""
Field dictionary mapping heterogeneous log keys to OCSF standard schema.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Dict, Optional

COMMON_FIELD_MAP: Dict[str, str] = {
    # Identity & Event Type Markers (never overwrite raw_event_id SHA-256 hash)
    "event_id": "status_code",
    "eventid": "status_code",
    "eventId": "status_code",
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
    "action": "action",
    "event_action": "action",
    "act": "action",
    "method": "action",
    "http_method": "action",
    "activity_name": "activity_name",
    "activity": "activity_name",
    "severity": "severity",
    "level": "severity",
    "sev": "severity",
    "severity_id": "severity_id",
    "status": "status",
    "outcome": "status",
    "result": "status",
    "status_code": "status_code",
    "statuscode": "status_code",
    "code": "status_code",
    "status_detail": "status_detail",
    "reason": "status_detail",
    "message": "message",
    "msg": "message",
    "error": "message",
    "err": "message",
    "description": "message",
    # Network
    "ip": "src_ip",
    "src_ip": "src_ip",
    "source_ip": "src_ip",
    "srcaddr": "src_ip",
    "srcip": "src_ip",
    "client_ip": "src_ip",
    "clientip": "src_ip",
    "client": "src_ip",
    "src": "src_ip",
    "srcIp": "src_ip",
    "ipaddress": "src_ip",
    "ip_address": "src_ip",
    "dst_ip": "dst_ip",
    "destination_ip": "dst_ip",
    "dstaddr": "dst_ip",
    "dstip": "dst_ip",
    "server_ip": "dst_ip",
    "server": "dst_ip",
    "dst": "dst_ip",
    "dstIp": "dst_ip",
    "src_port": "src_port",
    "source_port": "src_port",
    "srcport": "src_port",
    "sport": "src_port",
    "srcPort": "src_port",
    "ipport": "src_port",
    "dst_port": "dst_port",
    "destination_port": "dst_port",
    "dstport": "dst_port",
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
    "usr": "user",
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
    "agent": "user_agent",
    "useragent": "user_agent",
    "user_agent": "user_agent",
    "service_name": "service_name",
    "service": "service_name",
    "svc": "service_name",
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
    anchor_date: Optional[datetime] = None,
) -> Optional[datetime]:
    """
    Parse string/numeric timestamp into standard UTC datetime.
    Supports:
    1. Absolute ISO 8601, RFC 3339, BSD syslog.
    2. Relative/elapsed timestamps (HH:MM:SS.ffffff) converted using anchor_date.
    3. Epoch timestamps (seconds, milliseconds, microseconds).
    """
    from datetime import timedelta

    if value is None:
        return None
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)
    if isinstance(value, (int, float)):
        try:
            # Handle epoch in milliseconds or microseconds
            if value > 1e14:  # microseconds
                return datetime.fromtimestamp(value / 1e6, tz=timezone.utc)
            if value > 1e11:  # milliseconds
                return datetime.fromtimestamp(value / 1e3, tz=timezone.utc)
            return datetime.fromtimestamp(value, tz=timezone.utc)
        except Exception:
            return None
    if isinstance(value, str):
        val = value.strip()
        if not val or val.lower() in ("null", "none", "-", ""):
            return None

        # Check relative / elapsed timestamp pattern: HH:MM:SS.ffffff or +HH:MM:SS.fff
        rel_match = re.match(r"^(?:\+)?(\d{1,2}):(\d{2}):(\d{2})(?:\.(\d+))?$", val)
        if rel_match:
            if anchor_date is not None:
                h = int(rel_match.group(1))
                m = int(rel_match.group(2))
                s = int(rel_match.group(3))
                us_str = (rel_match.group(4) or "0").ljust(6, "0")[:6]
                us = int(us_str)
                delta = timedelta(hours=h, minutes=m, seconds=s, microseconds=us)
                target_anchor = anchor_date if anchor_date.tzinfo else anchor_date.replace(tzinfo=timezone.utc)
                return (target_anchor + delta).astimezone(timezone.utc)
            # If no anchor date, we cannot compute absolute time from relative offset alone
            return None

        # Check numeric string epoch
        if re.match(r"^\d{10,16}(?:\.\d+)?$", val):
            try:
                num = float(val)
                if num > 1e14:
                    return datetime.fromtimestamp(num / 1e6, tz=timezone.utc)
                if num > 1e11:
                    return datetime.fromtimestamp(num / 1e3, tz=timezone.utc)
                return datetime.fromtimestamp(num, tz=timezone.utc)
            except Exception:
                pass

        # Clean fractional seconds if > 6 digits (e.g. nanoseconds .000000000 -> .000000)
        clean_iso = re.sub(r"(\.\d{6})\d+", r"\1", val)
        # Try fast ISO 8601 parsing
        try:
            iso_str = clean_iso.replace("Z", "+00:00")
            dt = datetime.fromisoformat(iso_str)
            if dt.tzinfo is None:
                return dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc)
        except Exception:
            pass

        # Determine fallback year for year-less timestamps
        if default_year is not None:
            target_year = default_year
        elif reference_date is not None:
            target_year = reference_date.year
        else:
            target_year = datetime.now(timezone.utc).year

        # Handle ISO, Syslog, and custom formats
        for fmt in (
            "%Y-%m-%dT%H:%M:%S%z",
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%dT%H:%M:%S.%f%z",
            "%Y-%m-%dT%H:%M:%S.%fZ",
            "%Y-%m-%d %H:%M:%S%z",
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%d %H:%M:%S.%f",
            "%Y-%m-%d %H:%M:%S,%f",
            "%b %d %Y %H:%M:%S",
            "%b  %d %Y %H:%M:%S",
            "%d/%b/%Y:%H:%M:%S %z",
            "%d/%b/%Y:%H:%M:%S",
            "%b %d %H:%M:%S",
            "%b  %d %H:%M:%S",
            "%m-%d %H:%M:%S.%f",
        ):
            try:
                dt = datetime.strptime(val, fmt)
                if dt.year == 1900:  # Inferred year
                    dt = dt.replace(year=target_year)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return dt.astimezone(timezone.utc)
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
