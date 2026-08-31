"""
Unified event schema for ULPF (Backend Model Layer).
Aligned with OCSF (Open Cybersecurity Schema Framework) standard taxonomy.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, field_serializer


class UnifiedEvent(BaseModel):
    """
    Flat, vendor-neutral representation of a single security event.
    Inspired by OCSF base_event, authentication, network_activity, and endpoint classes.
    """

    # Identity
    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()), description="Unique identifier for normalised event.")
    raw_event_id: Optional[str] = Field(default=None, description="Original event/log SHA-256 or ID.")

    # Temporal
    timestamp: Optional[datetime] = Field(default=None, description="Event occurrence timestamp (UTC).")

    @field_serializer("timestamp", when_used="json")
    def serialize_timestamp(self, ts: Optional[datetime]) -> Optional[str]:
        if ts is None:
            return None
        if ts.tzinfo is None or ts.tzinfo == timezone.utc:
            return ts.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        return ts.strftime("%Y-%m-%dT%H:%M:%S.%f%z")

    # Classification
    category_name: Optional[str] = Field(default=None, description="High-level category (e.g. Identity & Access Management, Network Activity).")
    category_uid: Optional[int] = Field(default=None, description="Numeric category UID (3=IAM, 4=Network).")
    class_name: Optional[str] = Field(default=None, description="Event class (e.g. Authentication, Network Activity).")
    class_uid: Optional[int] = Field(default=None, description="Numeric class UID.")
    activity_name: Optional[str] = Field(default=None, description="Specific activity (e.g. Logon, Logoff, Open, Close).")
    activity_id: Optional[int] = Field(default=None, description="Numeric activity identifier.")
    type_name: Optional[str] = Field(default=None, description="Full type name (e.g. Authentication: Logon).")
    type_uid: Optional[int] = Field(default=None, description="Numeric type identifier.")
    severity: Optional[str] = Field(default=None, description="Severity label (Informational, Low, Medium, High, Critical).")
    severity_id: Optional[int] = Field(default=None, description="Numeric severity ID (0=Unknown, 1=Info, 2=Low, 3=Med, 4=High, 5=Crit).")
    status: Optional[str] = Field(default=None, description="Outcome status (Success, Failure).")
    status_id: Optional[int] = Field(default=None, description="Numeric status ID (1=Success, 2=Failure, 0=Unknown).")
    status_code: Optional[str] = Field(default=None, description="Source-specific status code (e.g. 0x18, 403).")
    status_detail: Optional[str] = Field(default=None, description="Detailed human-readable outcome explanation.")
    message: Optional[str] = Field(default=None, description="Human-readable event summary/message.")

    # Network / Endpoint
    src_ip: Optional[str] = Field(default=None, description="Source IP address.")
    src_port: Optional[int] = Field(default=None, description="Source port number.")
    src_hostname: Optional[str] = Field(default=None, description="Source hostname.")
    src_endpoint_name: Optional[str] = Field(default=None, description="Short name of source endpoint.")
    dst_ip: Optional[str] = Field(default=None, description="Destination IP address.")
    dst_port: Optional[int] = Field(default=None, description="Destination port number.")
    dst_hostname: Optional[str] = Field(default=None, description="Destination hostname.")
    dst_endpoint_name: Optional[str] = Field(default=None, description="Short name of destination endpoint.")

    # Connection & Traffic
    protocol: Optional[str] = Field(default=None, description="Network protocol (tcp, udp, icmp).")
    direction: Optional[str] = Field(default=None, description="Traffic direction (Inbound, Outbound).")
    traffic_bytes: Optional[int] = Field(default=None, description="Total transferred bytes.")
    traffic_packets: Optional[int] = Field(default=None, description="Total transferred packets.")

    # Identity & Access (IAM)
    user: Optional[str] = Field(default=None, description="Username / principal.")
    user_uid: Optional[str] = Field(default=None, description="User unique identifier (SID, UID).")
    user_type: Optional[str] = Field(default=None, description="User type (User, Admin, System, Service).")
    user_domain: Optional[str] = Field(default=None, description="Domain (LDAP / AD domain).")
    auth_protocol: Optional[str] = Field(default=None, description="Auth protocol (Kerberos, NTLM, OIDC).")
    is_mfa: Optional[bool] = Field(default=None, description="MFA used boolean.")
    is_remote: Optional[bool] = Field(default=None, description="Remote connection boolean.")
    logon_type: Optional[str] = Field(default=None, description="Logon type (Interactive, Network).")
    service_name: Optional[str] = Field(default=None, description="Target service name.")
    session_uid: Optional[str] = Field(default=None, description="Session UID.")

    # Metadata & Product
    vendor: Optional[str] = Field(default=None, description="Hardware / Software Vendor.")
    product: Optional[str] = Field(default=None, description="Product / Tool Name.")
    product_version: Optional[str] = Field(default=None, description="Product version.")
    log_format: Optional[str] = Field(default=None, description="Format (json, csv, xml, syslog, cef, leef, generic).")
    log_name: Optional[str] = Field(default=None, description="Source log name.")

    # Catch-all & Traceability
    unmapped: Optional[Dict[str, Any]] = Field(default=None, description="Unmapped vendor attributes.")
    raw_event: str = Field(..., description="Original untouched raw log text for lossless forensic traceability.")
