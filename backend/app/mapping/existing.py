"""
Pre-configured schema mapping definitions for common security vendors.
"""

from __future__ import annotations

from typing import Any, Dict

# Pre-defined mapping dictionary
BUILTIN_MAPPINGS: Dict[str, Dict[str, Any]] = {
    "windows_security": {
        "vendor": "Microsoft",
        "product": "Windows Security",
        "format": "json",
        "field_maps": {
            "EventID": "status_code",
            "TargetUserName": "user",
            "TargetDomainName": "user_domain",
            "IpAddress": "src_ip",
            "IpPort": "src_port",
            "LogonType": "logon_type",
            "AuthenticationPackageName": "auth_protocol",
        },
        "event_id_mappings": {
            "4624": {"category_name": "Identity & Access Management", "activity_name": "Logon", "status": "Success", "severity": "Informational"},
            "4625": {"category_name": "Identity & Access Management", "activity_name": "Logon", "status": "Failure", "severity": "High"},
            "4634": {"category_name": "Identity & Access Management", "activity_name": "Logoff", "status": "Success", "severity": "Informational"},
            "4720": {"category_name": "Identity & Access Management", "activity_name": "Create", "status": "Success", "severity": "Low"},
        }
    },
    "sysmon": {
        "vendor": "Microsoft",
        "product": "Sysmon",
        "format": "xml",
        "field_maps": {
            "Image": "message",
            "CommandLine": "message",
            "User": "user",
            "SourceIp": "src_ip",
            "SourcePort": "src_port",
            "DestinationIp": "dst_ip",
            "DestinationPort": "dst_port",
            "Protocol": "protocol",
        }
    },
    "zeek_conn": {
        "vendor": "Zeek",
        "product": "Conn Log",
        "format": "generic",
        "field_maps": {
            "id.orig_h": "src_ip",
            "id.orig_p": "src_port",
            "id.resp_h": "dst_ip",
            "id.resp_p": "dst_port",
            "proto": "protocol",
            "orig_bytes": "traffic_bytes",
            "conn_state": "status",
        }
    }
}
