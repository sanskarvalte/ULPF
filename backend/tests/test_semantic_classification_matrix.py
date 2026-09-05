"""
Classification Test Matrix for Evidence-Based Semantic OCSF Normalization.

Contains 56 comprehensive, deterministic test cases covering:
- Identity & Access Management (IAM): Logon (Success/Failure/MFA/Sudo), Logoff
- Network Activity: DNS (Port 53, Proto, Query), SSH (Port 22, Proto, Kex),
  HTTP (Verbs GET/POST/PUT/DELETE, Status 200/404/500, Ports 80/443),
  General Network (Connection, Traffic, Dropped, Reset, Syn Flood)
- System Activity: Process Execution (Exec, Fork, Bash, Powershell, Kill),
  File System Activity (Create, Delete, Modify, Chmod, Unlink)
- Security Finding: Malware, Threat, Intrusion, Exploit, Ransomware
- Application Activity: SQL Select, Insert, Update, Database Queries
- Negative Guards (Rules 1 - 6):
  * Rule 1: Never classify on single weak signal.
  * Rule 2: Never classify solely because an IP exists.
  * Rule 3: Never classify solely because a user exists.
  * Rule 4: Never classify every unknown event as System Activity.
  * Rule 5: Never fabricate OCSF classification.
  * Rule 6: Preserve uncertain semantic evidence.
"""

from __future__ import annotations

import pytest
from app.models.event_schema import UnifiedEvent
from app.normalization.engine import normalize_event


# ===========================================================================
# 1. IDENTITY & ACCESS MANAGEMENT (IAM) - CASES 1 to 10
# ===========================================================================

def test_case_01_iam_login_success():
    ev = normalize_event(UnifiedEvent(
        raw_event="User alice logged in successfully from 192.168.1.10",
        user="alice",
        action="login",
        message="User alice logged in successfully",
    ))
    assert ev.category_name == "Identity & Access Management"
    assert ev.category_uid == 3
    assert ev.class_name == "Authentication"
    assert ev.class_uid == 3002
    assert ev.activity_name == "Logon"
    assert ev.activity_id == 1
    assert ev.status == "Success"
    assert ev.classification_confidence >= 0.90


def test_case_02_iam_login_failed_bad_password():
    ev = normalize_event(UnifiedEvent(
        raw_event="Failed password for bob from 10.0.0.1 port 22",
        user="bob",
        action="login_failed",
        message="Failed password for bob",
    ))
    assert ev.category_name == "Identity & Access Management"
    assert ev.category_uid == 3
    assert ev.class_name == "Authentication"
    assert ev.activity_name == "Logon"
    assert ev.status == "Failure"
    assert ev.severity == "High"


def test_case_03_iam_auth_failure_root():
    ev = normalize_event(UnifiedEvent(
        raw_event="authentication failure; rhost=1.2.3.4 user=root",
        user="root",
        message="authentication failure for user root",
    ))
    assert ev.category_name == "Identity & Access Management"
    assert ev.class_name == "Authentication"
    assert ev.activity_name == "Logon"
    assert ev.status == "Failure"


def test_case_04_iam_invalid_credentials():
    ev = normalize_event(UnifiedEvent(
        raw_event="auth error: invalid_credentials provided for admin",
        user="admin",
        action="authenticate",
        status_detail="invalid_credentials",
    ))
    assert ev.category_name == "Identity & Access Management"
    assert ev.class_name == "Authentication"
    assert ev.activity_name == "Logon"
    assert ev.status == "Failure"


def test_case_05_iam_logon_interactive():
    ev = normalize_event(UnifiedEvent(
        raw_event="Interactive logon granted for jdoe",
        user="jdoe",
        action="logon",
        message="Interactive logon granted",
    ))
    assert ev.category_name == "Identity & Access Management"
    assert ev.class_name == "Authentication"
    assert ev.activity_name == "Logon"


def test_case_06_iam_logout():
    ev = normalize_event(UnifiedEvent(
        raw_event="User alice logged out of session",
        user="alice",
        action="logout",
        message="User alice logged out",
    ))
    assert ev.category_name == "Identity & Access Management"
    assert ev.class_name == "Authentication"
    assert ev.activity_name == "Logoff"
    assert ev.activity_id == 2


def test_case_07_iam_logoff():
    ev = normalize_event(UnifiedEvent(
        raw_event="User bob logoff completed",
        user="bob",
        action="logoff",
    ))
    assert ev.category_name == "Identity & Access Management"
    assert ev.class_name == "Authentication"
    assert ev.activity_name == "Logoff"


def test_case_08_iam_session_terminated():
    ev = normalize_event(UnifiedEvent(
        raw_event="session_terminated for charlie",
        user="charlie",
        action="session_terminated",
    ))
    assert ev.category_name == "Identity & Access Management"
    assert ev.class_name == "Authentication"
    assert ev.activity_name == "Logoff"


def test_case_09_iam_mfa_verified():
    ev = normalize_event(UnifiedEvent(
        raw_event="mfa_verified for dave OTP accepted",
        user="dave",
        action="mfa_verified",
        message="OTP code accepted",
    ))
    assert ev.category_name == "Identity & Access Management"
    assert ev.class_name == "Authentication"
    assert ev.activity_name == "Logon"
    assert ev.status == "Success"


def test_case_10_iam_sudo_elevation():
    ev = normalize_event(UnifiedEvent(
        raw_event="sudo: eve : TTY=pts/0 ; USER=root ; COMMAND=/bin/ls",
        user="eve",
        action="sudo",
        message="sudo elevated privilege command execution",
    ))
    assert ev.category_name == "Identity & Access Management"
    assert ev.class_name == "Authentication"


# ===========================================================================
# 2. NETWORK ACTIVITY / DNS ACTIVITY - CASES 11 to 15
# ===========================================================================

def test_case_11_network_dns_port_53():
    ev = normalize_event(UnifiedEvent(
        raw_event="DNS query A example.com from 10.0.0.1 port 53",
        src_ip="10.0.0.1",
        dst_port=53,
        message="DNS query A example.com",
    ))
    assert ev.category_name == "Network Activity"
    assert ev.category_uid == 4
    assert ev.class_name == "DNS Activity"
    assert ev.class_uid == 4003
    assert ev.activity_name == "Query"
    assert ev.activity_id == 1


def test_case_12_network_dns_proto():
    ev = normalize_event(UnifiedEvent(
        raw_event="query to mail.corp.net",
        protocol="dns",
        src_ip="10.0.0.2",
        message="dns_request for mail.corp.net",
    ))
    assert ev.category_name == "Network Activity"
    assert ev.class_name == "DNS Activity"
    assert ev.activity_name == "Query"


def test_case_13_network_dns_a_record():
    ev = normalize_event(UnifiedEvent(
        raw_event="dns query a_record for internal.api from 192.168.1.5",
        src_ip="192.168.1.5",
        message="dns query a_record for internal.api",
    ))
    assert ev.category_name == "Network Activity"
    assert ev.class_name == "DNS Activity"
    assert ev.activity_name == "Query"


def test_case_14_network_dns_ptr_record():
    ev = normalize_event(UnifiedEvent(
        raw_event="dns query ptr_record for 1.0.0.10.in-addr.arpa port 53",
        dst_port=53,
        message="dns query ptr_record lookup",
    ))
    assert ev.category_name == "Network Activity"
    assert ev.class_name == "DNS Activity"


def test_case_15_network_dns_response():
    ev = normalize_event(UnifiedEvent(
        raw_event="dns_response resolved IP address from 8.8.8.8:53",
        protocol="dns",
        src_port=53,
        message="dns_response resolved",
    ))
    assert ev.category_name == "Network Activity"
    assert ev.class_name == "DNS Activity"


# ===========================================================================
# 3. NETWORK ACTIVITY / SSH ACTIVITY - CASES 16 to 20
# ===========================================================================

def test_case_16_network_ssh_port_22():
    ev = normalize_event(UnifiedEvent(
        raw_event="ssh connection established to 192.168.1.1:22",
        src_ip="192.168.1.10",
        dst_ip="192.168.1.1",
        dst_port=22,
        protocol="tcp",
        message="ssh connection established",
    ))
    assert ev.category_name == "Network Activity"
    assert ev.class_name == "SSH Activity"
    assert ev.class_uid == 4007


def test_case_17_network_ssh_login_attempt():
    ev = normalize_event(UnifiedEvent(
        raw_event="ssh_login initiated on port 22 from 10.0.0.5",
        src_ip="10.0.0.5",
        dst_port=22,
        action="ssh_login",
    ))
    assert ev.category_name == "Network Activity"
    assert ev.class_name == "SSH Activity"


def test_case_18_network_ssh_kex():
    ev = normalize_event(UnifiedEvent(
        raw_event="key_exchange negotiated for ssh session",
        protocol="ssh",
        dst_port=22,
        message="kex algorithm negotiated",
    ))
    assert ev.category_name == "Network Activity"
    assert ev.class_name == "SSH Activity"


def test_case_19_network_ssh_disconnect():
    ev = normalize_event(UnifiedEvent(
        raw_event="ssh_disconnect from host",
        protocol="ssh",
        dst_port=22,
        action="ssh_disconnect",
    ))
    assert ev.category_name == "Network Activity"
    assert ev.class_name == "SSH Activity"


def test_case_20_network_ssh_session():
    ev = normalize_event(UnifiedEvent(
        raw_event="ssh2 connection closed",
        protocol="ssh",
        src_ip="10.0.0.1",
        message="ssh2 connection closed",
    ))
    assert ev.category_name == "Network Activity"
    assert ev.class_name == "SSH Activity"


# ===========================================================================
# 4. NETWORK ACTIVITY / HTTP ACTIVITY - CASES 21 to 26
# ===========================================================================

def test_case_21_network_http_get_200():
    ev = normalize_event(UnifiedEvent(
        raw_event="GET /api/v1/items HTTP/1.1 200 OK port 80",
        action="GET",
        dst_port=80,
        status="200",
        message="HTTP request processed",
    ))
    assert ev.category_name == "Network Activity"
    assert ev.class_name == "HTTP Activity"
    assert ev.class_uid == 4002
    assert ev.activity_name == "GET"
    assert ev.status == "Success"


def test_case_22_network_http_post_404():
    ev = normalize_event(UnifiedEvent(
        raw_event="POST /login HTTP/1.1 404 Not Found port 443",
        action="POST",
        dst_port=443,
        status="404",
        message="web request url not found",
    ))
    assert ev.category_name == "Network Activity"
    assert ev.class_name == "HTTP Activity"
    assert ev.activity_name == "POST"
    assert ev.status == "Failure"


def test_case_23_network_http_put_500():
    ev = normalize_event(UnifiedEvent(
        raw_event="PUT /upload HTTP/1.1 500 Server Error port 8080",
        action="PUT",
        dst_port=8080,
        status="500",
        message="web_access error",
    ))
    assert ev.category_name == "Network Activity"
    assert ev.class_name == "HTTP Activity"
    assert ev.activity_name == "PUT"
    assert ev.status == "Failure"


def test_case_24_network_http_delete():
    ev = normalize_event(UnifiedEvent(
        raw_event="DELETE /resource/42 port 443",
        action="DELETE",
        dst_port=443,
        protocol="https",
    ))
    assert ev.category_name == "Network Activity"
    assert ev.class_name == "HTTP Activity"
    assert ev.activity_name == "DELETE"


def test_case_25_network_http_head():
    ev = normalize_event(UnifiedEvent(
        raw_event="HEAD /healthcheck port 8443",
        action="HEAD",
        dst_port=8443,
        message="http request to uri /healthcheck",
    ))
    assert ev.category_name == "Network Activity"
    assert ev.class_name == "HTTP Activity"
    assert ev.activity_name == "HEAD"


def test_case_26_network_web_request_url():
    ev = normalize_event(UnifiedEvent(
        raw_event="web_request to url https://app.example.com",
        protocol="https",
        dst_port=443,
        message="web_request url accessed",
    ))
    assert ev.category_name == "Network Activity"
    assert ev.class_name == "HTTP Activity"


# ===========================================================================
# 5. NETWORK ACTIVITY / GENERAL CONNECTION & FIREWALL - CASES 27 to 31
# ===========================================================================

def test_case_27_network_firewall_packet_dropped():
    ev = normalize_event(UnifiedEvent(
        raw_event="packet_dropped by firewall filter on port 9999 from 1.2.3.4 to 5.6.7.8",
        src_ip="1.2.3.4",
        dst_ip="5.6.7.8",
        dst_port=9999,
        protocol="tcp",
        message="packet_dropped by firewall filter",
    ))
    assert ev.category_name == "Network Activity"
    assert ev.class_name == "Network Activity"
    assert ev.class_uid == 4001
    assert ev.activity_name == "Drop"
    assert ev.status == "Failure"


def test_case_28_network_traffic_connection_open():
    ev = normalize_event(UnifiedEvent(
        raw_event="connection_open from 10.0.0.1:50000 to 10.0.0.2:8000 tcp",
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        src_port=50000,
        dst_port=8000,
        protocol="tcp",
        action="connection_open",
    ))
    assert ev.category_name == "Network Activity"
    assert ev.class_name == "Network Activity"
    assert ev.activity_name == "Open"


def test_case_29_network_firewall_deny():
    ev = normalize_event(UnifiedEvent(
        raw_event="firewall_deny port 1433 from 192.168.1.1 to 10.0.0.1",
        src_ip="192.168.1.1",
        dst_ip="10.0.0.1",
        dst_port=1433,
        protocol="tcp",
        action="firewall_deny",
    ))
    assert ev.category_name == "Network Activity"
    assert ev.class_name == "Network Activity"
    assert ev.activity_name == "Drop"


def test_case_30_network_tcp_reset():
    ev = normalize_event(UnifiedEvent(
        raw_event="connection_reset by peer tcp_rst from 10.1.1.1 to 10.1.1.2",
        src_ip="10.1.1.1",
        dst_ip="10.1.1.2",
        protocol="tcp",
        message="connection_reset by peer tcp_rst",
    ))
    assert ev.category_name == "Network Activity"
    assert ev.class_name == "Network Activity"
    assert ev.activity_name == "Close"


def test_case_31_network_syn_flood():
    ev = normalize_event(UnifiedEvent(
        raw_event="syn_flood attack on 10.2.2.3:80",
        src_ip="10.2.2.2",
        dst_ip="10.2.2.3",
        dst_port=80,
        protocol="tcp",
        message="syn_flood traffic detected",
    ))
    assert ev.category_name == "Network Activity"
    assert ev.class_name == "Network Activity"


# ===========================================================================
# 6. SYSTEM ACTIVITY / PROCESS ACTIVITY - CASES 32 to 36
# ===========================================================================

def test_case_32_system_process_execution():
    ev = normalize_event(UnifiedEvent(
        raw_event="process_execution: pid 1234 spawned",
        action="process_execution",
        message="process created pid 1234",
    ))
    assert ev.category_name == "System Activity"
    assert ev.category_uid == 1
    assert ev.class_name == "Process Activity"
    assert ev.class_uid == 1007
    assert ev.activity_name == "Execute"


def test_case_33_system_command_executed():
    ev = normalize_event(UnifiedEvent(
        raw_event="command_executed: /bin/bash /opt/script.sh",
        message="command_executed: /bin/bash /opt/script.sh",
    ))
    assert ev.category_name == "System Activity"
    assert ev.class_name == "Process Activity"
    assert ev.activity_name == "Execute"


def test_case_34_system_powershell_spawn():
    ev = normalize_event(UnifiedEvent(
        raw_event="process_spawned: powershell.exe -enc AAAA==",
        message="process_spawned: powershell.exe",
    ))
    assert ev.category_name == "System Activity"
    assert ev.class_name == "Process Activity"
    assert ev.activity_name == "Execute"


def test_case_35_system_execve_fork():
    ev = normalize_event(UnifiedEvent(
        raw_event="execve fork child process pid 4567",
        action="execve",
        message="fork child process",
    ))
    assert ev.category_name == "System Activity"
    assert ev.class_name == "Process Activity"
    assert ev.activity_name == "Execute"


def test_case_36_system_process_killed():
    ev = normalize_event(UnifiedEvent(
        raw_event="process_killed pid 9999 exit_code 137",
        action="process_killed",
        message="process_terminated by sigkill",
    ))
    assert ev.category_name == "System Activity"
    assert ev.class_name == "Process Activity"


# ===========================================================================
# 7. SYSTEM ACTIVITY / FILE SYSTEM ACTIVITY - CASES 37 to 41
# ===========================================================================

def test_case_37_system_file_created():
    ev = normalize_event(UnifiedEvent(
        raw_event="file_created: /etc/passwd.bak",
        action="file_created",
        message="new file created",
    ))
    assert ev.category_name == "System Activity"
    assert ev.category_uid == 1
    assert ev.class_name == "File System Activity"
    assert ev.class_uid == 1001
    assert ev.activity_name == "Create"


def test_case_38_system_file_deleted():
    ev = normalize_event(UnifiedEvent(
        raw_event="file_deleted: /tmp/tempfile.tmp",
        action="file_deleted",
        message="delete_file /tmp/tempfile.tmp",
    ))
    assert ev.category_name == "System Activity"
    assert ev.class_name == "File System Activity"
    assert ev.activity_name == "Delete"


def test_case_39_system_file_modified():
    ev = normalize_event(UnifiedEvent(
        raw_event="file_modified: /var/log/audit.log write_file",
        action="file_modified",
        message="write_file to destination",
    ))
    assert ev.category_name == "System Activity"
    assert ev.class_name == "File System Activity"
    assert ev.activity_name == "Modify"


def test_case_40_system_chmod_permission():
    ev = normalize_event(UnifiedEvent(
        raw_event="chmod 777 applied to file",
        action="chmod",
        message="file permissions modified to 777",
    ))
    assert ev.category_name == "System Activity"
    assert ev.class_name == "File System Activity"
    assert ev.activity_name == "Modify"


def test_case_41_system_file_unlink():
    ev = normalize_event(UnifiedEvent(
        raw_event="unlink file from disk",
        action="unlink",
        message="file unlinked from directory",
    ))
    assert ev.category_name == "System Activity"
    assert ev.class_name == "File System Activity"
    assert ev.activity_name == "Delete"


# ===========================================================================
# 8. SECURITY FINDINGS / THREATS / ALERTS - CASES 42 to 46
# ===========================================================================

def test_case_42_security_malware_detected():
    ev = normalize_event(UnifiedEvent(
        raw_event="malware_detected Trojan.Generic.123 on endpoint",
        action="security_alert",
        message="malware_detected Trojan.Generic.123",
    ))
    assert ev.category_name == "Security Finding"
    assert ev.category_uid == 2
    assert ev.class_name == "Security Finding"
    assert ev.class_uid == 2001
    assert ev.severity == "High"


def test_case_43_security_threat_intrusion():
    ev = normalize_event(UnifiedEvent(
        raw_event="threat_detected: intrusion_detected on host",
        message="threat_detected: intrusion_detected on port 21",
    ))
    assert ev.category_name == "Security Finding"
    assert ev.class_name == "Security Finding"


def test_case_44_security_exploit_blocked():
    ev = normalize_event(UnifiedEvent(
        raw_event="exploit_blocked: cve_2026_1234 buffer overflow waf_blocked",
        action="exploit_blocked",
        message="cve_2026_1234 exploit attempt blocked",
    ))
    assert ev.category_name == "Security Finding"
    assert ev.class_name == "Security Finding"
    assert ev.activity_name == "Deny"


def test_case_45_security_ransomware():
    ev = normalize_event(UnifiedEvent(
        raw_event="ransomware_detected encrypted files on disk",
        message="ransomware_detected on host system",
    ))
    assert ev.category_name == "Security Finding"
    assert ev.class_name == "Security Finding"


def test_case_46_security_vulnerability():
    ev = normalize_event(UnifiedEvent(
        raw_event="vulnerability_found cve_2026_9999",
        action="vulnerability_found",
        message="vulnerability_found during scan",
    ))
    assert ev.category_name == "Security Finding"
    assert ev.class_name == "Security Finding"


# ===========================================================================
# 9. APPLICATION ACTIVITY / DATABASE QUERIES - CASES 47 to 50
# ===========================================================================

def test_case_47_app_sql_select():
    ev = normalize_event(UnifiedEvent(
        raw_event="database_query: sql_select * from users",
        action="sql_select",
        message="database_query executed: sql_select * from users",
    ))
    assert ev.category_name == "Application Activity"
    assert ev.category_uid == 6
    assert ev.class_name == "Application Activity"
    assert ev.class_uid == 6001
    assert ev.activity_name == "Query"
    assert ev.activity_id == 1


def test_case_48_app_sql_insert():
    ev = normalize_event(UnifiedEvent(
        raw_event="sql_insert into audit_log values (1)",
        action="sql_insert",
        message="db_query: sql_insert into audit_log",
    ))
    assert ev.category_name == "Application Activity"
    assert ev.class_name == "Application Activity"
    assert ev.activity_name == "Query"


def test_case_49_app_sql_update():
    ev = normalize_event(UnifiedEvent(
        raw_event="database_query: sql_update records",
        action="sql_update",
        message="database_query updated records in table",
    ))
    assert ev.category_name == "Application Activity"
    assert ev.class_name == "Application Activity"
    assert ev.activity_name == "Query"


def test_case_50_app_database_commit():
    ev = normalize_event(UnifiedEvent(
        raw_event="db_query transaction commit on postgres",
        action="database_query",
        message="transaction begin commit executed on postgres",
    ))
    assert ev.category_name == "Application Activity"
    assert ev.class_name == "Application Activity"
    assert ev.activity_name == "Query"


# ===========================================================================
# 10. NEGATIVE GUARDS & ANTI-HALLUCINATION RULES - CASES 51 to 56
# ===========================================================================

def test_case_51_negative_ip_only_not_network_activity():
    """Rule 2: Never classify solely because an IP exists."""
    ev = normalize_event(UnifiedEvent(
        raw_event="Printer device ready at 192.168.1.50 status ready",
        src_ip="192.168.1.50",
        message="Printer device ready",
    ))
    # Must NOT be classified as Network Activity or System Activity!
    assert ev.category_name is None
    assert ev.class_name is None
    assert ev.classification_confidence == 0.0
    assert ev.classification_reason == "insufficient_semantic_evidence"


def test_case_52_negative_user_only_not_iam():
    """Rule 3: Never classify solely because a user exists."""
    ev = normalize_event(UnifiedEvent(
        raw_event="Customer profile record viewed: user=alice",
        user="alice",
        message="Customer profile viewed",
    ))
    # Must NOT be classified as IAM/Authentication!
    assert ev.category_name is None
    assert ev.class_name is None
    assert ev.classification_confidence == 0.0
    assert ev.classification_reason == "insufficient_semantic_evidence"


def test_case_53_negative_weak_word_not_system_activity():
    """Rule 1 & 4: Never classify on single weak signal; never default to System Activity."""
    ev = normalize_event(UnifiedEvent(
        raw_event="system informational notice: sync completed",
        message="system informational notice",
    ))
    assert ev.category_name is None
    assert ev.class_name is None
    assert ev.classification_confidence == 0.0


def test_case_54_negative_ambiguous_sensor_reading():
    """Rule 4: Never classify every unknown event as System Activity."""
    ev = normalize_event(UnifiedEvent(
        raw_event="[sensor-42] reading=98.6 unit=fahrenheit",
        message="sensor reading recorded",
    ))
    assert ev.category_name is None
    assert ev.class_name is None
    assert ev.classification_confidence == 0.0
    assert ev.classification_reason == "insufficient_semantic_evidence"


def test_case_55_negative_isolated_port_no_proto_or_verb():
    """Rule 1: An isolated non-standard port without network verbs or protocol is not Network Activity."""
    ev = normalize_event(UnifiedEvent(
        raw_event="Record index 12345 parsed",
        src_port=12345,
        message="Record index parsed",
    ))
    assert ev.category_name is None
    assert ev.class_name is None
    assert ev.classification_confidence == 0.0


def test_case_56_evidence_preservation_in_unmapped():
    """Rule 6: Preserve uncertain semantic evidence in unmapped."""
    ev = normalize_event(UnifiedEvent(
        raw_event="Ambiguous device payload 10.0.0.1 user=bob",
        src_ip="10.0.0.1",
        user="bob",
        message="Ambiguous device payload",
    ))
    assert ev.category_name is None
    assert ev.classification_confidence == 0.0
    assert ev.unmapped is not None
    assert ev.unmapped.get("classification_confidence") == 0.0
    assert ev.unmapped.get("classification_reason") == "insufficient_semantic_evidence"
    assert isinstance(ev.unmapped.get("classification_evidence"), list)
    assert "isolated_ip" in ev.unmapped["classification_evidence"]
    assert "isolated_user" in ev.unmapped["classification_evidence"]
