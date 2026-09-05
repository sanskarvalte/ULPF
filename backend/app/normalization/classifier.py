"""
Evidence-Based Semantic Classifier for OCSF Normalization.

Evaluates multi-signal evidence across:
- Parsed fields (action, activity_name, service_name, protocol, ports, user, IPs)
- Message text & raw event
- Authentication indicators
- Security & threat indicators
- Network protocol & port indicators
- Process, file-system, and OS execution indicators
- Application & database query indicators

Strict Guards:
1. Never classify using one weak signal.
2. Never classify solely because an IP exists.
3. Never classify solely because a user exists.
4. Never classify every unknown event as System Activity.
5. Never fabricate OCSF classification.
6. Preserve uncertain semantic evidence.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Set, Tuple

from app.normalization.taxonomy import (
    ACTIVITY_MAP,
    CATEGORY_MAP,
    CLASS_MAP,
    PROCESS_TAXONOMY_MAP,
    resolve_process_taxonomy,
)

# ---------------------------------------------------------------------------
# Indicator Dictionaries & Signal Keywords
# ---------------------------------------------------------------------------

# IAM / Authentication Indicators
_AUTH_SUCCESS_KEYWORDS = {
    "login_success", "logon_success", "successful_login", "successful_logon",
    "auth_success", "authentication_success", "mfa_verified", "session_authenticated",
    "authenticated", "logged_in", "logged_on", "login_ok", "logon_ok",
}

_AUTH_FAILURE_KEYWORDS = {
    "login_failed", "logon_failed", "failed_login", "failed_logon",
    "auth_failed", "authentication_failed", "auth_failure", "authentication_failure",
    "invalid_password", "bad_password", "wrong_password", "bad_credentials",
    "invalid_credentials", "access_denied", "permission_denied", "account_locked",
    "user_unknown", "unknown_user", "invalid_user", "failed_password",
}

_AUTH_LOGOFF_KEYWORDS = {
    "logout", "logoff", "signout", "sign_out", "session_terminated",
    "session_closed", "disconnect_session", "session_expired", "logged_out",
    "logged_off", "user_logout", "user_logoff",
}

_AUTH_GENERAL_KEYWORDS = {
    "login", "logon", "authenticate", "auth", "signin", "sign_in",
    "interactive_logon", "network_logon", "remote_logon", "kerberos",
    "ntlm", "saml", "oauth", "sso", "elevate", "sudo",
}

# Network Indicators
_DNS_QUERY_KEYWORDS = {
    "dns_query", "dns_request", "dns_lookup", "query_type", "dns_response",
    "dns_answer", "a_record", "aaaa_record", "ptr_record", "cname_record",
    "mx_record", "txt_record", "ns_record", "srv_record", "soa_record",
}

_SSH_KEYWORDS = {
    "ssh_connection", "ssh_login", "ssh_session", "ssh_disconnect",
    "sshd", "ssh", "openssh", "key_exchange", "kex", "ssh2",
}

_HTTP_VERBS = {"get", "post", "put", "delete", "patch", "head", "options", "connect"}

_HTTP_KEYWORDS = {
    "http_request", "http_response", "web_request", "web_access",
    "http_access", "url", "uri", "http_status", "user_agent",
    "http_method", "nginx", "apache", "httpd", "caddy",
    "http", "https",
}

_APP_LIFECYCLE_KEYWORDS = {
    "hadoop", "mrappmaster", "hdfs", "yarn", "spark", "kafka", "zookeeper",
    "application_start", "application_stop", "application_init", "appattempt",
    "containermanager", "nodemanager", "resourcemanager",
    "datanode", "namenode", "journalnode", "yarnrm",
}

_NETWORK_VERB_KEYWORDS = {
    "connection_open", "open_connection", "connection_close", "close_connection",
    "connection_reset", "reset_connection", "connection_timeout", "connection_refused",
    "packet_dropped", "packet_filtered", "traffic_allowed", "traffic_denied",
    "firewall_drop", "firewall_deny", "firewall_permit", "firewall_accept",
    "syn_flood", "tcp_rst", "tcp_syn", "tcp_ack", "udp_traffic",
    "icmp_ping", "icmp_echo", "outbound_connection", "inbound_connection",
    "port_scan", "network_flow", "netflow", "ipfix",
}

# System / Process / File Indicators
_PROCESS_EXEC_KEYWORDS = {
    "process_execution", "process_created", "process_spawned", "process_start",
    "command_executed", "command_run", "execve", "fork", "spawn",
    "/bin/bash", "/bin/sh", "/bin/zsh", "cmd.exe", "powershell.exe",
    "process_killed", "process_terminated", "kill_process", "exit_code",
    "child_process", "parent_process", "ppid", "subshell",
}

_FILE_SYSTEM_KEYWORDS = {
    "file_created", "create_file", "file_creation", "file_deleted",
    "delete_file", "file_deletion", "file_modified", "modify_file",
    "file_modification", "write_file", "read_file", "file_opened",
    "file_renamed", "rename_file", "chmod", "chown", "unlink",
    "mkdir", "rmdir", "file_copied", "directory_created",
}

# Security Findings / Alerts
_SECURITY_FINDING_KEYWORDS = {
    "security_alert", "threat_detected", "malware_detected", "malware_found",
    "virus_detected", "trojan_detected", "ransomware_detected", "worm_detected",
    "intrusion_detected", "intrusion_attempt", "exploit_attempt", "exploit_blocked",
    "vulnerability_found", "cve_", "ids_alert", "ips_alert", "waf_blocked",
    "quarantine_file", "attack_detected", "brute_force_detected",
}

# Application / Database Query Indicators
_DATABASE_QUERY_KEYWORDS = {
    "database_query", "db_query", "sql_query", "query_executed",
    "sql_select", "sql_insert", "sql_update", "sql_delete",
    "drop_table", "create_table", "alter_table", "commit", "rollback",
    "transaction_begin", "postgres", "mysql", "oracle", "mongodb",
    "sql_execution", "prepared_statement",
}

# Weak, ambiguous words that MUST NEVER trigger classification alone
_WEAK_WORDS = {
    "info", "information", "informational", "status", "ok", "test",
    "error", "warning", "debug", "trace", "notice", "event", "log",
    "service", "app", "system", "user", "client", "server", "host",
    "msg", "message", "type", "name", "id", "data", "success", "failure",
}


def _clean_token(value: Any) -> str:
    """Normalize string into a clean lowercase underscore token."""
    if value is None:
        return ""
    return str(value).strip().lower().replace("-", "_").replace(" ", "_")


def _extract_all_evidence_tokens(mapped: Dict[str, Any]) -> Tuple[List[str], Set[str]]:
    """
    Extract discrete tokens and whole phrases from all candidate text fields.
    Returns: (ordered_tokens, token_set)
    """
    token_set: Set[str] = set()
    token_list: List[str] = []

    def add_token(t: str):
        cleaned = _clean_token(t)
        if cleaned and cleaned not in token_set:
            token_set.add(cleaned)
            token_list.append(cleaned)
            # Also break compound snake_case, dotted, and dollar tokens into individual words
            for sub in re.split(r"[._$]+", cleaned):
                if len(sub) >= 2 and sub not in token_set:
                    token_set.add(sub)
                    token_list.append(sub)

    # 1. Primary candidate fields
    for field in (
        "activity_name", "action", "event_action", "operation",
        "event_type", "type_name", "service_name", "product",
        "protocol", "log_name",
    ):
        val = mapped.get(field)
        if val is not None:
            add_token(str(val))

    # 2. Status details & message
    for field in ("status_detail", "message", "status_code"):
        val = mapped.get(field)
        if val is not None and isinstance(val, str):
            phrase = _clean_token(val[:120])
            add_token(phrase)
            for part in re.split(r"[\s,;:|/\\()\[\]]+", val):
                if len(part) >= 2:
                    add_token(part)

    # 3. Unmapped fields
    unmapped = mapped.get("unmapped")
    if isinstance(unmapped, dict):
        for k, v in unmapped.items():
            add_token(str(k))
            if isinstance(v, str) and len(v) < 100:
                add_token(v)

    # 4. Raw event snippet & tokens
    raw = mapped.get("raw_event")
    if raw and isinstance(raw, str):
        raw_lower = raw.lower()
        # Phrase shortcuts for common natural language logs
        if "logged in" in raw_lower or "logged_in" in raw_lower:
            add_token("login_success")
            add_token("login")
        if "logged out" in raw_lower or "logged_out" in raw_lower:
            add_token("logout")
        if "logged on" in raw_lower or "logged_on" in raw_lower:
            add_token("logon_success")
            add_token("logon")
        if "logged off" in raw_lower or "logged_off" in raw_lower:
            add_token("logoff")

        for kw in (
            "authentication failure", "failed password", "invalid user",
            "accepted password", "session opened", "session closed",
            "dns query", "ssh connection", "http get", "http post",
            "command executed", "file created", "threat detected",
            "malware detected", "database query", "sql select",
            "exploit blocked", "cve_", "waf blocked",
        ):
            if kw in raw_lower:
                add_token(kw)

        if "select" in raw_lower and ("from" in raw_lower or "where" in raw_lower):
            add_token("sql_select")
        if "insert into" in raw_lower:
            add_token("sql_insert")
        if "update" in raw_lower and "set" in raw_lower:
            add_token("sql_update")
        if "delete from" in raw_lower:
            add_token("sql_delete")

        # Tokenize discrete words from raw text
        for part in re.split(r"[\s,;:|=/\\()\[\]\"']+", raw):
            if len(part) >= 2:
                add_token(part)

    return token_list, token_set


from app.normalization.semantic_classifier import classify_semantics


def classify_event_semantics(mapped: Dict[str, Any]) -> Dict[str, Any]:
    """
    Evidence-based semantic classifier for OCSF category, class, activity, and status.
    Delegates to central semantic classifier engine.

    Args:
        mapped: Dictionary of parsed event attributes (modified in place and returned).

    Returns:
        Classification result summary with confidence, reason, and evidence.
    """
    sem = classify_semantics(mapped)
    mapped["category_name"] = sem["category_name"]
    mapped["category_uid"] = sem["category_uid"]
    mapped["class_name"] = sem["class_name"]
    mapped["class_uid"] = sem["class_uid"]
    if not mapped.get("activity_name") or mapped.get("activity_name") in ("unknown", "generic"):
        if sem.get("activity_name"):
            mapped["activity_name"] = sem["activity_name"]
    if mapped.get("activity_id") is None and sem.get("activity_id") is not None:
        mapped["activity_id"] = sem["activity_id"]
    if not mapped.get("status"):
        if sem.get("status"):
            mapped["status"] = sem["status"]
    if mapped.get("status_id") is None and sem.get("status_id") is not None:
        mapped["status_id"] = sem["status_id"]
    if not mapped.get("severity"):
        if sem.get("severity"):
            mapped["severity"] = sem["severity"]
    if mapped.get("severity_id") is None and sem.get("severity_id") is not None:
        mapped["severity_id"] = sem["severity_id"]
    mapped["classification_confidence"] = sem["semantic_confidence"]
    mapped["classification_reason"] = sem["classification_reason"]
    mapped["classification_status"] = sem["classification_status"]
    mapped["classification_evidence"] = sem.get("classification_evidence", [])
    return mapped


    # Extract network & endpoint signals
    src_ip = mapped.get("src_ip")
    dst_ip = mapped.get("dst_ip")
    has_ip = bool((src_ip and str(src_ip).strip()) or (dst_ip and str(dst_ip).strip()))
    if not has_ip:
        has_ip = any(re.match(r"^(?:\d{1,3}\.){3}\d{1,3}$", t) for t in token_set)

    src_port = mapped.get("src_port")
    dst_port = mapped.get("dst_port")
    ports: Set[int] = set()
    for p in (src_port, dst_port):
        if isinstance(p, int) and 0 < p <= 65535:
            ports.add(p)

    protocol = _clean_token(mapped.get("protocol"))
    user = mapped.get("user")
    has_user = bool(user and str(user).strip())

    # Check if event already has an authoritative taxonomy match from known process/daemon
    proc = mapped.get("product")
    is_kernel_firewall = (
        proc == "kernel"
        and (
            "iptables" in token_set
            or "ufw" in token_set
            or "netfilter" in token_set
            or (has_ip and any(w in token_set for w in ("drop", "dropped", "deny", "action_drop")))
        )
    )
    if proc and not is_kernel_firewall:
        tax = resolve_process_taxonomy(proc)
        if tax and tax.get("category_name"):
            cat = tax["category_name"]
            cat_uid = tax.get("category_uid", 1)
            cls_name = tax.get("class_name", cat)
            cls_uid = tax.get("class_uid", cat_uid * 1000)
            act_name = tax.get("activity_name", mapped.get("activity_name", "Log"))
            act_id = tax.get("activity_id", 1)

            if not mapped.get("category_name"):
                mapped["category_name"] = cat
                mapped["category_uid"] = cat_uid
            if not mapped.get("class_name"):
                mapped["class_name"] = cls_name
                mapped["class_uid"] = cls_uid
            if not mapped.get("activity_name"):
                mapped["activity_name"] = act_name
                mapped["activity_id"] = act_id

            evidence = [f"authoritative_daemon:{proc}"]
            mapped["classification_confidence"] = 0.99
            mapped["classification_reason"] = f"authoritative_process_taxonomy_{proc}"
            mapped["classification_evidence"] = evidence
            return mapped

    # -----------------------------------------------------------------------
    # RULE SET 1: Security Findings / Threats / Alerts (Category 2 / Class 2001)
    # -----------------------------------------------------------------------
    security_matches = token_set.intersection(_SECURITY_FINDING_KEYWORDS)
    if security_matches:
        evidence = sorted(list(security_matches))
        mapped["category_name"] = "Security Finding"
        mapped["category_uid"] = 2
        mapped["class_name"] = "Security Finding"
        mapped["class_uid"] = 2001
        if not mapped.get("activity_name") or mapped.get("activity_name") in ("unknown", "generic"):
            mapped["activity_name"] = "Deny" if any("blocked" in s or "quarantine" in s for s in evidence) else "Alert"
            mapped["activity_id"] = 5 if mapped["activity_name"] == "Deny" else 1
        if not mapped.get("severity"):
            mapped["severity"] = "High"
            mapped["severity_id"] = 4
        mapped["classification_confidence"] = 0.98
        mapped["classification_reason"] = "security_finding_threat_evidence"
        mapped["classification_evidence"] = evidence
        return mapped

    # -----------------------------------------------------------------------
    # RULE SET 2: Network Activity / DNS Activity (Category 4 / Class 4003)
    # -----------------------------------------------------------------------
    has_dns_port = 53 in ports
    has_dns_proto = protocol in ("dns", "domain")
    dns_matches = token_set.intersection(_DNS_QUERY_KEYWORDS)

    if (has_dns_port or has_dns_proto) or (len(dns_matches) >= 1 and has_ip):
        evidence = []
        if has_dns_port:
            evidence.append("port:53")
        if has_dns_proto:
            evidence.append("proto:dns")
        evidence.extend(sorted(list(dns_matches)))
        mapped["category_name"] = "Network Activity"
        mapped["category_uid"] = 4
        mapped["class_name"] = "DNS Activity"
        mapped["class_uid"] = 4003
        if not mapped.get("activity_name") or mapped.get("activity_name") in ("unknown", "generic"):
            mapped["activity_name"] = "Query"
            mapped["activity_id"] = 1
        mapped["classification_confidence"] = 0.98
        mapped["classification_reason"] = "network_dns_activity_evidence"
        mapped["classification_evidence"] = evidence
        return mapped

    # -----------------------------------------------------------------------
    # RULE SET 3: Network Activity / SSH Activity (Category 4 / Class 4007)
    # -----------------------------------------------------------------------
    has_ssh_port = 22 in ports
    has_ssh_proto = protocol == "ssh"
    ssh_matches = token_set.intersection(_SSH_KEYWORDS)

    if (has_ssh_port or has_ssh_proto) and (ssh_matches or has_ip) or (
        ssh_matches and any(m in ("ssh_connection", "ssh_login", "ssh_disconnect", "ssh_session", "key_exchange", "kex") for m in ssh_matches)
    ):
        evidence = []
        if has_ssh_port:
            evidence.append("port:22")
        if has_ssh_proto:
            evidence.append("proto:ssh")
        evidence.extend(sorted(list(ssh_matches)))
        mapped["category_name"] = "Network Activity"
        mapped["category_uid"] = 4
        mapped["class_name"] = "SSH Activity"
        mapped["class_uid"] = 4007
        if not mapped.get("activity_name") or mapped.get("activity_name") in ("unknown", "generic"):
            if any("disconnect" in s or "close" in s for s in evidence):
                mapped["activity_name"] = "Close"
                mapped["activity_id"] = 2
            elif any("login" in s or "logon" in s for s in evidence):
                mapped["activity_name"] = "Logon"
                mapped["activity_id"] = 1
            else:
                mapped["activity_name"] = "Open"
                mapped["activity_id"] = 1
        mapped["classification_confidence"] = 0.95
        mapped["classification_reason"] = "network_ssh_activity_evidence"
        mapped["classification_evidence"] = evidence
        return mapped

    # -----------------------------------------------------------------------
    # RULE SET 4: Network Activity / HTTP Activity (Category 4 / Class 4002)
    # -----------------------------------------------------------------------
    has_http_port = any(p in ports for p in (80, 443, 8080, 8443, 8000))
    has_http_proto = protocol in ("http", "https", "tls", "ssl")
    http_verb_matches = token_set.intersection(_HTTP_VERBS)
    http_matches = token_set.intersection(_HTTP_KEYWORDS)

    if (http_verb_matches and (has_http_port or has_http_proto or has_ip or http_matches)) or (
        (has_http_port or has_http_proto) and http_matches
    ):
        evidence = []
        if has_http_port:
            evidence.append(f"http_port:{sorted(list(ports.intersection({80, 443, 8080, 8443, 8000})))}")
        if has_http_proto:
            evidence.append(f"proto:{protocol}")
        evidence.extend(sorted(list(http_verb_matches)))
        evidence.extend(sorted(list(http_matches)))

        mapped["category_name"] = "Network Activity"
        mapped["category_uid"] = 4
        mapped["class_name"] = "HTTP Activity"
        mapped["class_uid"] = 4002
        if not mapped.get("activity_name") or mapped.get("activity_name") in ("unknown", "generic"):
            verb = list(http_verb_matches)[0].upper() if http_verb_matches else "GET"
            mapped["activity_name"] = verb
            mapped["activity_id"] = 1 if verb in ("GET", "HEAD") else 2
        if not mapped.get("status"):
            if any(code in token_set for code in ("200", "201", "204", "301", "302", "304")):
                mapped["status"] = "Success"
                mapped["status_id"] = 1
            elif any(code in token_set for code in ("400", "401", "403", "404", "500", "502", "503")):
                mapped["status"] = "Failure"
                mapped["status_id"] = 2
        mapped["classification_confidence"] = 0.96
        mapped["classification_reason"] = "network_http_activity_evidence"
        mapped["classification_evidence"] = evidence
        return mapped

    # -----------------------------------------------------------------------
    # RULE SET 5: Application Activity / Database Queries (Category 6 / Class 6001)
    # -----------------------------------------------------------------------
    db_matches = token_set.intersection(_DATABASE_QUERY_KEYWORDS)
    if db_matches:
        evidence = sorted(list(db_matches))
        mapped["category_name"] = "Application Activity"
        mapped["category_uid"] = 6
        mapped["class_name"] = "Application Activity"
        mapped["class_uid"] = 6001
        if not mapped.get("activity_name") or mapped.get("activity_name") in ("unknown", "generic"):
            mapped["activity_name"] = "Query"
            mapped["activity_id"] = 1
        mapped["classification_confidence"] = 0.92
        mapped["classification_reason"] = "application_database_query_evidence"
        mapped["classification_evidence"] = evidence
        return mapped

    # -----------------------------------------------------------------------
    # RULE SET 5b: Application Activity / Application Lifecycle (Category 6 / Class 6001)
    # -----------------------------------------------------------------------
    app_matches = token_set.intersection(_APP_LIFECYCLE_KEYWORDS)
    if app_matches:
        evidence = sorted(list(app_matches))
        mapped["category_name"] = "Application Activity"
        mapped["category_uid"] = 6
        mapped["class_name"] = "Application Lifecycle"
        mapped["class_uid"] = 6001
        if not mapped.get("activity_name") or mapped.get("activity_name") in ("unknown", "generic"):
            mapped["activity_name"] = "Log"
            mapped["activity_id"] = 1
        if not mapped.get("severity"):
            if "warn" in token_set or "warning" in token_set:
                mapped["severity"] = "Medium"
                mapped["severity_id"] = 3
            elif "error" in token_set or "fatal" in token_set:
                mapped["severity"] = "High"
                mapped["severity_id"] = 4
            elif "info" in token_set or "informational" in token_set:
                mapped["severity"] = "Informational"
                mapped["severity_id"] = 1
        if not mapped.get("status") and ("fail" in token_set or "failed" in token_set):
            mapped["status"] = "Failure"
            mapped["status_id"] = 2
        mapped["classification_confidence"] = 0.92
        mapped["classification_reason"] = "application_lifecycle_evidence"
        mapped["classification_evidence"] = evidence
        return mapped

    # -----------------------------------------------------------------------
    # RULE SET 6: Identity & Access Management (Category 3 / Class 3002)
    # -----------------------------------------------------------------------
    auth_failure_matches = token_set.intersection(_AUTH_FAILURE_KEYWORDS)
    auth_success_matches = token_set.intersection(_AUTH_SUCCESS_KEYWORDS)
    auth_logoff_matches = token_set.intersection(_AUTH_LOGOFF_KEYWORDS)
    auth_general_matches = token_set.intersection(_AUTH_GENERAL_KEYWORDS)

    # Multi-signal check for Logoff
    if auth_logoff_matches:
        evidence = sorted(list(auth_logoff_matches))
        if has_user:
            evidence.append(f"user:{user}")
        mapped["category_name"] = "Identity & Access Management"
        mapped["category_uid"] = 3
        mapped["class_name"] = "Authentication"
        mapped["class_uid"] = 3002
        if not mapped.get("activity_name") or mapped.get("activity_name") in ("unknown", "generic"):
            mapped["activity_name"] = "Logoff"
            mapped["activity_id"] = 2
        mapped["classification_confidence"] = 0.96
        mapped["classification_reason"] = "iam_auth_logoff_evidence"
        mapped["classification_evidence"] = evidence
        return mapped

    # Multi-signal check for Logon Failure
    if auth_failure_matches:
        evidence = sorted(list(auth_failure_matches))
        if has_user:
            evidence.append(f"user:{user}")
        mapped["category_name"] = "Identity & Access Management"
        mapped["category_uid"] = 3
        mapped["class_name"] = "Authentication"
        mapped["class_uid"] = 3002
        if not mapped.get("activity_name") or mapped.get("activity_name") in ("unknown", "generic"):
            mapped["activity_name"] = "Logon"
            mapped["activity_id"] = 1
        mapped["status"] = "Failure"
        mapped["status_id"] = 2
        mapped["severity"] = "High"
        mapped["severity_id"] = 4
        mapped["classification_confidence"] = 0.98
        mapped["classification_reason"] = "iam_auth_logon_failure_evidence"
        mapped["classification_evidence"] = evidence
        return mapped

    # Multi-signal check for Logon Success
    if auth_success_matches:
        evidence = sorted(list(auth_success_matches))
        if has_user:
            evidence.append(f"user:{user}")
        mapped["category_name"] = "Identity & Access Management"
        mapped["category_uid"] = 3
        mapped["class_name"] = "Authentication"
        mapped["class_uid"] = 3002
        if not mapped.get("activity_name") or mapped.get("activity_name") in ("unknown", "generic"):
            mapped["activity_name"] = "Logon"
            mapped["activity_id"] = 1
        if not mapped.get("status"):
            mapped["status"] = "Success"
            mapped["status_id"] = 1
        if not mapped.get("severity"):
            mapped["severity"] = "Informational"
            mapped["severity_id"] = 1
        mapped["classification_confidence"] = 0.98
        mapped["classification_reason"] = "iam_auth_logon_success_evidence"
        mapped["classification_evidence"] = evidence
        return mapped

    # General auth action (e.g. action="login", action="authenticate")
    # Rule 3 Guard: A user alone does NOT trigger auth; must have an auth verb!
    if auth_general_matches and (
        any(m in ("login", "logon", "authenticate", "auth", "sudo", "elevate", "signin") for m in auth_general_matches)
    ):
        evidence = sorted(list(auth_general_matches))
        if has_user:
            evidence.append(f"user:{user}")
        mapped["category_name"] = "Identity & Access Management"
        mapped["category_uid"] = 3
        mapped["class_name"] = "Authentication"
        mapped["class_uid"] = 3002
        if not mapped.get("activity_name") or mapped.get("activity_name") in ("unknown", "generic"):
            mapped["activity_name"] = "Logon"
            mapped["activity_id"] = 1
        mapped["classification_confidence"] = 0.92
        mapped["classification_reason"] = "iam_auth_general_evidence"
        mapped["classification_evidence"] = evidence
        return mapped

    # -----------------------------------------------------------------------
    # RULE SET 7: System Activity / Process Activity (Category 1 / Class 1007)
    # -----------------------------------------------------------------------
    process_matches = token_set.intersection(_PROCESS_EXEC_KEYWORDS)
    if process_matches:
        evidence = sorted(list(process_matches))
        mapped["category_name"] = "System Activity"
        mapped["category_uid"] = 1
        mapped["class_name"] = "Process Activity"
        mapped["class_uid"] = 1007
        if not mapped.get("activity_name") or mapped.get("activity_name") in ("unknown", "generic"):
            mapped["activity_name"] = "Execute"
            mapped["activity_id"] = 1
        mapped["classification_confidence"] = 0.95
        mapped["classification_reason"] = "system_process_activity_evidence"
        mapped["classification_evidence"] = evidence
        return mapped

    # -----------------------------------------------------------------------
    # RULE SET 8: System Activity / File System Activity (Category 1 / Class 1001)
    # -----------------------------------------------------------------------
    file_matches = token_set.intersection(_FILE_SYSTEM_KEYWORDS)
    if file_matches:
        evidence = sorted(list(file_matches))
        mapped["category_name"] = "System Activity"
        mapped["category_uid"] = 1
        mapped["class_name"] = "File System Activity"
        mapped["class_uid"] = 1001

        if not mapped.get("activity_name") or mapped.get("activity_name") in ("unknown", "generic"):
            if any("creat" in s for s in file_matches):
                mapped["activity_name"] = "Create"
                mapped["activity_id"] = 1
            elif any("delet" in s or "unlink" in s or "rmdir" in s for s in file_matches):
                mapped["activity_name"] = "Delete"
                mapped["activity_id"] = 2
            elif any("modif" in s or "chmod" in s or "chown" in s or "writ" in s for s in file_matches):
                mapped["activity_name"] = "Modify"
                mapped["activity_id"] = 3
            else:
                mapped["activity_name"] = "Read"
                mapped["activity_id"] = 4

        mapped["classification_confidence"] = 0.95
        mapped["classification_reason"] = "system_file_activity_evidence"
        mapped["classification_evidence"] = evidence
        return mapped

    # -----------------------------------------------------------------------
    # RULE SET 9: Network Activity / General Traffic & Firewall (Category 4 / Class 4001)
    # -----------------------------------------------------------------------
    network_verb_matches = token_set.intersection(_NETWORK_VERB_KEYWORDS)
    if network_verb_matches or (has_ip and (ports or protocol) and ("traffic" in token_set or "connection" in token_set or "connect" in token_set)):
        evidence = sorted(list(network_verb_matches))
        if ports:
            evidence.append(f"ports:{sorted(list(ports))}")
        if protocol:
            evidence.append(f"proto:{protocol}")
        if has_ip:
            evidence.append("ip_endpoints_present")

        mapped["category_name"] = "Network Activity"
        mapped["category_uid"] = 4
        mapped["class_name"] = "Network Activity"
        mapped["class_uid"] = 4001

        if any("drop" in s or "den" in s or "block" in s or "filter" in s for s in evidence):
            if not mapped.get("activity_name") or mapped.get("activity_name") in ("unknown", "generic"):
                mapped["activity_name"] = "Drop"
                mapped["activity_id"] = 4
            mapped["status"] = "Failure"
            mapped["status_id"] = 2
        elif any("close" in s or "rst" in s or "reset" in s for s in evidence):
            if not mapped.get("activity_name") or mapped.get("activity_name") in ("unknown", "generic"):
                mapped["activity_name"] = "Close"
                mapped["activity_id"] = 2
        elif any("open" in s or "accept" in s or "permit" in s or "allow" in s or "established" in s for s in evidence):
            if not mapped.get("activity_name") or mapped.get("activity_name") in ("unknown", "generic"):
                mapped["activity_name"] = "Open"
                mapped["activity_id"] = 1
        else:
            if not mapped.get("activity_name") or mapped.get("activity_name") in ("unknown", "generic"):
                mapped["activity_name"] = "Traffic"
                mapped["activity_id"] = 6

        mapped["classification_confidence"] = 0.90
        mapped["classification_reason"] = "network_connection_traffic_evidence"
        mapped["classification_evidence"] = evidence
        return mapped

    # -----------------------------------------------------------------------
    # RULE SET 10: INSUFFICIENT SEMANTIC EVIDENCE (Safest Supported Fallback)
    # -----------------------------------------------------------------------
    # Rules 1, 2, 3, 4:
    # Do NOT invent a class.
    # Do NOT classify solely because an IP exists.
    # Do NOT classify solely because a user exists.
    # Do NOT classify every unknown event as System Activity!
    weak_signals = sorted(list(token_set.intersection(_WEAK_WORDS)))
    if has_ip:
        weak_signals.append("isolated_ip")
    if has_user:
        weak_signals.append("isolated_user")

    # Clear any misleading fallback defaults
    mapped["category_name"] = None
    mapped["category_uid"] = None
    mapped["class_name"] = None
    mapped["class_uid"] = None
    mapped["activity_name"] = mapped.get("activity_name") or None
    mapped["activity_id"] = None
    mapped["classification_confidence"] = 0.0
    mapped["classification_reason"] = "insufficient_semantic_evidence"
    mapped["classification_evidence"] = weak_signals

    return mapped
