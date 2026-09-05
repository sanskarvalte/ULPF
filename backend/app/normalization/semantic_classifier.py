"""
Central Evidence-Based Semantic Classifier for OCSF Normalization.

Consolidates deterministic multi-signal semantic classification across:
- Explicit event_type / authoritative subsystem taxonomy
- Explicit service & application semantics
- Protocol + action (SSH, HTTP, DNS, Network)
- Strong action & event keywords (Authentication, Process Execution, Security Findings)
- Message text & composite phrases
- Field combinations (host + process + pid, host + finding + indicator)
- Ambiguity & Weak-Signal Guards (never default to System Activity, never guess on ambiguous verbs)

Guiding Principle:
    CORRECT EVENT > UNKNOWN / REVIEW EVENT > INCORRECT EVENT
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Set, Tuple, Union

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
    "accepted_password", "accepted", "valid_credentials",
}

_AUTH_FAILURE_KEYWORDS = {
    "login_failed", "logon_failed", "failed_login", "failed_logon",
    "auth_failed", "authentication_failed", "auth_failure", "authentication_failure",
    "invalid_password", "bad_password", "wrong_password", "bad_credentials",
    "invalid_credentials", "access_denied", "permission_denied", "account_locked",
    "user_unknown", "unknown_user", "invalid_user", "failed_password", "denied",
}

_AUTH_LOGOFF_KEYWORDS = {
    "logout", "logoff", "signout", "sign_out", "session_terminated",
    "disconnect_session", "session_expired", "logged_out",
    "logged_off", "user_logout", "user_logoff",
}

_AUTH_GENERAL_KEYWORDS = {
    "login", "logon", "authenticate", "auth", "signin", "sign_in",
    "interactive_logon", "network_logon", "remote_logon", "kerberos",
    "ntlm", "saml", "oauth", "sso", "elevate", "sudo",
    "password_authentication", "user_login", "ssh_login",
}

# Network Indicators
_DNS_QUERY_KEYWORDS = {
    "dns_query", "dns_request", "dns_lookup", "query_type", "dns_response",
    "dns_answer", "a_record", "aaaa_record", "ptr_record", "cname_record",
    "mx_record", "txt_record", "ns_record", "srv_record", "soa_record",
    "resolver",
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
    "process_create", "command_executed", "command_run", "execve", "fork", "spawn",
    "/bin/bash", "/bin/sh", "/bin/zsh", "cmd.exe", "powershell.exe",
    "process_killed", "process_terminated", "kill_process", "exit_code",
    "child_process", "parent_process", "ppid", "subshell", "executable",
    "command_line", "process_activity",
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
    "malware", "virus_detected", "trojan_detected", "ransomware_detected", "worm_detected",
    "intrusion_detected", "intrusion_attempt", "intrusion", "exploit_attempt", "exploit_blocked",
    "vulnerability_found", "vulnerability", "cve_", "ids_alert", "ips_alert", "waf_blocked",
    "quarantine_file", "attack_detected", "brute_force_detected", "security_finding",
    "suspicious_activity", "ioc",
}

# Application / Database Query Indicators
_DATABASE_QUERY_KEYWORDS = {
    "database_query", "db_query", "sql_query", "query_executed",
    "sql_select", "sql_insert", "sql_update", "sql_delete",
    "drop_table", "create_table", "alter_table", "commit", "rollback",
    "transaction_begin", "postgres", "mysql", "oracle", "mongodb",
    "sql_execution", "prepared_statement",
}

# Weak or ambiguous words that MUST NEVER trigger classification alone
_WEAK_WORDS = {
    "info", "information", "informational", "status", "ok", "test",
    "error", "warning", "debug", "trace", "notice", "event", "log",
    "service", "app", "system", "user", "client", "server", "host",
    "msg", "message", "type", "name", "id", "data", "success", "failure",
    "activity", "update", "state", "reading", "value",
}

# Ambiguous action verbs that must NOT be guessed into OCSF classes without strong context
_AMBIGUOUS_ACTIONS = {
    "update", "change", "modify", "activity", "sync", "check", "process", "run", "event",
}


def _clean_token(value: Any) -> str:
    """Normalize string into a clean lowercase underscore token."""
    if value is None:
        return ""
    return str(value).strip().lower().replace("-", "_").replace(" ", "_")


def _extract_all_evidence_tokens(mapped: Dict[str, Any]) -> Tuple[List[str], Set[str]]:
    """
    Extract discrete tokens and phrases from all candidate fields, raw text, and unmapped attributes.
    Returns: (ordered_tokens, token_set)
    """
    token_set: Set[str] = set()
    token_list: List[str] = []

    def add_token(t: str):
        cleaned = _clean_token(t)
        if cleaned and cleaned not in token_set:
            token_set.add(cleaned)
            token_list.append(cleaned)
            for sub in re.split(r"[._$]+", cleaned):
                if len(sub) >= 2 and sub not in token_set:
                    token_set.add(sub)
                    token_list.append(sub)

    # 1. Primary candidate fields
    for field in (
        "activity_name", "action", "event_action", "operation",
        "event_type", "type_name", "service_name", "product",
        "protocol", "log_name", "reason", "finding", "indicator",
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

    # 3. Unmapped attributes
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

        # Auth phrases
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
            "exploit blocked", "cve_", "waf blocked", "valid_credentials",
            "invalid_credentials", "malware_detected",
        ):
            if kw in raw_lower:
                add_token(kw)

        # SQL verbs
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


def classify_semantics(
    event_or_dict: Union[Any, Dict[str, Any]],
) -> Dict[str, Any]:
    """
    Central Evidence-Based Semantic Classifier.

    Evaluates normalized/canonical evidence and returns structured semantic classification:
    {
        "category_name": Optional[str],
        "category_uid": Optional[int],
        "class_name": Optional[str],
        "class_uid": Optional[int],
        "activity_name": Optional[str],
        "activity_id": Optional[int],
        "semantic_confidence": float,
        "classification_reason": str,
        "classification_status": str,  # "classified", "review", "unknown"
        "classification_evidence": List[str],
        "status": Optional[str],
        "status_id": Optional[int],
        "severity": Optional[str],
        "severity_id": Optional[int],
    }

    Strict Rules:
    1. Correct Event > Review Event > Incorrect Event.
    2. Never fabricate semantic meaning.
    3. Never default ambiguous events to "System Activity".
    4. If evidence is ambiguous or insufficient, classify as "review".
    """
    if hasattr(event_or_dict, "model_dump"):
        mapped = event_or_dict.model_dump()
    elif isinstance(event_or_dict, dict):
        mapped = dict(event_or_dict)
    else:
        mapped = vars(event_or_dict) if hasattr(event_or_dict, "__dict__") else {}

    token_list, token_set = _extract_all_evidence_tokens(mapped)

    unmapped_dict = mapped.get("unmapped") if isinstance(mapped.get("unmapped"), dict) else {}

    src_ip = mapped.get("src_ip")
    dst_ip = mapped.get("dst_ip")
    if not src_ip:
        src_ip = unmapped_dict.get("src_ip") or unmapped_dict.get("client") or unmapped_dict.get("src")
    if not dst_ip:
        dst_ip = unmapped_dict.get("dst_ip") or unmapped_dict.get("server") or unmapped_dict.get("dst")

    has_ip = bool((src_ip and str(src_ip).strip()) or (dst_ip and str(dst_ip).strip()))
    if not has_ip:
        has_ip = any(re.match(r"^(?:\d{1,3}\.){3}\d{1,3}$", t) for t in token_set)

    src_port = mapped.get("src_port") or unmapped_dict.get("src_port") or unmapped_dict.get("sport")
    dst_port = mapped.get("dst_port") or unmapped_dict.get("dst_port") or unmapped_dict.get("dport")
    ports: Set[int] = set()
    for p in (src_port, dst_port):
        if isinstance(p, int) and 0 < p <= 65535:
            ports.add(p)
        elif isinstance(p, str) and p.isdigit():
            val = int(p)
            if 0 < val <= 65535:
                ports.add(val)

    raw_lower = (mapped.get("raw_event") or "").lower()
    for m in re.finditer(r"\b(?:dport|sport|port)=(\d{1,5})\b", raw_lower):
        val = int(m.group(1))
        if 0 < val <= 65535:
            ports.add(val)

    protocol = _clean_token(mapped.get("protocol") or unmapped_dict.get("protocol"))
    if not protocol:
        proto_match = re.search(r"\bprotocol=([a-zA-Z0-9_-]+)\b", raw_lower)
        if proto_match:
            protocol = _clean_token(proto_match.group(1))

    user = mapped.get("user") or unmapped_dict.get("user")
    has_user = bool(user and str(user).strip())

    action_clean = _clean_token(mapped.get("action") or unmapped_dict.get("action"))
    if not action_clean:
        act_match = re.search(r"\b(?:action|act)=([a-zA-Z0-9_-]+)\b", raw_lower)
        if act_match:
            action_clean = _clean_token(act_match.group(1))

    # Pre-calculate weak signals list for fallback / evidence tracking
    weak_signals = sorted(list(token_set.intersection(_WEAK_WORDS)))
    if has_ip:
        weak_signals.append("isolated_ip")
    if has_user:
        weak_signals.append("isolated_user")

    # -----------------------------------------------------------------------
    # AMBIGUITY PRE-GUARD: Ambiguous action verbs with NO strong domain evidence
    # Example: action=update status=SUCCESS or event=activity
    # -----------------------------------------------------------------------
    has_strong_auth = bool(token_set.intersection(_AUTH_SUCCESS_KEYWORDS | _AUTH_FAILURE_KEYWORDS | _AUTH_LOGOFF_KEYWORDS | _AUTH_GENERAL_KEYWORDS))
    has_strong_sec = bool(token_set.intersection(_SECURITY_FINDING_KEYWORDS))
    has_strong_proc = bool(token_set.intersection(_PROCESS_EXEC_KEYWORDS)) or bool(mapped.get("process") or mapped.get("executable") or mapped.get("pid"))
    has_strong_dns = bool(token_set.intersection(_DNS_QUERY_KEYWORDS)) or (protocol in ("dns", "domain")) or (53 in ports)
    has_strong_http = bool(token_set.intersection(_HTTP_VERBS | _HTTP_KEYWORDS)) or (protocol in ("http", "https")) or bool(ports.intersection({80, 443, 8080, 8443}))
    has_strong_ssh = (protocol == "ssh") or (22 in ports) or bool(token_set.intersection(_SSH_KEYWORDS))
    has_strong_db = bool(token_set.intersection(_DATABASE_QUERY_KEYWORDS))
    has_strong_file = bool(token_set.intersection(_FILE_SYSTEM_KEYWORDS))

    # If the ONLY non-weak signal is an ambiguous action like 'update', do NOT guess!
    if action_clean in _AMBIGUOUS_ACTIONS and not (has_strong_auth or has_strong_sec or has_strong_proc or has_strong_dns or has_strong_http or has_strong_ssh or has_strong_db or has_strong_file):
        return {
            "category_name": None,
            "category_uid": None,
            "class_name": None,
            "class_uid": None,
            "activity_name": mapped.get("activity_name") or (action_clean.title() if action_clean else None),
            "activity_id": None,
            "semantic_confidence": 0.0,
            "classification_reason": "insufficient_semantic_evidence",
            "classification_status": "review",
            "classification_evidence": weak_signals,
            "status": mapped.get("status"),
            "status_id": mapped.get("status_id"),
            "severity": mapped.get("severity"),
            "severity_id": mapped.get("severity_id"),
        }

    # -----------------------------------------------------------------------
    # PRIORITY 1: Explicit Subsystem / Authoritative Daemon Taxonomy
    # -----------------------------------------------------------------------
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

            return {
                "category_name": cat,
                "category_uid": cat_uid,
                "class_name": cls_name,
                "class_uid": cls_uid,
                "activity_name": act_name,
                "activity_id": act_id,
                "semantic_confidence": 0.99,
                "classification_reason": f"authoritative_process_taxonomy_{proc}",
                "classification_status": "classified",
                "classification_evidence": [f"authoritative_daemon:{proc}"],
                "status": mapped.get("status"),
                "status_id": mapped.get("status_id"),
                "severity": mapped.get("severity"),
                "severity_id": mapped.get("severity_id"),
            }

    # -----------------------------------------------------------------------
    # PRIORITY 2: Security Findings / Threats / Alerts (Category 2 / Class 2001)
    # -----------------------------------------------------------------------
    security_matches = token_set.intersection(_SECURITY_FINDING_KEYWORDS)
    finding_val = mapped.get("finding")
    indicator_val = mapped.get("indicator")
    if security_matches or (finding_val and any(k in str(finding_val).lower() for k in ("malware", "threat", "alert", "attack", "exploit"))):
        evidence = sorted(list(security_matches))
        if finding_val:
            evidence.append(f"finding:{finding_val}")
        if indicator_val:
            evidence.append(f"indicator:{indicator_val}")

        is_deny = any("blocked" in s or "quarantine" in s or "drop" in s for s in evidence)
        act_name = "Deny" if is_deny else "Alert"
        act_id = 5 if is_deny else 1

        return {
            "category_name": "Security Finding",
            "category_uid": 2,
            "class_name": "Security Finding",
            "class_uid": 2001,
            "activity_name": act_name,
            "activity_id": act_id,
            "semantic_confidence": 0.98,
            "classification_reason": "security_finding_threat_evidence",
            "classification_status": "classified",
            "classification_evidence": evidence,
            "status": mapped.get("status"),
            "status_id": mapped.get("status_id"),
            "severity": mapped.get("severity") or "High",
            "severity_id": mapped.get("severity_id") or 4,
        }

    # -----------------------------------------------------------------------
    # PRIORITY 2b: Kernel Firewall / IPTables / Network Drop
    # -----------------------------------------------------------------------
    is_firewall_drop = is_kernel_firewall or (
        bool(token_set.intersection({"iptables", "ufw", "netfilter", "firewall"}))
        and any(w in token_set for w in ("drop", "dropped", "deny", "action_drop", "blocked", "reject"))
    )
    if is_firewall_drop:
        evidence = sorted(list(token_set.intersection({"iptables", "ufw", "netfilter", "firewall", "drop", "dropped", "deny", "action_drop", "blocked", "reject"})))
        if ports:
            evidence.append(f"ports:{sorted(list(ports))}")
        if protocol:
            evidence.append(f"proto:{protocol}")
        if has_ip:
            evidence.append("ip_endpoints_present")

        return {
            "category_name": "Network Activity",
            "category_uid": 4,
            "class_name": "Network Activity",
            "class_uid": 4001,
            "activity_name": mapped.get("activity_name") or "Drop",
            "activity_id": mapped.get("activity_id") or 4,
            "semantic_confidence": 0.96,
            "classification_reason": "network_firewall_drop_evidence",
            "classification_status": "classified",
            "classification_evidence": evidence,
            "status": mapped.get("status") or "Failure",
            "status_id": mapped.get("status_id") or 2,
            "severity": mapped.get("severity"),
            "severity_id": mapped.get("severity_id"),
        }

    # -----------------------------------------------------------------------
    # PRIORITY 3a: Protocol SSH Semantics
    # Check if SSH contains authentication semantics vs connection semantics
    # -----------------------------------------------------------------------
    has_ssh_proto = protocol == "ssh" or bool(re.search(r"\bprotocol=ssh\b", raw_lower))
    has_ssh_port = 22 in ports or bool(re.search(r"\b(?:dport|sport|port)=?22\b", raw_lower))
    ssh_matches = token_set.intersection(_SSH_KEYWORDS)

    if (has_ssh_proto or has_ssh_port or ssh_matches) and not is_firewall_drop:
        auth_success = bool(token_set.intersection(_AUTH_SUCCESS_KEYWORDS)) or "result=accepted" in raw_lower or "accepted password" in raw_lower or "valid_credentials" in raw_lower
        auth_failure = bool(token_set.intersection(_AUTH_FAILURE_KEYWORDS)) or "result=denied" in raw_lower or "failed password" in raw_lower or "invalid_credentials" in raw_lower
        auth_logoff = bool(token_set.intersection(_AUTH_LOGOFF_KEYWORDS))
        auth_general = bool(token_set.intersection(_AUTH_GENERAL_KEYWORDS))

        evidence = sorted(list(ssh_matches))
        if has_ssh_port:
            evidence.append("port:22")
        if has_ssh_proto:
            evidence.append("proto:ssh")
        if has_user:
            evidence.append(f"user:{user}")

        if auth_failure:
            evidence.extend(sorted(list(token_set.intersection(_AUTH_FAILURE_KEYWORDS))))
            return {
                "category_name": "Identity & Access Management",
                "category_uid": 3,
                "class_name": "Authentication",
                "class_uid": 3002,
                "activity_name": "Logon",
                "activity_id": 1,
                "semantic_confidence": 0.99,
                "classification_reason": "ssh_authentication_failure_evidence",
                "classification_status": "classified",
                "classification_evidence": evidence,
                "status": "Failure",
                "status_id": 2,
                "severity": mapped.get("severity") or "High",
                "severity_id": mapped.get("severity_id") or 4,
            }
        elif auth_success:
            evidence.extend(sorted(list(token_set.intersection(_AUTH_SUCCESS_KEYWORDS))))
            return {
                "category_name": "Identity & Access Management",
                "category_uid": 3,
                "class_name": "Authentication",
                "class_uid": 3002,
                "activity_name": "Logon",
                "activity_id": 1,
                "semantic_confidence": 0.99,
                "classification_reason": "ssh_authentication_success_evidence",
                "classification_status": "classified",
                "classification_evidence": evidence,
                "status": "Success",
                "status_id": 1,
                "severity": mapped.get("severity") or "Informational",
                "severity_id": mapped.get("severity_id") or 1,
            }
        elif auth_logoff:
            evidence.extend(sorted(list(token_set.intersection(_AUTH_LOGOFF_KEYWORDS))))
            return {
                "category_name": "Identity & Access Management",
                "category_uid": 3,
                "class_name": "Authentication",
                "class_uid": 3002,
                "activity_name": "Logoff",
                "activity_id": 2,
                "semantic_confidence": 0.96,
                "classification_reason": "ssh_auth_logoff_evidence",
                "classification_status": "classified",
                "classification_evidence": evidence,
                "status": mapped.get("status") or "Success",
                "status_id": mapped.get("status_id") or 1,
                "severity": mapped.get("severity"),
                "severity_id": mapped.get("severity_id"),
            }
        else:
            # Pure SSH network activity (session, connect, disconnect, kex, ssh_login initiated) without auth results/credentials
            is_close = any("disconnect" in s or "close" in s for s in token_set) or "disconnect" in raw_lower or action_clean in ("disconnect", "close", "session_closed")
            is_login_verb = any("login" in s or "logon" in s for s in ssh_matches) or "login" in raw_lower or "logon" in raw_lower
            act_name = "Close" if is_close else ("Logon" if is_login_verb else "Open")
            act_id = 2 if is_close else 1
            return {
                "category_name": "Network Activity",
                "category_uid": 4,
                "class_name": "SSH Activity",
                "class_uid": 4007,
                "activity_name": act_name,
                "activity_id": act_id,
                "semantic_confidence": 0.95,
                "classification_reason": "network_ssh_activity_evidence",
                "classification_status": "classified",
                "classification_evidence": evidence,
                "status": mapped.get("status"),
                "status_id": mapped.get("status_id"),
                "severity": mapped.get("severity"),
                "severity_id": mapped.get("severity_id"),
            }

    # -----------------------------------------------------------------------
    # PRIORITY 3b: Protocol DNS Semantics (Category 4 / Class 4003)
    # -----------------------------------------------------------------------
    has_dns_port = 53 in ports or bool(re.search(r"\b(?:dport|sport|port)=?53\b", raw_lower))
    has_dns_proto = protocol in ("dns", "domain") or bool(re.search(r"\bprotocol=dns\b", raw_lower))
    dns_matches = token_set.intersection(_DNS_QUERY_KEYWORDS)
    has_dns_fields = bool(mapped.get("query") or mapped.get("query_type") or bool(re.search(r"\bquery=", raw_lower)))

    if (has_dns_port or has_dns_proto or has_dns_fields) or (len(dns_matches) >= 1 and has_ip):
        evidence = []
        if has_dns_port:
            evidence.append("port:53")
        if has_dns_proto:
            evidence.append("proto:dns")
        evidence.extend(sorted(list(dns_matches)))
        return {
            "category_name": "Network Activity",
            "category_uid": 4,
            "class_name": "DNS Activity",
            "class_uid": 4003,
            "activity_name": "Query",
            "activity_id": 1,
            "semantic_confidence": 0.98,
            "classification_reason": "network_dns_activity_evidence",
            "classification_status": "classified",
            "classification_evidence": evidence,
            "status": mapped.get("status"),
            "status_id": mapped.get("status_id"),
            "severity": mapped.get("severity"),
            "severity_id": mapped.get("severity_id"),
        }

    # -----------------------------------------------------------------------
    # PRIORITY 3c: Protocol HTTP Semantics (Category 4 / Class 4002)
    # -----------------------------------------------------------------------
    has_http_port = bool(ports.intersection({80, 443, 8080, 8443, 8000})) or any(f"dport={p}" in raw_lower for p in (80, 443, 8080, 8443))
    has_http_proto = protocol in ("http", "https", "tls", "ssl") or "protocol=http" in raw_lower
    http_verb_matches = token_set.intersection(_HTTP_VERBS)
    method_val = _clean_token(mapped.get("method") or mapped.get("http_method"))
    if method_val in _HTTP_VERBS:
        http_verb_matches.add(method_val)
    has_http_path = bool(mapped.get("path") or mapped.get("url") or "path=" in raw_lower or "get /" in raw_lower or "post /" in raw_lower)
    http_matches = token_set.intersection(_HTTP_KEYWORDS)

    if (http_verb_matches and (has_http_port or has_http_proto or has_ip or has_http_path or http_matches)) or (
        (has_http_port or has_http_proto) and (http_matches or has_http_path)
    ):
        evidence = []
        if has_http_port:
            evidence.append("port:http")
        if has_http_proto:
            evidence.append(f"proto:{protocol}")
        evidence.extend(sorted(list(http_verb_matches)))
        evidence.extend(sorted(list(http_matches)))

        verb = list(http_verb_matches)[0].upper() if http_verb_matches else (method_val.upper() if method_val else "GET")
        act_id = 1 if verb in ("GET", "HEAD") else 2

        # Status inference for HTTP
        st = mapped.get("status")
        st_id = mapped.get("status_id")
        if not st:
            if any(code in token_set for code in ("200", "201", "204", "301", "302", "304")):
                st, st_id = "Success", 1
            elif any(code in token_set for code in ("400", "401", "403", "404", "500", "502", "503")):
                st, st_id = "Failure", 2

        return {
            "category_name": "Network Activity",
            "category_uid": 4,
            "class_name": "HTTP Activity",
            "class_uid": 4002,
            "activity_name": verb,
            "activity_id": act_id,
            "semantic_confidence": 0.96,
            "classification_reason": "network_http_activity_evidence",
            "classification_status": "classified",
            "classification_evidence": evidence,
            "status": st,
            "status_id": st_id,
            "severity": mapped.get("severity"),
            "severity_id": mapped.get("severity_id"),
        }

    # -----------------------------------------------------------------------
    # PRIORITY 4a: Identity & Access Management (Non-SSH)
    # -----------------------------------------------------------------------
    auth_failure_matches = token_set.intersection(_AUTH_FAILURE_KEYWORDS)
    auth_success_matches = token_set.intersection(_AUTH_SUCCESS_KEYWORDS)
    auth_logoff_matches = token_set.intersection(_AUTH_LOGOFF_KEYWORDS)
    auth_general_matches = token_set.intersection(_AUTH_GENERAL_KEYWORDS)

    if auth_logoff_matches:
        evidence = sorted(list(auth_logoff_matches))
        if has_user:
            evidence.append(f"user:{user}")
        return {
            "category_name": "Identity & Access Management",
            "category_uid": 3,
            "class_name": "Authentication",
            "class_uid": 3002,
            "activity_name": "Logoff",
            "activity_id": 2,
            "semantic_confidence": 0.96,
            "classification_reason": "iam_auth_logoff_evidence",
            "classification_status": "classified",
            "classification_evidence": evidence,
            "status": mapped.get("status") or "Success",
            "status_id": mapped.get("status_id") or 1,
            "severity": mapped.get("severity"),
            "severity_id": mapped.get("severity_id"),
        }

    if auth_failure_matches:
        evidence = sorted(list(auth_failure_matches))
        if has_user:
            evidence.append(f"user:{user}")
        return {
            "category_name": "Identity & Access Management",
            "category_uid": 3,
            "class_name": "Authentication",
            "class_uid": 3002,
            "activity_name": "Logon",
            "activity_id": 1,
            "semantic_confidence": 0.98,
            "classification_reason": "iam_auth_logon_failure_evidence",
            "classification_status": "classified",
            "classification_evidence": evidence,
            "status": "Failure",
            "status_id": 2,
            "severity": mapped.get("severity") or "High",
            "severity_id": mapped.get("severity_id") or 4,
        }

    if auth_success_matches:
        evidence = sorted(list(auth_success_matches))
        if has_user:
            evidence.append(f"user:{user}")
        return {
            "category_name": "Identity & Access Management",
            "category_uid": 3,
            "class_name": "Authentication",
            "class_uid": 3002,
            "activity_name": "Logon",
            "activity_id": 1,
            "semantic_confidence": 0.98,
            "classification_reason": "iam_auth_logon_success_evidence",
            "classification_status": "classified",
            "classification_evidence": evidence,
            "status": mapped.get("status") or "Success",
            "status_id": mapped.get("status_id") or 1,
            "severity": mapped.get("severity") or "Informational",
            "severity_id": mapped.get("severity_id") or 1,
        }

    if auth_general_matches and (
        any(m in ("login", "logon", "authenticate", "auth", "sudo", "elevate", "signin") for m in auth_general_matches)
    ):
        evidence = sorted(list(auth_general_matches))
        if has_user:
            evidence.append(f"user:{user}")
        return {
            "category_name": "Identity & Access Management",
            "category_uid": 3,
            "class_name": "Authentication",
            "class_uid": 3002,
            "activity_name": "Logon",
            "activity_id": 1,
            "semantic_confidence": 0.92,
            "classification_reason": "iam_auth_general_evidence",
            "classification_status": "classified",
            "classification_evidence": evidence,
            "status": mapped.get("status"),
            "status_id": mapped.get("status_id"),
            "severity": mapped.get("severity"),
            "severity_id": mapped.get("severity_id"),
        }

    # -----------------------------------------------------------------------
    # PRIORITY 4b: Process Execution Semantics (Category 1 / Class 1007)
    # -----------------------------------------------------------------------
    process_matches = token_set.intersection(_PROCESS_EXEC_KEYWORDS)
    proc_val = mapped.get("process") or mapped.get("process_name") or mapped.get("executable") or unmapped_dict.get("process") or unmapped_dict.get("executable")
    has_process_field = bool(proc_val)
    has_command_field = bool(mapped.get("command") or mapped.get("command_line") or unmapped_dict.get("command") or unmapped_dict.get("cmd"))
    has_pid_field = bool(mapped.get("pid") or mapped.get("ppid") or unmapped_dict.get("pid"))

    if process_matches or ((has_process_field or has_command_field) and (has_pid_field or has_user or "process=" in raw_lower)):
        evidence = sorted(list(process_matches))
        if has_process_field:
            evidence.append(f"proc:{proc_val}")
        if has_command_field:
            evidence.append("command_present")
        return {
            "category_name": "System Activity",
            "category_uid": 1,
            "class_name": "Process Activity",
            "class_uid": 1007,
            "activity_name": "Execute",
            "activity_id": 1,
            "semantic_confidence": 0.95,
            "classification_reason": "system_process_activity_evidence",
            "classification_status": "classified",
            "classification_evidence": evidence,
            "status": mapped.get("status"),
            "status_id": mapped.get("status_id"),
            "severity": mapped.get("severity"),
            "severity_id": mapped.get("severity_id"),
        }

    # -----------------------------------------------------------------------
    # PRIORITY 4c: File System Semantics (Category 1 / Class 1001)
    # -----------------------------------------------------------------------
    file_matches = token_set.intersection(_FILE_SYSTEM_KEYWORDS)
    if file_matches:
        evidence = sorted(list(file_matches))
        if any("creat" in s for s in file_matches):
            act_name, act_id = "Create", 1
        elif any("delet" in s or "unlink" in s or "rmdir" in s for s in file_matches):
            act_name, act_id = "Delete", 2
        elif any("modif" in s or "chmod" in s or "chown" in s or "writ" in s for s in file_matches):
            act_name, act_id = "Modify", 3
        else:
            act_name, act_id = "Read", 4

        return {
            "category_name": "System Activity",
            "category_uid": 1,
            "class_name": "File System Activity",
            "class_uid": 1001,
            "activity_name": act_name,
            "activity_id": act_id,
            "semantic_confidence": 0.95,
            "classification_reason": "system_file_activity_evidence",
            "classification_status": "classified",
            "classification_evidence": evidence,
            "status": mapped.get("status"),
            "status_id": mapped.get("status_id"),
            "severity": mapped.get("severity"),
            "severity_id": mapped.get("severity_id"),
        }

    # -----------------------------------------------------------------------
    # PRIORITY 4d: Database Queries & App Lifecycle (Category 6)
    # -----------------------------------------------------------------------
    db_matches = token_set.intersection(_DATABASE_QUERY_KEYWORDS)
    if db_matches:
        evidence = sorted(list(db_matches))
        return {
            "category_name": "Application Activity",
            "category_uid": 6,
            "class_name": "Application Activity",
            "class_uid": 6001,
            "activity_name": "Query",
            "activity_id": 1,
            "semantic_confidence": 0.92,
            "classification_reason": "application_database_query_evidence",
            "classification_status": "classified",
            "classification_evidence": evidence,
            "status": mapped.get("status"),
            "status_id": mapped.get("status_id"),
            "severity": mapped.get("severity"),
            "severity_id": mapped.get("severity_id"),
        }

    app_matches = token_set.intersection(_APP_LIFECYCLE_KEYWORDS)
    if app_matches:
        evidence = sorted(list(app_matches))
        sev = mapped.get("severity")
        sev_id = mapped.get("severity_id")
        if not sev:
            if "warn" in token_set or "warning" in token_set:
                sev, sev_id = "Medium", 3
            elif "error" in token_set or "fatal" in token_set or "fail" in token_set:
                sev, sev_id = "High", 4
            elif "info" in token_set or "informational" in token_set:
                sev, sev_id = "Informational", 1

        st = mapped.get("status")
        st_id = mapped.get("status_id")
        if not st and ("fail" in token_set or "failed" in token_set):
            st, st_id = "Failure", 2

        return {
            "category_name": "Application Activity",
            "category_uid": 6,
            "class_name": "Application Lifecycle",
            "class_uid": 6001,
            "activity_name": "Log",
            "activity_id": 1,
            "semantic_confidence": 0.92,
            "classification_reason": "application_lifecycle_evidence",
            "classification_status": "classified",
            "classification_evidence": evidence,
            "status": st,
            "status_id": st_id,
            "severity": sev,
            "severity_id": sev_id,
        }

    # -----------------------------------------------------------------------
    # PRIORITY 4e: General Network Traffic & Firewall (Category 4 / Class 4001)
    # -----------------------------------------------------------------------
    network_verb_matches = token_set.intersection(_NETWORK_VERB_KEYWORDS)
    if network_verb_matches or (
        has_ip and (ports or protocol) and ("traffic" in token_set or "connection" in token_set or "connect" in token_set)
    ):
        evidence = sorted(list(network_verb_matches))
        if ports:
            evidence.append(f"ports:{sorted(list(ports))}")
        if protocol:
            evidence.append(f"proto:{protocol}")
        if has_ip:
            evidence.append("ip_endpoints_present")

        st = mapped.get("status")
        st_id = mapped.get("status_id")
        if any("drop" in s or "den" in s or "block" in s or "filter" in s for s in network_verb_matches):
            act_name, act_id = "Drop", 4
            st, st_id = "Failure", 2
        elif any("close" in s or "rst" in s or "reset" in s for s in network_verb_matches):
            act_name, act_id = "Close", 2
        elif any("open" in s or "accept" in s or "permit" in s or "allow" in s or "established" in s for s in network_verb_matches):
            act_name, act_id = "Open", 1
        else:
            act_name, act_id = "Traffic", 6

        return {
            "category_name": "Network Activity",
            "category_uid": 4,
            "class_name": "Network Activity",
            "class_uid": 4001,
            "activity_name": act_name,
            "activity_id": act_id,
            "semantic_confidence": 0.90,
            "classification_reason": "network_connection_traffic_evidence",
            "classification_status": "classified",
            "classification_evidence": evidence,
            "status": st,
            "status_id": st_id,
            "severity": mapped.get("severity"),
            "severity_id": mapped.get("severity_id"),
        }

    # -----------------------------------------------------------------------
    # PRIORITY 8: Insufficient Semantic Evidence (Strict Fallback)
    # Covers ambiguous actions, sensor readings, telemetry, isolated IPs/users.
    # NEVER DEFAULT TO SYSTEM ACTIVITY!
    # -----------------------------------------------------------------------
    return {
        "category_name": None,
        "category_uid": None,
        "class_name": None,
        "class_uid": None,
        "activity_name": mapped.get("activity_name") or None,
        "activity_id": None,
        "semantic_confidence": 0.0,
        "classification_reason": "insufficient_semantic_evidence",
        "classification_status": "review" if token_list else "unknown",
        "classification_evidence": weak_signals,
        "status": mapped.get("status"),
        "status_id": mapped.get("status_id"),
        "severity": mapped.get("severity"),
        "severity_id": mapped.get("severity_id"),
    }
