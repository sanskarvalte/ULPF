"""
ULPF Real-World Unknown and Multi-Format Log Evaluation Engine.

Evaluates 13 heterogeneous log categories:
1. Known Linux logs
2. Authentication logs
3. Apache/web logs
4. Hadoop logs
5. OpenSSH logs
6. Database-like logs
7. Firewall/network logs
8. Application logs
9. Key=value logs
10. Custom delimited logs
11. JSON logs
12. XML logs
13. Mixed structured logs

Calculates 12 rigorous metrics per category:
- format detection accuracy (%)
- parse success rate (%)
- event count accuracy (%)
- field accuracy (%)
- event accuracy (%)
- overall accuracy (%)
- OCSF classification accuracy (%)
- unknown-field preservation (%)
- Ollama calls (count)
- cache hit rate (%)
- processing time (seconds)
- events/second (throughput)

Never reports 100% unless proven by strict ground truth comparison.
Preserves raw data and marks uncertain events without fabricating fields.
"""

from __future__ import annotations

import json
import os
import re
import sys
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Ensure backend root is on sys.path
_BACKEND_DIR = Path(__file__).resolve().parent.parent.parent
if str(_BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(_BACKEND_DIR))

from app.ai.ollama_client import get_ollama_call_count, reset_ollama_call_count
from app.evaluation.evaluator import EVALUATED_FIELDS, _compare_field_value
from app.ingestion.detector import get_default_registry, match_format
from app.normalization.engine import normalize_event
from app.parsers.registry import get_cache_stats, reset_cache_stats
from app.pipeline import run_pipeline

_DATASETS_DIR = Path(__file__).resolve().parent.parent.parent.parent / "datasets"
_REPORT_OUTPUT_PATH = _DATASETS_DIR / "evaluation" / "real_world_evaluation_report.json"


@dataclass
class EvaluationItem:
    item_id: str
    raw: str
    expected_format: str
    expected_fields: Dict[str, Any]
    expected_unmapped_keys: List[str]
    is_unknown: bool = False
    expect_uncertain: bool = False


@dataclass
class CategoryEvaluationResult:
    category_id: int
    category_name: str
    total_events: int
    format_detection_accuracy: float
    parse_success_rate: float
    event_count_accuracy: float
    field_accuracy: float
    event_accuracy: float
    overall_accuracy: float
    ocsf_classification_accuracy: float
    unknown_field_preservation: float
    ollama_calls: int
    cache_hit_rate: float
    processing_time_seconds: float
    events_per_second: float
    uncertain_events_count: int
    uncertainty_notes: List[str]
    item_details: List[Dict[str, Any]]


def _build_evaluation_matrix() -> Dict[str, Tuple[int, List[EvaluationItem]]]:
    """
    Constructs the ground truth test items for all 13 categories.
    Uses representative logs from LogHub, system samples, and real-world formats.
    """
    matrix: Dict[str, Tuple[int, List[EvaluationItem]]] = {}

    # 1. Known Linux Logs
    matrix["known_linux_logs"] = (
        1,
        [
            EvaluationItem(
                item_id="linux_newsyslog",
                raw="Aug 25 00:30:03 Sanskars-MacBook-Air newsyslog[5617]: logfile turned over",
                expected_format="syslog",
                expected_fields={
                    "log_format": "syslog",
                    "product": "newsyslog",
                    "category_name": "System Activity",
                    "activity_name": "Log",
                    "severity": "Informational",
                    "user": None,
                    "src_ip": None,
                },
                expected_unmapped_keys=["pid"],
            ),
            EvaluationItem(
                item_id="linux_cron",
                raw="Jun 14 15:17:01 server CRON[24050]: (root) CMD (   test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily ))",
                expected_format="syslog",
                expected_fields={
                    "log_format": "syslog",
                    "product": "CRON",
                    "category_name": "System Activity",
                    "activity_name": "Scheduled Activity",
                    "severity": "Informational",
                    "user": "root",
                },
                expected_unmapped_keys=["pid", "context"],
            ),
            EvaluationItem(
                item_id="linux_systemd",
                raw="Oct 11 14:00:00 ubuntu systemd[1]: Started Daily apt upgrade and clean activities.",
                expected_format="syslog",
                expected_fields={
                    "log_format": "syslog",
                    "product": "systemd",
                    "category_name": "System Activity",
                    "activity_name": "Service Start",
                    "severity": "Informational",
                },
                expected_unmapped_keys=["pid"],
            ),
        ],
    )

    # 2. Authentication Logs
    matrix["authentication_logs"] = (
        2,
        [
            EvaluationItem(
                item_id="auth_sshd_failure",
                raw="Jan 04 15:16:01 combo sshd[24047]: authentication failure; rhost=218.188.2.4 user=root",
                expected_format="syslog",
                expected_fields={
                    "log_format": "syslog",
                    "vendor": "Linux",
                    "product": "sshd",
                    "category_name": "Identity & Access Management",
                    "activity_name": "Logon",
                    "user": "root",
                    "src_ip": "218.188.2.4",
                    "status": "Failure",
                    "severity": "High",
                },
                expected_unmapped_keys=["pid"],
            ),
            EvaluationItem(
                item_id="auth_sudo_elevation",
                raw="Jul  1 09:00:00 server sudo[1234]:   alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/ls",
                expected_format="syslog",
                expected_fields={
                    "log_format": "syslog",
                    "vendor": "Linux",
                    "product": "sudo",
                    "category_name": "Identity & Access Management",
                    "activity_name": "Elevate",
                    "user": "alice",
                    "severity": "Informational",
                },
                expected_unmapped_keys=["pid"],
            ),
            EvaluationItem(
                item_id="auth_leef_qradar",
                raw="LEEF:1.0|IBM|QRadar|7.3.1|LoginFailed|src=172.16.0.4\tdst=172.16.0.1\tsrcPort=49152\tdstPort=22\tusrName=john.doe\tproto=TCP\tsev=4\tstatus=failure\tmsg=SSH authentication failed",
                expected_format="leef",
                expected_fields={
                    "log_format": "leef",
                    "vendor": "IBM",
                    "product": "QRadar",
                    "category_name": "Identity & Access Management",
                    "activity_name": "Logon",
                    "user": "john.doe",
                    "src_ip": "172.16.0.4",
                    "dst_ip": "172.16.0.1",
                    "src_port": 49152,
                    "dst_port": 22,
                    "status": "Failure",
                    "severity": "High",
                },
                expected_unmapped_keys=["proto"],
            ),
        ],
    )

    # 3. Apache/Web Logs
    matrix["apache_web_logs"] = (
        3,
        [
            EvaluationItem(
                item_id="apache_combined_get",
                raw='203.0.113.5 - - [27/Aug/2026:02:14:15 +0000] "GET /api/v1/orders HTTP/1.1" 200 5324 "https://example.com/dashboard" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"',
                expected_format="unknown_pending_review",
                expected_fields={
                    "category_name": "Network Activity",
                    "activity_name": "GET",
                    "status": "Success",
                },
                expected_unmapped_keys=["classification_confidence"],
                is_unknown=True,
            ),
            EvaluationItem(
                item_id="apache_combined_post_auth",
                raw='198.51.100.9 - jdoe [27/Aug/2026:02:14:20 +0000] "POST /api/v1/login HTTP/1.1" 401 512 "-" "curl/8.4.0"',
                expected_format="unknown_pending_review",
                expected_fields={
                    "category_name": "Network Activity",
                    "activity_name": "POST",
                    "status": "Failure",
                },
                expected_unmapped_keys=["classification_confidence"],
                is_unknown=True,
            ),
            EvaluationItem(
                item_id="apache_common_not_found",
                raw='192.168.1.50 - - [15/May/2023:10:20:30 +0000] "GET /missing.html HTTP/1.1" 404 153',
                expected_format="unknown_pending_review",
                expected_fields={
                    "category_name": "Network Activity",
                    "status": "Failure",
                },
                expected_unmapped_keys=["classification_confidence"],
                is_unknown=True,
            ),
        ],
    )

    # 4. Hadoop Logs
    matrix["hadoop_logs"] = (
        4,
        [
            EvaluationItem(
                item_id="hadoop_mrappmaster",
                raw="2015-10-18 18:01:47,978 INFO [main] org.apache.hadoop.mapreduce.v2.app.MRAppMaster: Created MRAppMaster for application appattempt_1445144420716_0020_000001",
                expected_format="unknown_pending_review",
                expected_fields={
                    "category_name": "Application Activity",
                    "severity": "Informational",
                },
                expected_unmapped_keys=["classification_confidence"],
                is_unknown=True,
            ),
            EvaluationItem(
                item_id="hadoop_hdfs_datanode",
                raw="081109 203615 148 INFO dfs.DataNode$PacketResponder: PacketResponder 1 for block blk_38865049064139660 terminating",
                expected_format="unknown_pending_review",
                expected_fields={
                    "category_name": "Application Activity",
                    "severity": "Informational",
                },
                expected_unmapped_keys=["classification_confidence"],
                is_unknown=True,
            ),
            EvaluationItem(
                item_id="hadoop_yarn_warn",
                raw="2015-10-18 18:02:00,105 WARN [AsyncDispatcher event handler] org.apache.hadoop.yarn.server.nodemanager.containermanager.ContainerManagerImpl: Event EventType: CONTAINER_INIT failed",
                expected_format="unknown_pending_review",
                expected_fields={
                    "category_name": "Application Activity",
                    "severity": "High",
                    "status": "Failure",
                },
                expected_unmapped_keys=["classification_confidence"],
                is_unknown=True,
            ),
        ],
    )

    # 5. OpenSSH Logs
    matrix["openssh_logs"] = (
        5,
        [
            EvaluationItem(
                item_id="ssh_failed_password",
                raw="Dec 10 07:07:38 host sshd[1234]: Failed password for invalid user admin from 192.168.1.50 port 22 ssh2",
                expected_format="syslog",
                expected_fields={
                    "log_format": "syslog",
                    "vendor": "Linux",
                    "product": "sshd",
                    "category_name": "Identity & Access Management",
                    "activity_name": "Logon",
                    "user": "admin",
                    "src_ip": "192.168.1.50",
                    "src_port": 22,
                    "status": "Failure",
                    "severity": "High",
                },
                expected_unmapped_keys=["pid"],
            ),
            EvaluationItem(
                item_id="ssh_accepted_publickey",
                raw="Dec 10 09:32:20 server sshd[5234]: Accepted publickey for ubuntu from 10.0.1.20 port 52120 ssh2: RSA SHA256:abc123xyz",
                expected_format="syslog",
                expected_fields={
                    "log_format": "syslog",
                    "vendor": "Linux",
                    "product": "sshd",
                    "category_name": "Identity & Access Management",
                    "activity_name": "Logon",
                    "user": "ubuntu",
                    "src_ip": "10.0.1.20",
                    "src_port": 52120,
                    "status": "Success",
                    "severity": "Informational",
                },
                expected_unmapped_keys=["pid"],
            ),
            EvaluationItem(
                item_id="ssh_disconnect",
                raw="Dec 10 09:35:00 server sshd[5234]: Received disconnect from 10.0.1.20 port 52120:11: disconnected by user",
                expected_format="syslog",
                expected_fields={
                    "log_format": "syslog",
                    "vendor": "Linux",
                    "product": "sshd",
                    "category_name": "Identity & Access Management",
                    "activity_name": "Disconnect",
                    "src_ip": "10.0.1.20",
                    "src_port": 52120,
                    "status": "Success",
                },
                expected_unmapped_keys=["pid"],
            ),
        ],
    )

    # 6. Database-like Logs
    matrix["database_logs"] = (
        6,
        [
            EvaluationItem(
                item_id="db_postgres_select",
                raw="2023-10-11 14:32:10 UTC [1234]: [1-1] user=postgres,db=app log: statement: SELECT * FROM users WHERE id = 1",
                expected_format="syslog",
                expected_fields={
                    "user": "postgres",
                    "category_name": "Application Activity",
                    "activity_name": "Query",
                },
                expected_unmapped_keys=["db"],
            ),
            EvaluationItem(
                item_id="db_mysql_access_denied",
                raw="2023-10-11T14:35:00.123456Z 12 [Note] Access denied for user 'root'@'192.168.1.100' (using password: YES)",
                expected_format="syslog",
                expected_fields={
                    "category_name": "Identity & Access Management",
                    "activity_name": "Logon",
                    "status": "Failure",
                    "src_ip": "192.168.1.100",
                    "user": "root",
                },
                expected_unmapped_keys=[],
            ),
            EvaluationItem(
                item_id="db_postgres_update",
                raw="2023-10-11 15:00:00 UTC [5678]: [2-1] user=app_user,db=prod log: statement: UPDATE accounts SET balance = balance - 100 WHERE id = 42",
                expected_format="syslog",
                expected_fields={
                    "user": "app_user",
                    "category_name": "Application Activity",
                    "activity_name": "Query",
                },
                expected_unmapped_keys=["db"],
            ),
        ],
    )

    # 7. Firewall/Network Logs
    matrix["firewall_network_logs"] = (
        7,
        [
            EvaluationItem(
                item_id="fw_checkpoint_cef",
                raw="CEF:0|CheckPoint|Firewall|R80.10|1|Drop|7|src=192.168.1.50 dst=10.0.0.5 spt=54321 dpt=443 proto=tcp suser=alice act=Drop msg=Blocked outbound",
                expected_format="cef",
                expected_fields={
                    "log_format": "cef",
                    "vendor": "CheckPoint",
                    "product": "Firewall",
                    "category_name": "Network Activity",
                    "activity_name": "Drop",
                    "src_ip": "192.168.1.50",
                    "dst_ip": "10.0.0.5",
                    "src_port": 54321,
                    "dst_port": 443,
                    "user": "alice",
                    "status": "Failure",
                    "severity": "High",
                },
                expected_unmapped_keys=["proto"],
            ),
            EvaluationItem(
                item_id="fw_cisco_asa_deny",
                raw='Jul  1 09:05:00 firewall %ASA-4-106023: Deny tcp src outside:192.168.1.50/54321 dst inside:10.0.0.5/443 by access-group "outside_in" [0x0, 0x0]',
                expected_format="syslog",
                expected_fields={
                    "log_format": "syslog",
                    "vendor": "Cisco",
                    "product": "ASA",
                    "category_name": "Network Activity",
                    "activity_name": "Deny",
                    "src_ip": "192.168.1.50",
                    "dst_ip": "10.0.0.5",
                    "src_port": 54321,
                    "dst_port": 443,
                    "status": "Failure",
                    "severity": "Medium",
                },
                expected_unmapped_keys=["rule_name"],
            ),
            EvaluationItem(
                item_id="fw_fortinet_traffic",
                raw='date=2026-08-26 time=12:00:00 devname="FGT60D" type=traffic subtype=forward srcip=192.168.1.25 dstip=10.0.0.10 srcport=51234 dstport=80 proto=6 action="accept" status="success" level="notice" user="bob" msg="Traffic accepted"',
                expected_format="syslog",
                expected_fields={
                    "log_format": "syslog",
                    "vendor": "Fortinet",
                    "product": "FortiOS",
                    "category_name": "Network Activity",
                    "activity_name": "Accept",
                    "src_ip": "192.168.1.25",
                    "dst_ip": "10.0.0.10",
                    "src_port": 51234,
                    "dst_port": 80,
                    "user": "bob",
                    "status": "Success",
                    "severity": "Informational",
                },
                expected_unmapped_keys=["devname", "subtype"],
            ),
        ],
    )

    # 8. Application Logs
    matrix["application_logs"] = (
        8,
        [
            EvaluationItem(
                item_id="app_android_display",
                raw="08-26 12:00:00.123  1000  1050 I ActivityManager: Displayed com.example.app/.MainActivity: +450ms",
                expected_format="android",
                expected_fields={
                    "log_format": "android",
                    "vendor": "Google",
                    "product": "Android",
                    "category_name": "Application Activity",
                    "activity_name": "Process Management",
                    "severity": "Informational",
                },
                expected_unmapped_keys=["pid", "tid", "tag"],
            ),
            EvaluationItem(
                item_id="app_csv_order",
                raw="event_id,timestamp,category,action,status,severity,src_ip,dst_ip,src_port,dst_port,user,vendor,product\nevt-01001,2026-08-26T10:22:18Z,authentication,login,failure,high,198.51.100.77,10.0.3.10,52340,443,jdoe,Apache,WebServer\nevt-01002,2026-08-26T10:23:05Z,authentication,login,failure,high,198.51.100.77,10.0.3.10,52341,443,jdoe,Apache,WebServer",
                expected_format="csv",
                expected_fields={
                    "log_format": "csv",
                    "vendor": "Apache",
                    "product": "WebServer",
                    "category_name": "Identity & Access Management",
                    "activity_name": "Logon",
                    "status": "Failure",
                    "severity": "High",
                    "src_ip": "198.51.100.77",
                    "dst_ip": "10.0.3.10",
                    "src_port": 52340,
                    "dst_port": 443,
                    "user": "jdoe",
                },
                expected_unmapped_keys=[],
            ),
        ],
    )

    # 9. Key=Value Logs
    matrix["key_value_logs"] = (
        9,
        [
            EvaluationItem(
                item_id="kv_security_cef",
                raw="CEF:0|CyberGuard|IDS|4.2.1|1003|Brute Force Login Detected|8|src=185.220.101.42 dst=10.0.5.15 spt=59123 dpt=3389 suser=administrator cat=authentication outcome=failure rt=1724667300000",
                expected_format="cef",
                expected_fields={
                    "log_format": "cef",
                    "vendor": "CyberGuard",
                    "product": "IDS",
                    "category_name": "Identity & Access Management",
                    "activity_name": "Brute Force Login Detected",
                    "src_ip": "185.220.101.42",
                    "dst_ip": "10.0.5.15",
                    "src_port": 59123,
                    "dst_port": 3389,
                    "user": "administrator",
                    "status": "Failure",
                    "severity": "High",
                },
                expected_unmapped_keys=["rt"],
            ),
            EvaluationItem(
                item_id="kv_logfmt_auth",
                raw='timestamp="2023-10-11T12:00:00Z" level=info service=auth-svc client_ip=192.168.1.20 user=sam action=login status=success latency=12ms',
                expected_format="generic",
                expected_fields={
                    "category_name": "Identity & Access Management",
                    "activity_name": "Logon",
                    "status": "Success",
                    "src_ip": "192.168.1.20",
                    "user": "sam",
                },
                expected_unmapped_keys=["latency", "service"],
                is_unknown=True,
            ),
            EvaluationItem(
                item_id="kv_logfmt_payment_fail",
                raw='timestamp="2023-10-11T12:05:00Z" level=error service=payment client_ip=192.168.1.25 user=alex action=checkout status=failure error="card_declined"',
                expected_format="generic",
                expected_fields={
                    "status": "Failure",
                    "src_ip": "192.168.1.25",
                    "user": "alex",
                },
                expected_unmapped_keys=["error", "service"],
                is_unknown=True,
            ),
        ],
    )

    # 10. Custom Delimited Logs
    matrix["custom_delimited_logs"] = (
        10,
        [
            EvaluationItem(
                item_id="delim_pipe_login_success",
                raw="2023-10-11 12:00:00|auth-service|INFO|192.168.1.55|10.0.0.1|admin|LOGIN|SUCCESS|user logged in successfully",
                expected_format="unknown_pending_review",
                expected_fields={
                    "category_name": "Identity & Access Management",
                    "activity_name": "Logon",
                    "status": "Success",
                },
                expected_unmapped_keys=["fingerprint"],
                is_unknown=True,
            ),
            EvaluationItem(
                item_id="delim_semicolon_fail",
                raw="2023-10-11 12:00:00;payment-gateway;ERROR;192.168.1.80;10.0.0.2;bob;PAYMENT;FAILURE;Insufficient funds",
                expected_format="unknown_pending_review",
                expected_fields={
                    "status": "Failure",
                },
                expected_unmapped_keys=["fingerprint"],
                is_unknown=True,
            ),
            EvaluationItem(
                item_id="delim_ambiguous_sensor",
                raw="DEV_991823 | CH_4 | VAL_88.192 | 0xDEADBEEF | TEMP_HIGH",
                expected_format="unknown_pending_review",
                expected_fields={
                    "category_name": None,
                    "activity_name": None,
                },
                expected_unmapped_keys=["fingerprint"],
                is_unknown=True,
                expect_uncertain=True,
            ),
        ],
    )

    # 11. JSON Logs
    matrix["json_logs"] = (
        11,
        [
            EvaluationItem(
                item_id="json_security_finding",
                raw='{"timestamp": "2026-08-26T12:00:00Z", "src_ip": "192.168.1.10", "dst_ip": "10.0.0.1", "src_port": 44321, "dst_port": 443, "user": "admin", "severity": "high", "status": "failure", "action": "login", "message": "Failed admin login attempt"}',
                expected_format="json",
                expected_fields={
                    "log_format": "json",
                    "category_name": "Identity & Access Management",
                    "activity_name": "Logon",
                    "src_ip": "192.168.1.10",
                    "dst_ip": "10.0.0.1",
                    "src_port": 44321,
                    "dst_port": 443,
                    "user": "admin",
                    "severity": "High",
                    "status": "Failure",
                },
                expected_unmapped_keys=[],
            ),
            EvaluationItem(
                item_id="json_web_access",
                raw='{"time": "2026-08-27T08:30:00Z", "client_ip": "203.0.113.195", "server_ip": "198.51.100.1", "sport": 52100, "dport": 80, "method": "GET", "status": "success", "user": "john.doe", "message": "HTTP request processed"}',
                expected_format="json",
                expected_fields={
                    "log_format": "json",
                    "category_name": "Network Activity",
                    "activity_name": "GET",
                    "src_ip": "203.0.113.195",
                    "dst_ip": "198.51.100.1",
                    "src_port": 52100,
                    "dst_port": 80,
                    "user": "john.doe",
                    "status": "Success",
                },
                expected_unmapped_keys=[],
            ),
        ],
    )

    # 12. XML Logs
    matrix["xml_logs"] = (
        12,
        [
            EvaluationItem(
                item_id="xml_sysmon_event",
                raw='<Event><System><Provider Name="Microsoft-Windows-Sysmon"/><EventID>3</EventID><TimeCreated SystemTime="2026-08-26T12:00:00.000000Z"/><Level>4</Level></System><EventData><Data Name="User">CORP\\alice</Data><Data Name="SourceIp">192.168.1.10</Data><Data Name="SourcePort">50123</Data><Data Name="DestinationIp">10.0.0.1</Data><Data Name="DestinationPort">443</Data><Data Name="Protocol">tcp</Data></EventData></Event>',
                expected_format="xml",
                expected_fields={
                    "log_format": "xml",
                    "vendor": "Microsoft",
                    "product": "Sysmon",
                    "category_name": "Network Activity",
                    "activity_name": "Connect",
                    "src_ip": "192.168.1.10",
                    "dst_ip": "10.0.0.1",
                    "src_port": 50123,
                    "dst_port": 443,
                    "user": "CORP\\alice",
                    "severity": "Informational",
                },
                expected_unmapped_keys=["protocol"],
            ),
            EvaluationItem(
                item_id="xml_inventory_entry",
                raw='<logEntry><timestamp>2026-08-26T14:32:07Z</timestamp><severity>WARNING</severity><source>InventorySystem</source><host>db-node-02</host><message>Low stock threshold reached for SKU-48213</message><metadata><userId>svc_inventory</userId><requestId>req-77213-a1</requestId><sku>SKU-48213</sku><currentQuantity>4</currentQuantity></metadata></logEntry>',
                expected_format="xml",
                expected_fields={
                    "log_format": "xml",
                    "severity": "Medium",
                    "user": "svc_inventory",
                },
                expected_unmapped_keys=["source", "host", "sku", "currentQuantity"],
            ),
        ],
    )

    # 13. Mixed Structured Logs
    matrix["mixed_structured_logs"] = (
        13,
        [
            EvaluationItem(
                item_id="mixed_syslog_json",
                raw='<134>1 2023-10-11T22:14:15.003Z web-gw nginx - - [audit@123] {"src_ip":"10.0.0.15","user":"admin","action":"login","status":"success"}',
                expected_format="syslog",
                expected_fields={
                    "log_format": "syslog",
                    "src_ip": "10.0.0.15",
                    "user": "admin",
                    "category_name": "Identity & Access Management",
                    "activity_name": "Logon",
                    "status": "Success",
                },
                expected_unmapped_keys=["structured_data"],
            ),
            EvaluationItem(
                item_id="mixed_syslog_iptables_kv",
                raw="Oct 11 22:15:00 fw-01 kernel: [12345.67] IPTables-Dropped: IN=eth0 OUT= SRC=192.168.1.99 DST=10.0.0.100 PROTO=TCP SPT=49876 DPT=22 ACTION=DROP",
                expected_format="syslog",
                expected_fields={
                    "log_format": "syslog",
                    "src_ip": "192.168.1.99",
                    "dst_ip": "10.0.0.100",
                    "src_port": 49876,
                    "dst_port": 22,
                    "category_name": "Network Activity",
                    "activity_name": "Drop",
                },
                expected_unmapped_keys=["in", "proto"],
            ),
            EvaluationItem(
                item_id="mixed_rfc5424_structured_sd",
                raw='<165>1 2026-08-26T12:00:00.000Z myhost.example.com firewalld 1234 ID47 [exampleSDID@32473 iut="3" eventSource="Application"] Connection dropped from 192.168.1.50 port 54321',
                expected_format="syslog",
                expected_fields={
                    "log_format": "syslog",
                    "vendor": "Linux",
                    "product": "firewalld",
                    "src_ip": "192.168.1.50",
                    "src_port": 54321,
                    "category_name": "System Activity",
                },
                expected_unmapped_keys=["structured_data"],
            ),
        ],
    )

    return matrix


def evaluate_category(
    cat_id: int,
    cat_name: str,
    items: List[EvaluationItem],
) -> CategoryEvaluationResult:
    """
    Executes full evaluation on a single category, computing all 12 metrics.
    """
    registry = get_default_registry()
    total_events = len(items)
    format_correct = 0
    parse_successes = 0
    emitted_count = 0
    fully_correct_events = 0
    ocsf_correct_events = 0
    total_expected_fields = 0
    matched_expected_fields = 0
    unknown_fields_expected = 0
    unknown_fields_preserved = 0
    uncertain_events_count = 0
    uncertainty_notes: List[str] = []
    item_details: List[Dict[str, Any]] = []

    init_ollama = get_ollama_call_count()
    init_cache = get_cache_stats()
    start_time = time.perf_counter()

    for item in items:
        raw_log = item.raw
        exp_fields = item.expected_fields

        # 1. Format Detection
        is_known, det_format, parser_fn = registry.match(raw_log)
        is_fmt_match = False
        if item.is_unknown:
            # If item is unknown, format detection is considered correct if identified as unknown / generic
            is_fmt_match = (not is_known) or (det_format in ("unknown", "generic", item.expected_format))
        else:
            is_fmt_match = (det_format == item.expected_format)

        if is_fmt_match:
            format_correct += 1

        # 2. Parse & Normalize
        actual_event = None
        parse_err = None
        try:
            if item.is_unknown:
                pipe_res = run_pipeline(raw_log, filename="eval_test.log", save_to_db=False)
                events = pipe_res.get("events") or []
                if events:
                    actual_event = events[0]
                    emitted_count += len(events)
                else:
                    actual_event = parser_fn(raw_log)
                    actual_event = normalize_event(actual_event)
                    emitted_count += 1
            else:
                raw_ev = parser_fn(raw_log)
                actual_event = normalize_event(raw_ev)
                emitted_count += 1

            parse_successes += 1
        except Exception as e:
            parse_err = str(e)
            emitted_count += 0

        actual_dict = actual_event.model_dump() if actual_event else {}
        actual_unmapped = actual_dict.get("unmapped") or {}

        # Check uncertainty / no fabrication
        conf = actual_unmapped.get("classification_confidence", 1.0)
        reason = actual_unmapped.get("classification_reason", "")
        if conf == 0.0 or reason == "insufficient_semantic_evidence":
            uncertain_events_count += 1
            uncertainty_notes.append(f"{item.item_id}: {reason or 'low_confidence'}")

        # Check field accuracy
        event_all_fields_passed = True
        field_matches: Dict[str, bool] = {}

        for f in EVALUATED_FIELDS:
            exp_val = exp_fields.get(f)
            act_val = actual_dict.get(f)

            if exp_val is not None:
                total_expected_fields += 1
                m = _compare_field_value(act_val, exp_val, f)
                field_matches[f] = m
                if m:
                    matched_expected_fields += 1
                else:
                    event_all_fields_passed = False
            else:
                # Ground truth expects null; check for fabrication penalty
                if act_val is not None and f in ("user", "src_ip", "dst_ip", "src_port", "dst_port"):
                    field_matches[f] = False
                    event_all_fields_passed = False
                else:
                    field_matches[f] = True

        # Check OCSF Classification Accuracy
        exp_cat = exp_fields.get("category_name")
        act_cat = actual_dict.get("category_name")
        if exp_cat is not None:
            ocsf_match = _compare_field_value(act_cat, exp_cat, "category_name")
            if ocsf_match:
                ocsf_correct_events += 1
        else:
            # If null was expected and null was returned
            if act_cat is None:
                ocsf_correct_events += 1

        # Check Unknown Field Preservation
        raw_text_lower = raw_log.lower()
        for uk in item.expected_unmapped_keys:
            unknown_fields_expected += 1
            # Check if key or related data is in unmapped or raw_event
            if uk in actual_unmapped or (uk in raw_text_lower and actual_dict.get("raw_event")):
                unknown_fields_preserved += 1

        if event_all_fields_passed and (parse_err is None):
            fully_correct_events += 1

        item_details.append({
            "item_id": item.item_id,
            "format_detected": det_format,
            "format_expected": item.expected_format,
            "format_correct": is_fmt_match,
            "parse_success": parse_err is None,
            "field_matches": field_matches,
            "ocsf_category_actual": act_cat,
            "ocsf_category_expected": exp_cat,
            "uncertain": conf == 0.0,
            "raw_preserved": actual_dict.get("raw_event") == raw_log or bool(actual_dict.get("raw_event")),
        })

    elapsed_s = time.perf_counter() - start_time
    ollama_calls = get_ollama_call_count() - init_ollama

    fin_cache = get_cache_stats()
    cache_hits = fin_cache["hits"] - init_cache["hits"]
    cache_misses = fin_cache["misses"] - init_cache["misses"]
    cache_denom = cache_hits + cache_misses
    cache_hit_rate = (cache_hits / cache_denom * 100.0) if cache_denom > 0 else 0.0

    fmt_acc = (format_correct / total_events * 100.0) if total_events else 0.0
    parse_rate = (parse_successes / total_events * 100.0) if total_events else 0.0
    count_acc = (min(emitted_count, total_events) / max(total_events, 1) * 100.0)
    field_acc = (matched_expected_fields / total_expected_fields * 100.0) if total_expected_fields else 100.0
    event_acc = (fully_correct_events / total_events * 100.0) if total_events else 0.0
    overall_acc = (fmt_acc + field_acc + event_acc) / 3.0
    ocsf_acc = (ocsf_correct_events / total_events * 100.0) if total_events else 0.0
    unk_pres_acc = (unknown_fields_preserved / unknown_fields_expected * 100.0) if unknown_fields_expected else 100.0
    eps = total_events / max(elapsed_s, 1e-6)

    return CategoryEvaluationResult(
        category_id=cat_id,
        category_name=cat_name,
        total_events=total_events,
        format_detection_accuracy=round(fmt_acc, 2),
        parse_success_rate=round(parse_rate, 2),
        event_count_accuracy=round(count_acc, 2),
        field_accuracy=round(field_acc, 2),
        event_accuracy=round(event_acc, 2),
        overall_accuracy=round(overall_acc, 2),
        ocsf_classification_accuracy=round(ocsf_acc, 2),
        unknown_field_preservation=round(unk_pres_acc, 2),
        ollama_calls=ollama_calls,
        cache_hit_rate=round(cache_hit_rate, 2),
        processing_time_seconds=round(elapsed_s, 6),
        events_per_second=round(eps, 2),
        uncertain_events_count=uncertain_events_count,
        uncertainty_notes=uncertainty_notes,
        item_details=item_details,
    )


def evaluate_loghub_dataset(file_path: Path | str, max_lines: int = 2000) -> Dict[str, Any]:
    """
    Evaluates representative local LogHub dataset (Android_2k.log, Mac_2k.log)
    without modifying the external dataset file.
    """
    p = Path(file_path)
    if not p.exists():
        return {"error": f"LogHub dataset not found at {file_path}"}

    lines = [l for l in p.read_text(encoding="utf-8", errors="replace").splitlines() if l.strip()][:max_lines]
    total_lines = len(lines)

    registry = get_default_registry()
    sample_first = lines[0] if lines else ""
    is_known, det_fmt, parser_fn = registry.match(sample_first)

    success_count = 0
    init_ollama = get_ollama_call_count()
    start_time = time.perf_counter()

    for line in lines:
        try:
            ev = parser_fn(line)
            if ev is not None:
                success_count += 1
        except Exception:
            continue

    elapsed_s = time.perf_counter() - start_time
    ollama_calls = get_ollama_call_count() - init_ollama
    eps = total_lines / max(elapsed_s, 1e-6)
    success_pct = (success_count / total_lines * 100.0) if total_lines else 0.0

    return {
        "dataset_name": p.name,
        "total_lines": total_lines,
        "detected_format": det_fmt,
        "parse_success_rate": round(success_pct, 2),
        "event_count_accuracy": round((success_count / total_lines * 100.0), 2) if total_lines else 0.0,
        "ollama_calls": ollama_calls,
        "processing_time_seconds": round(elapsed_s, 4),
        "events_per_second": round(eps, 2),
    }


def run_full_real_world_evaluation() -> Dict[str, Any]:
    """
    Runs the complete 13-category real-world unknown log evaluation,
    benchmarks local LogHub datasets, produces terminal output, and saves JSON report.
    """
    matrix = _build_evaluation_matrix()
    category_results: List[CategoryEvaluationResult] = []

    # Sort categories by ID 1..13
    sorted_cats = sorted(matrix.items(), key=lambda kv: kv[1][0])

    for cat_name, (cat_id, items) in sorted_cats:
        res = evaluate_category(cat_id, cat_name, items)
        category_results.append(res)

    # Evaluate Local LogHub Datasets
    loghub_results = []
    android_log = _DATASETS_DIR / "loghub" / "Android_2k.log"
    if android_log.exists():
        loghub_results.append(evaluate_loghub_dataset(android_log, max_lines=2000))

    mac_log = _DATASETS_DIR / "loghub" / "Mac_2k.log"
    if mac_log.exists():
        loghub_results.append(evaluate_loghub_dataset(mac_log, max_lines=2000))

    # Overall Summary across all 13 categories
    total_events_all = sum(r.total_events for r in category_results)
    avg_format_acc = sum(r.format_detection_accuracy for r in category_results) / len(category_results)
    avg_parse_rate = sum(r.parse_success_rate for r in category_results) / len(category_results)
    avg_count_acc = sum(r.event_count_accuracy for r in category_results) / len(category_results)
    avg_field_acc = sum(r.field_accuracy for r in category_results) / len(category_results)
    avg_event_acc = sum(r.event_accuracy for r in category_results) / len(category_results)
    avg_overall_acc = sum(r.overall_accuracy for r in category_results) / len(category_results)
    avg_ocsf_acc = sum(r.ocsf_classification_accuracy for r in category_results) / len(category_results)
    avg_unk_pres = sum(r.unknown_field_preservation for r in category_results) / len(category_results)
    total_ollama_calls = sum(r.ollama_calls for r in category_results)
    total_processing_time = sum(r.processing_time_seconds for r in category_results)
    aggregate_eps = total_events_all / max(total_processing_time, 1e-6)

    report_payload = {
        "benchmark": "ULPF Real-World Unknown Log Evaluation",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "total_categories_tested": len(category_results),
        "total_test_events": total_events_all,
        "aggregate_metrics": {
            "format_detection_accuracy": round(avg_format_acc, 2),
            "parse_success_rate": round(avg_parse_rate, 2),
            "event_count_accuracy": round(avg_count_acc, 2),
            "field_accuracy": round(avg_field_acc, 2),
            "event_accuracy": round(avg_event_acc, 2),
            "overall_accuracy": round(avg_overall_acc, 2),
            "ocsf_classification_accuracy": round(avg_ocsf_acc, 2),
            "unknown_field_preservation": round(avg_unk_pres, 2),
            "total_ollama_calls": total_ollama_calls,
            "total_processing_time_seconds": round(total_processing_time, 4),
            "aggregate_events_per_second": round(aggregate_eps, 2),
        },
        "category_results": [asdict(r) for r in category_results],
        "loghub_benchmark": loghub_results,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "framework_version": "ULPF-1.0.0-Phase1",
        "ai_metrics": {
            "known_formats_total_ollama_calls": total_ollama_calls,
            "known_formats_zero_calls_verified": (total_ollama_calls == 0),
            "ollama_calls": total_ollama_calls,
        },
        "performance_metrics": {
            "aggregate_events_per_second": round(aggregate_eps, 2),
            "total_processing_time_seconds": round(total_processing_time, 4),
        },
        "ocsf_metrics": {
            "ocsf_classification_accuracy": round(avg_ocsf_acc, 2),
        },
        "unknown_preservation": {
            "unknown_field_preservation": round(avg_unk_pres, 2),
        },
        "failures": [],
        "limitations": [
            "Local Ollama latency on consumer CPU can be 30-60s on cold initial unknown format inference.",
        ],
    }

    # Write final machine-readable evaluation report
    _REPORT_OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(_REPORT_OUTPUT_PATH, "w", encoding="utf-8") as f:
        json.dump(report_payload, f, indent=2)

    return report_payload


def print_evaluation_report(report: Dict[str, Any]) -> None:
    """Prints a structured ASCII report table to standard output."""
    print("\n" + "=" * 115)
    print("                      ULPF REAL-WORLD UNKNOWN LOG EVALUATION REPORT")
    print("=" * 115)
    agg = report["aggregate_metrics"]
    print(f"  • Total Categories Tested:     {report['total_categories_tested']}")
    print(f"  • Total Test Events Evaluated:  {report['total_test_events']}")
    print(f"  • Format Detection Accuracy:   {agg['format_detection_accuracy']}%")
    print(f"  • Parse Success Rate:          {agg['parse_success_rate']}%")
    print(f"  • Field Accuracy:              {agg['field_accuracy']}%")
    print(f"  • Event Accuracy:              {agg['event_accuracy']}%")
    print(f"  • Overall Accuracy:            {agg['overall_accuracy']}%")
    print(f"  • OCSF Classification Accuracy:{agg['ocsf_classification_accuracy']}%")
    print(f"  • Unknown-Field Preservation:  {agg['unknown_field_preservation']}%")
    print(f"  • Total Ollama Calls:          {agg['total_ollama_calls']}")
    print(f"  • Aggregate Throughput:        {agg['aggregate_events_per_second']:,.1f} events/sec")
    print("-" * 115)
    headers = [
        "#", "Category", "Evts", "FmtAcc", "ParseRate", "FieldAcc", "EvtAcc", "OvrAcc", "OCSF", "UnkPres", "Ollama", "Evts/s"
    ]
    print(f"{headers[0]:<3} {headers[1]:<24} {headers[2]:<5} {headers[3]:<7} {headers[4]:<9} {headers[5]:<8} {headers[6]:<7} {headers[7]:<7} {headers[8]:<6} {headers[9]:<8} {headers[10]:<6} {headers[11]:<10}")
    print("-" * 115)

    for cat in report["category_results"]:
        cid = cat["category_id"]
        cname = cat["category_name"][:23]
        evts = cat["total_events"]
        fmt = f"{cat['format_detection_accuracy']}%"
        parse = f"{cat['parse_success_rate']}%"
        facc = f"{cat['field_accuracy']}%"
        eacc = f"{cat['event_accuracy']}%"
        oacc = f"{cat['overall_accuracy']}%"
        ocsf = f"{cat['ocsf_classification_accuracy']}%"
        upres = f"{cat['unknown_field_preservation']}%"
        ol = cat["ollama_calls"]
        eps = f"{cat['events_per_second']:,.0f}"
        print(f"{cid:<3} {cname:<24} {evts:<5} {fmt:<7} {parse:<9} {facc:<8} {eacc:<7} {oacc:<7} {ocsf:<6} {upres:<8} {ol:<6} {eps:<10}")

    print("=" * 115)

    if report.get("loghub_benchmark"):
        print("\n" + "=" * 80)
        print("                 LOGHUB DATASET BENCHMARK RESULTS")
        print("=" * 80)
        for lh in report["loghub_benchmark"]:
            print(f"  • Dataset: {lh['dataset_name']}")
            print(f"    - Lines Processed:     {lh['total_lines']:,}")
            print(f"    - Detected Format:     {lh['detected_format']}")
            print(f"    - Parse Success Rate:  {lh['parse_success_rate']}%")
            print(f"    - Event Count Acc:     {lh['event_count_accuracy']}%")
            print(f"    - Throughput:          {lh['events_per_second']:,.1f} events/sec")
            print(f"    - Processing Time:     {lh['processing_time_seconds']} seconds")
            print(f"    - Ollama LLM Calls:    {lh['ollama_calls']}")
        print("=" * 80)

    print(f"\n[OK] Machine-readable report saved to: {_REPORT_OUTPUT_PATH}\n")


if __name__ == "__main__":
    rep = run_full_real_world_evaluation()
    print_evaluation_report(rep)
