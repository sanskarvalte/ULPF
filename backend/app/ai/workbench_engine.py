"""
Local Offline AI Log Intelligence Workbench Engine for ULPF.
Performs deterministic and heuristic structural analysis on raw unknown log lines:
- Field Discovery with type inference (DATETIME, IPV4, IPV6, PORT, CATEGORICAL, etc.)
- Inferred Grok & Regex template generation
- Parser configuration suggestion (YAML / JSON)
- Interactive parser validation against sample logs
- Lossless OCSF normalization integration
"""

from __future__ import annotations

import re
import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from app.models.event_schema import UnifiedEvent
from app.normalization.engine import enrich_classification
from app.normalization.field_mapping import COMMON_FIELD_MAP, coerce_int, coerce_bool, parse_timestamp


# Supported Inferred Types
TYPE_DATETIME = "DATETIME"
TYPE_IPV4 = "IPV4"
TYPE_IPV6 = "IPV6"
TYPE_PORT = "PORT"
TYPE_CATEGORICAL = "CATEGORICAL"
TYPE_INTEGER = "INTEGER"
TYPE_FLOAT = "FLOAT"
TYPE_BOOLEAN = "BOOLEAN"
TYPE_URL = "URL"
TYPE_HASH = "HASH"
TYPE_STRING = "STRING"
TYPE_UNKNOWN = "UNKNOWN"

IPV4_REGEX = re.compile(r"\b(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}\b")
IPV6_REGEX = re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|\b(?:[0-9a-fA-F]{1,4}:)*::(?:[0-9a-fA-F]{1,4}:)*[0-9a-fA-F]{1,4}\b")
URL_REGEX = re.compile(r"https?://[^\s<>\"']+|ftp://[^\s<>\"']+", re.IGNORECASE)
HASH_REGEX = re.compile(r"\b[0-9a-fA-F]{32}\b|\b[0-9a-fA-F]{40}\b|\b[0-9a-fA-F]{64}\b")
SYSLOG_TS_REGEX = re.compile(r"\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\b")
ISO_TS_REGEX = re.compile(r"\b\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b")

KNOWN_CATEGORIES = {
    "RT_FLOW_SESSION_CREATE", "RT_FLOW_SESSION_CLOSE", "RT_IDS_ATTACK_DETECTED",
    "LOGIN_SUCCESS", "LOGIN_FAILED", "USER_AUTH", "SESSION_OPEN", "SESSION_CLOSE",
    "DROP", "ALLOW", "DENY", "BLOCK", "ACCEPT", "REJECT", "FORWARD", "FILTER",
    "ESTABLISHED", "TIME_WAIT", "CLOSE_WAIT", "SYN_SENT", "RESET", "ALERT", "CRITICAL"
}


def infer_field_type(name: str, value: Any) -> Tuple[str, float]:
    """
    Infer semantic data type and confidence for a discovered field name and value.
    Returns: (type_name, confidence_float)
    """
    if value is None:
        return TYPE_UNKNOWN, 0.50

    val_str = str(value).strip()
    name_lower = name.lower()

    # 1. IP Addresses
    if IPV4_REGEX.fullmatch(val_str) or ("ip" in name_lower and IPV4_REGEX.search(val_str)):
        return TYPE_IPV4, 0.99
    if IPV6_REGEX.fullmatch(val_str):
        return TYPE_IPV6, 0.98

    # 2. Port Numbers
    if ("port" in name_lower or "sport" in name_lower or "dport" in name_lower) and val_str.isdigit():
        p_val = int(val_str)
        if 1 <= p_val <= 65535:
            return TYPE_PORT, 0.99

    # 3. Timestamps & Dates
    if ISO_TS_REGEX.search(val_str) or SYSLOG_TS_REGEX.search(val_str) or parse_timestamp(val_str) is not None:
        return TYPE_DATETIME, 0.99
    if "time" in name_lower or "timestamp" in name_lower or name_lower in ("ts", "date"):
        if parse_timestamp(val_str) is not None:
            return TYPE_DATETIME, 0.99

    # 4. URLs
    if URL_REGEX.fullmatch(val_str):
        return TYPE_URL, 0.97

    # 5. Hashes
    if HASH_REGEX.fullmatch(val_str) or "hash" in name_lower or "md5" in name_lower or "sha" in name_lower:
        return TYPE_HASH, 0.96

    # 6. Booleans
    if val_str.lower() in ("true", "false", "yes", "no", "enabled", "disabled"):
        return TYPE_BOOLEAN, 0.98

    # 7. Categorical enums / actions
    if val_str.upper() in KNOWN_CATEGORIES or name_lower in ("event_type", "action", "status", "category", "severity", "protocol", "module"):
        return TYPE_CATEGORICAL, 0.88

    # 8. Integers
    if re.fullmatch(r"^-?\d+$", val_str):
        return TYPE_INTEGER, 0.95

    # 9. Floats
    if re.fullmatch(r"^-?\d+\.\d+$", val_str):
        return TYPE_FLOAT, 0.95

    # 10. String default
    if name_lower in ("hostname", "host", "host_name", "src_host"):
        return TYPE_STRING, 0.98
    if name_lower in ("user", "username", "account", "src_user"):
        return TYPE_STRING, 0.97

    return TYPE_STRING, 0.90


def discover_fields_from_log(raw_text: str) -> List[Dict[str, Any]]:
    """
    Discover structured tokens, key-value pairs, syslog positional tokens,
    and network fields from raw unknown log text.
    """
    discovered: Dict[str, Dict[str, Any]] = {}

    first_line = ""
    for line in raw_text.splitlines():
        if line.strip() and not line.strip().startswith("#"):
            first_line = line.strip()
            break
    if not first_line:
        first_line = raw_text.strip()

    # 1. Syslog Priority prefix: <14>
    prio_match = re.match(r"^<(?P<syslog_pri>\d{1,3})>", first_line)
    if prio_match:
        prio_val = prio_match.group("syslog_pri")
        discovered["syslog_pri"] = {
            "name": "syslog_pri",
            "sample_value": prio_val,
            "type": TYPE_INTEGER,
            "confidence": 0.99,
        }

    # 2. Syslog Timestamp: Oct 27 08:14:22
    ts_match = re.search(r"\b(?P<ts>(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\b", first_line)
    if ts_match:
        discovered["timestamp"] = {
            "name": "timestamp",
            "sample_value": ts_match.group("ts"),
            "type": TYPE_DATETIME,
            "confidence": 0.99,
        }
    else:
        # ISO timestamp check
        iso_match = re.search(r"\b(?P<ts>\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\b", first_line)
        if iso_match:
            discovered["timestamp"] = {
                "name": "timestamp",
                "sample_value": iso_match.group("ts"),
                "type": TYPE_DATETIME,
                "confidence": 0.99,
            }

    # 3. Hostname after timestamp
    host_match = re.search(r"(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+(?P<host>[a-zA-Z0-9_\-\.]+)\b", first_line)
    if host_match:
        discovered["hostname"] = {
            "name": "hostname",
            "sample_value": host_match.group("host"),
            "type": TYPE_STRING,
            "confidence": 0.98,
        }

    # 4. Juniper / BSD Module and Event Type: RT_FLOW: RT_FLOW_SESSION_CREATE:
    mod_match = re.search(r"\b(?P<module>[A-Z0-9_]+):\s+(?P<event_type>[A-Z0-9_]+):", first_line)
    if mod_match:
        discovered["module"] = {
            "name": "module",
            "sample_value": mod_match.group("module"),
            "type": TYPE_CATEGORICAL,
            "confidence": 0.92,
        }
        discovered["event_type"] = {
            "name": "event_type",
            "sample_value": mod_match.group("event_type"),
            "type": TYPE_CATEGORICAL,
            "confidence": 0.88,
        }

    # 5. IP:Port or IP/Port pairs: 192.168.1.100/54321->10.0.0.5/443
    flow_match = re.search(r"(?P<src_ip>(?:\d{1,3}\.){3}\d{1,3})[/:(?P<src_port>\d{1,5})]?\s*(?:->|-&gt;)\s*(?P<dst_ip>(?:\d{1,3}\.){3}\d{1,3})[/:(?P<dst_port>\d{1,5})]?", first_line)
    if flow_match:
        discovered["src_ip"] = {
            "name": "src_ip",
            "sample_value": flow_match.group("src_ip"),
            "type": TYPE_IPV4,
            "confidence": 0.99,
        }
        discovered["dst_ip"] = {
            "name": "dst_ip",
            "sample_value": flow_match.group("dst_ip"),
            "type": TYPE_IPV4,
            "confidence": 0.99,
        }
        if "src_port" in flow_match.groupdict() and flow_match.group("src_port"):
            discovered["src_port"] = {
                "name": "src_port",
                "sample_value": flow_match.group("src_port"),
                "type": TYPE_PORT,
                "confidence": 0.98,
            }
        if "dst_port" in flow_match.groupdict() and flow_match.group("dst_port"):
            discovered["dst_port"] = {
                "name": "dst_port",
                "sample_value": flow_match.group("dst_port"),
                "type": TYPE_PORT,
                "confidence": 0.98,
            }
    else:
        # Standalone IPs
        ips = list(IPV4_REGEX.finditer(first_line))
        if len(ips) >= 1 and "src_ip" not in discovered:
            discovered["src_ip"] = {
                "name": "src_ip",
                "sample_value": ips[0].group(0),
                "type": TYPE_IPV4,
                "confidence": 0.99,
            }
        if len(ips) >= 2 and "dst_ip" not in discovered:
            discovered["dst_ip"] = {
                "name": "dst_ip",
                "sample_value": ips[1].group(0),
                "type": TYPE_IPV4,
                "confidence": 0.99,
            }

    # 6. Delimited key-value extraction: key=val or key:val or key="val"
    kv_pattern = re.compile(r"""\b(?P<k>[a-zA-Z_][a-zA-Z0-9_\-\.]*)[=:](?P<v>"[^"]*"|'[^']*'|[^\s,;]+)""")
    for m in kv_pattern.finditer(first_line):
        k = m.group("k").strip()
        v = m.group("v").strip().strip("\"'")
        if not v or v.lower() in ("null", "none", "n/a", "-"):
            continue
        if k in ("syslog_pri", "ts", "timestamp", "Oct", "Nov", "Dec", "RT_FLOW", "RT_IDS"):
            continue

        inferred_type, conf = infer_field_type(k, v)
        discovered[k] = {
            "name": k,
            "sample_value": v,
            "type": inferred_type,
            "confidence": conf,
        }

    # 7. Protocol and Interface tokens (e.g. junos-https, ge-0/0/1.0, tcp, udp)
    proto_match = re.search(r"\b(tcp|udp|icmp|junos-[a-z0-9\-]+)\b", first_line, re.IGNORECASE)
    if proto_match and "protocol" not in discovered:
        discovered["protocol"] = {
            "name": "protocol",
            "sample_value": proto_match.group(1),
            "type": TYPE_CATEGORICAL,
            "confidence": 0.94,
        }

    if_match = re.search(r"\b(ge-\d+/\d+/\d+(?:\.\d+)?|eth\d+|ens\d+|wlan\d+)\b", first_line)
    if if_match and "interface" not in discovered:
        discovered["interface"] = {
            "name": "interface",
            "sample_value": if_match.group(1),
            "type": TYPE_STRING,
            "confidence": 0.93,
        }

    # 8. User extraction
    user_match = re.search(r"\b(?:user|usr|username|account)[=:\s]+(?P<u>[a-zA-Z0-9_\-\.]+)\b", first_line, re.IGNORECASE)
    if user_match and "user" not in discovered:
        discovered["user"] = {
            "name": "user",
            "sample_value": user_match.group("u"),
            "type": TYPE_STRING,
            "confidence": 0.96,
        }

    # Return fields sorted with high priority/standard attributes first
    priority_keys = ["timestamp", "hostname", "module", "event_type", "src_ip", "src_port", "dst_ip", "dst_port", "protocol", "action", "user", "severity", "message"]
    ordered_fields = []
    for pk in priority_keys:
        if pk in discovered:
            ordered_fields.append(discovered.pop(pk))
    for rem in sorted(discovered.keys()):
        ordered_fields.append(discovered[rem])

    return ordered_fields


def infer_template_from_log(raw_text: str, fields: List[Dict[str, Any]]) -> Tuple[str, str, str]:
    """
    Generate Grok template and equivalent Python named-regex pattern.
    Returns: (format_name, grok_template, regex_pattern)
    """
    first_line = ""
    for line in raw_text.splitlines():
        if line.strip() and not line.strip().startswith("#"):
            first_line = line.strip()
            break
    if not first_line:
        first_line = raw_text.strip()

    # Check known vendor/format archetypes
    if "<" in first_line and "RT_FLOW" in first_line:
        format_name = "juniper-srx-syslog"
        grok = "<%{INT:syslog_pri}>%{SYSLOGTIMESTAMP:timestamp} %{HOSTNAME:hostname} %{WORD:module}: %{WORD:event_type}: %{GREEDYDATA:message_body}"
        regex = r"^<(?P<syslog_pri>\d+)>(?P<timestamp>[A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(?P<hostname>[a-zA-Z0-9_\-\.]+)\s+(?P<module>[a-zA-Z0-9_]+):\s+(?P<event_type>[a-zA-Z0-9_]+):\s*(?P<message_body>.*)$"
        return format_name, grok, regex

    if "<" in first_line and re.search(r"\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\b", first_line):
        format_name = "bsd-syslog-extended"
        grok = "<%{INT:syslog_pri}>%{SYSLOGTIMESTAMP:timestamp} %{HOSTNAME:hostname} %{PROG:program}(?:\\[%{POSINT:pid}\\])?: %{GREEDYDATA:message_body}"
        regex = r"^<(?P<syslog_pri>\d+)>(?P<timestamp>[A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(?P<hostname>[a-zA-Z0-9_\-\.]+)\s+(?P<program>[a-zA-Z0-9_\-\.]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<message_body>.*)$"
        return format_name, grok, regex

    if "at=" in first_line or ("method=" in first_line and "status=" in first_line):
        format_name = "logfmt-http-flow"
        grok = "%{GREEDYDATA:kv_pairs}"
        regex = r"""(?P<key>[a-zA-Z0-9_\-\.]+)=(?P<val>"[^"]*"|'[^']*'|\S+)"""
        return format_name, grok, regex

    if "|" in first_line:
        # Pipe-delimited custom log
        format_name = "custom-pipe-auth"
        parts = [p.strip() for p in first_line.split("|")]
        grok_parts = []
        regex_parts = []
        for i, p in enumerate(parts):
            field_name = fields[i]["name"] if i < len(fields) else f"col_{i+1}"
            grok_parts.append(f"%{{NOTSPACE:{field_name}}}")
            regex_parts.append(f"(?P<{field_name}>[^|]+)")
        grok = "|".join(grok_parts)
        regex = r"^" + r"\|".join(regex_parts) + r"$"
        return format_name, grok, regex

    # General heuristic fallback
    format_name = "custom-generic-parser"
    grok = "%{GREEDYDATA:message}"
    regex = r"^(?P<message>.*)$"
    return format_name, grok, regex


def generate_parser_configuration(
    format_name: str,
    grok_template: str,
    regex_pattern: str,
    fields: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """
    Generate clean, production-grade parser configuration matching ULPF architecture.
    """
    transforms = []
    field_mappings = {}

    has_timestamp = any(f["name"] == "timestamp" for f in fields)
    if has_timestamp:
        transforms.append({
            "type": "date",
            "field": "timestamp",
            "format": "MMM dd HH:mm:ss" if "SYSLOGTIMESTAMP" in grok_template else "ISO8601",
        })

    has_module = any(f["name"] == "module" for f in fields)
    if has_module:
        transforms.append({
            "type": "route",
            "condition": 'module == "RT_FLOW"',
            "target": "firewall_flows",
        })

    for f in fields:
        fn = f["name"]
        if fn in ("syslog_pri", "message_body"):
            continue
        ocsf_target = COMMON_FIELD_MAP.get(fn.lower()) or fn
        field_mappings[fn] = ocsf_target

    config_dict = {
        "parsers": [
            {
                "name": format_name,
                "type": "grok",
                "match": {
                    "message": grok_template,
                },
                "pattern_regex": regex_pattern,
                "field_mapping": field_mappings,
                "transforms": transforms,
            }
        ]
    }
    return config_dict


def calculate_overall_confidence(raw_text: str, fields: List[Dict[str, Any]], regex_pattern: str) -> float:
    """
    Calculate aggregate AI confidence score (0.0 to 1.0) based on:
    - Number of discovered typed attributes (IP, Port, Datetime)
    - Pattern matching ratio across sample lines
    """
    if not fields:
        return 0.50

    typed_count = sum(1 for f in fields if f["type"] not in (TYPE_STRING, TYPE_UNKNOWN))
    base = 0.80 if typed_count >= 3 else 0.70

    # Test regex against lines
    lines = [l.strip() for l in raw_text.splitlines() if l.strip() and not l.strip().startswith("#")]
    if lines:
        try:
            cre = re.compile(regex_pattern, re.IGNORECASE | re.DOTALL)
            matched = sum(1 for l in lines if cre.search(l) is not None)
            ratio = matched / len(lines)
            score = (base * 0.4) + (ratio * 0.6)
            return round(min(0.99, max(0.40, score)), 2)
        except Exception:
            return round(base, 2)
    return 0.92


def validate_proposed_parser(
    pattern_regex: str,
    raw_sample: str,
    field_mapping: Optional[Dict[str, Any]] = None,
    format_name: Optional[str] = "custom_test",
) -> Dict[str, Any]:
    """
    Validate proposed parser pattern and mappings against sample log text.
    Returns detailed PASS/FAIL report with records processed, match percentage,
    extracted fields, and sample parsed record.
    """
    field_mapping = field_mapping or {}
    lines = [l.strip() for l in raw_sample.splitlines() if l.strip() and not l.strip().startswith("#")]
    if not lines:
        return {
            "status": "FAIL",
            "is_valid": False,
            "total_records": 0,
            "matched_records": 0,
            "success_rate_percent": 0.0,
            "errors": ["Sample log contains no non-empty log lines."],
            "extracted_fields": [],
            "sample_record": None,
        }

    try:
        compiled_re = re.compile(pattern_regex, re.IGNORECASE | re.DOTALL)
    except Exception as e:
        return {
            "status": "FAIL",
            "is_valid": False,
            "total_records": len(lines),
            "matched_records": 0,
            "success_rate_percent": 0.0,
            "errors": [f"Invalid Regex Pattern: {e}"],
            "extracted_fields": [],
            "sample_record": None,
        }

    matched_count = 0
    extracted_fields_set = set()
    errors = []
    first_parsed_event = None

    for idx, line in enumerate(lines):
        match = compiled_re.search(line)
        if match:
            matched_count += 1
            gd = match.groupdict()
            for k, v in gd.items():
                if v is not None:
                    extracted_fields_set.add(k)

            if first_parsed_event is None:
                # Build mock UnifiedEvent
                ev_data: Dict[str, Any] = {
                    "raw_event": line,
                    "log_format": format_name,
                }
                for k, v in gd.items():
                    if v is None:
                        continue
                    ocsf_k = field_mapping.get(k) or COMMON_FIELD_MAP.get(k.lower()) or k
                    ev_data[ocsf_k] = v

                # Also scan for key=value tokens in message_body or line
                kv_re = re.compile(r"""\b(?P<k>[a-zA-Z_][a-zA-Z0-9_\-\.]*)[=:](?P<v>"[^"]*"|'[^']*'|[^\s,;]+)""")
                for m in kv_re.finditer(line):
                    k = m.group("k")
                    v = m.group("v").strip("\"'")
                    ocsf_k = field_mapping.get(k) or COMMON_FIELD_MAP.get(k.lower()) or k
                    if ocsf_k not in ev_data:
                        ev_data[ocsf_k] = v

                if "timestamp" in ev_data and isinstance(ev_data["timestamp"], str):
                    ev_data["timestamp"] = parse_timestamp(ev_data["timestamp"])
                for int_field in ("src_port", "dst_port", "severity_id", "status_id"):
                    if int_field in ev_data:
                        ev_data[int_field] = coerce_int(ev_data[int_field])

                enrich_classification(ev_data)
                try:
                    first_parsed_event = UnifiedEvent(**ev_data).model_dump(mode="json")
                except Exception as ex:
                    first_parsed_event = ev_data
        else:
            if len(errors) < 3:
                errors.append(f"Line {idx+1} failed to match pattern: '{line[:60]}...'")

    rate = round((matched_count / len(lines)) * 100.0, 1)
    is_pass = rate >= 80.0

    return {
        "status": "PASS" if is_pass else "FAIL",
        "is_valid": is_pass,
        "total_records": len(lines),
        "matched_records": matched_count,
        "success_rate_percent": rate,
        "errors": errors if not is_pass else [],
        "extracted_fields": sorted(list(extracted_fields_set)),
        "sample_record": first_parsed_event,
    }


def dump_yaml(data: Any, indent: int = 0) -> str:
    """Zero-dependency YAML serializer for parser configurations."""
    lines = []
    prefix = "  " * indent
    if isinstance(data, dict):
        for k, v in data.items():
            if isinstance(v, (dict, list)):
                lines.append(f"{prefix}{k}:")
                lines.append(dump_yaml(v, indent + 1))
            else:
                v_str = f'"{v}"' if isinstance(v, str) and (":" in v or "{" in v or "%" in v or " " in v) else str(v)
                lines.append(f"{prefix}{k}: {v_str}")
    elif isinstance(data, list):
        for item in data:
            if isinstance(item, dict):
                first = True
                for k, v in item.items():
                    if first:
                        if isinstance(v, (dict, list)):
                            lines.append(f"{prefix}- {k}:")
                            lines.append(dump_yaml(v, indent + 2))
                        else:
                            v_str = f'"{v}"' if isinstance(v, str) and (":" in v or "{" in v or "%" in v or " " in v) else str(v)
                            lines.append(f"{prefix}- {k}: {v_str}")
                        first = False
                    else:
                        sub_prefix = prefix + "  "
                        if isinstance(v, (dict, list)):
                            lines.append(f"{sub_prefix}{k}:")
                            lines.append(dump_yaml(v, indent + 2))
                        else:
                            v_str = f'"{v}"' if isinstance(v, str) and (":" in v or "{" in v or "%" in v or " " in v) else str(v)
                            lines.append(f"{sub_prefix}{k}: {v_str}")
            else:
                lines.append(f"{prefix}- {item}")
    return "\n".join(lines)


def analyze_unknown_log(raw_text: str, source: Optional[str] = None) -> Dict[str, Any]:
    """
    Full local offline AI analysis pipeline for an unknown log payload:
    Raw Text -> Field Discovery -> Template Inference -> Parser Configuration -> Live Validation
    """
    fields = discover_fields_from_log(raw_text)
    format_name, grok_template, regex_pattern = infer_template_from_log(raw_text, fields)
    parser_config = generate_parser_configuration(format_name, grok_template, regex_pattern, fields)
    confidence = calculate_overall_confidence(raw_text, fields, regex_pattern)

    field_mapping = parser_config["parsers"][0]["field_mapping"]
    val_result = validate_proposed_parser(
        pattern_regex=regex_pattern,
        raw_sample=raw_text,
        field_mapping=field_mapping,
        format_name=format_name,
    )

    yaml_str = dump_yaml(parser_config)

    return {
        "source": source or "unknown-log-stream",
        "raw_log": raw_text,
        "format_name": format_name,
        "detected_pattern": regex_pattern,
        "confidence": confidence,
        "confidence_percent": int(confidence * 100),
        "discovered_fields": fields,
        "fields_count": len(fields),
        "inferred_template": grok_template,
        "suggested_parser": parser_config,
        "suggested_parser_yaml": yaml_str,
        "validation_result": val_result,
    }
