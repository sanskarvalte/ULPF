"""
Android logcat parser for ULPF.
Parses threadtime log format and extracts balanced-brace structured attributes into OCSF taxonomy.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple

from app.models.event_schema import UnifiedEvent
from app.normalization.field_mapping import COMMON_FIELD_MAP, coerce_int
from app.parsers.base import BaseParser

# Regex matching standard Android threadtime format: MM-DD HH:MM:SS.mmm  PID  TID Level Component: Message
_ANDROID_LOGCAT_RE = re.compile(
    r"^(\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d{3})\s+(\d+)\s+(\d+)\s+([VDIWEF])\s+([^:]+):\s*(.*)$"
)

# Deterministic Android level to OCSF Severity mapping
_SEVERITY_MAP: Dict[str, Tuple[str, int]] = {
    "V": ("Informational", 1),
    "D": ("Informational", 1),
    "I": ("Informational", 1),
    "W": ("Medium", 3),
    "E": ("High", 4),
    "F": ("Critical", 5),
}

# Android Component / Tag to OCSF Taxonomy Mapping
_TAG_TAXONOMY: Dict[str, Dict[str, Any]] = {
    "WindowManager": {
        "category_name": "Application Activity", "category_uid": 6,
        "class_name": "Application Lifecycle", "class_uid": 6001,
        "activity_name": "Display", "activity_id": 1,
    },
    "SurfaceFlinger": {
        "category_name": "Application Activity", "category_uid": 6,
        "class_name": "Application Lifecycle", "class_uid": 6001,
        "activity_name": "Render", "activity_id": 2,
    },
    "PhoneStatusBar": {
        "category_name": "Application Activity", "category_uid": 6,
        "class_name": "Application Lifecycle", "class_uid": 6001,
        "activity_name": "UI Status", "activity_id": 3,
    },
    "DisplayPowerController": {
        "category_name": "System Activity", "category_uid": 1,
        "class_name": "Operating System", "class_uid": 1001,
        "activity_name": "Display Power", "activity_id": 4,
    },
    "DisplayManagerService": {
        "category_name": "System Activity", "category_uid": 1,
        "class_name": "Operating System", "class_uid": 1001,
        "activity_name": "Display Configuration", "activity_id": 5,
    },
    "StackScrollAlgorithm": {
        "category_name": "Application Activity", "category_uid": 6,
        "class_name": "Application Lifecycle", "class_uid": 6001,
        "activity_name": "Layout", "activity_id": 6,
    },
    "PanelView": {
        "category_name": "Application Activity", "category_uid": 6,
        "class_name": "Application Lifecycle", "class_uid": 6001,
        "activity_name": "View", "activity_id": 7,
    },
    "TextView": {
        "category_name": "Application Activity", "category_uid": 6,
        "class_name": "Application Lifecycle", "class_uid": 6001,
        "activity_name": "Text Render", "activity_id": 8,
    },
    "ActivityManager": {
        "category_name": "Application Activity", "category_uid": 6,
        "class_name": "Application Lifecycle", "class_uid": 6001,
        "activity_name": "Process Management", "activity_id": 9,
    },
    "PackageManager": {
        "category_name": "Application Activity", "category_uid": 6,
        "class_name": "Application Lifecycle", "class_uid": 6001,
        "activity_name": "Package Install", "activity_id": 10,
    },
    "PowerManagerService": {
        "category_name": "System Activity", "category_uid": 1,
        "class_name": "Operating System", "class_uid": 1001,
        "activity_name": "Power State", "activity_id": 11,
    },
    "DeviceIdleController": {
        "category_name": "System Activity", "category_uid": 1,
        "class_name": "Operating System", "class_uid": 1001,
        "activity_name": "Power State", "activity_id": 11,
    },
    "AlarmManager": {
        "category_name": "System Activity", "category_uid": 1,
        "class_name": "Scheduled Job", "class_uid": 1003,
        "activity_name": "Alarm Trigger", "activity_id": 12,
    },
    "AudioManager": {
        "category_name": "System Activity", "category_uid": 1,
        "class_name": "Device Configuration", "class_uid": 1004,
        "activity_name": "Audio", "activity_id": 13,
    },
    "PhoneInterfaceManager": {
        "category_name": "Network Activity", "category_uid": 4,
        "class_name": "Network Activity", "class_uid": 4001,
        "activity_name": "Telephony", "activity_id": 14,
    },
    "TelephonyManager": {
        "category_name": "Network Activity", "category_uid": 4,
        "class_name": "Network Activity", "class_uid": 4001,
        "activity_name": "Telephony Status", "activity_id": 15,
    },
    "ConnectivityService": {
        "category_name": "Network Activity", "category_uid": 4,
        "class_name": "Network Activity", "class_uid": 4001,
        "activity_name": "Connection", "activity_id": 16,
    },
    "WifiService": {
        "category_name": "Network Activity", "category_uid": 4,
        "class_name": "Network Activity", "class_uid": 4001,
        "activity_name": "Wireless", "activity_id": 17,
    },
    "WifiController": {
        "category_name": "Network Activity", "category_uid": 4,
        "class_name": "Network Activity", "class_uid": 4001,
        "activity_name": "Wireless Configuration", "activity_id": 22,
    },
    "KeyguardUpdateMonitor": {
        "category_name": "Identity & Access Management", "category_uid": 3,
        "class_name": "Authentication", "class_uid": 3002,
        "activity_name": "Lockscreen State", "activity_id": 18,
    },
    "FingerprintService": {
        "category_name": "Identity & Access Management", "category_uid": 3,
        "class_name": "Authentication", "class_uid": 3002,
        "activity_name": "Biometric Auth", "activity_id": 19,
    },
    "NotificationManager": {
        "category_name": "Application Activity", "category_uid": 6,
        "class_name": "Notification", "class_uid": 6002,
        "activity_name": "Notify", "activity_id": 20,
    },
    "MediaPlayer": {
        "category_name": "Application Activity", "category_uid": 6,
        "class_name": "Application Lifecycle", "class_uid": 6001,
        "activity_name": "Media Playback", "activity_id": 21,
    },
}

_DEFAULT_TAXONOMY = {
    "category_name": "Application Activity", "category_uid": 6,
    "class_name": "Application Lifecycle", "class_uid": 6001,
    "activity_name": "Execution", "activity_id": 0,
}


def _extract_balanced_kv(msg: str) -> Dict[str, str]:
    """
    Extract structured key-value pairs from Android log message body,
    properly tracking balanced braces {...}, brackets [...], and quotes without truncating.
    Stops consuming when depth returns to 0 or an unmatched closing delimiter is encountered.
    """
    kv: Dict[str, str] = {}
    i = 0
    n = len(msg)
    key_regex = re.compile(r"(?:^|[\s,;])([a-zA-Z_][a-zA-Z0-9_.-]*)\s*(=|:)\s*")

    while i < n:
        m = key_regex.search(msg[i:])
        if not m:
            break

        key = m.group(1)
        val_start = i + m.end()
        j = val_start
        if j >= n:
            break

        if msg[j] in ('"', "'"):
            quote = msg[j]
            j += 1
            while j < n and msg[j] != quote:
                if msg[j] == "\\" and j + 1 < n:
                    j += 2
                else:
                    j += 1
            if j < n and msg[j] == quote:
                j += 1
            val = msg[val_start + 1 : j - 1] if j <= n else msg[val_start + 1 :]
        else:
            depth_brace = 0
            depth_bracket = 0
            depth_paren = 0
            has_structured = False
            while j < n:
                ch = msg[j]
                if ch == "{":
                    depth_brace += 1
                    has_structured = True
                elif ch == "}":
                    if depth_brace > 0:
                        depth_brace -= 1
                    else:
                        break
                elif ch == "[":
                    depth_bracket += 1
                    has_structured = True
                elif ch == "]":
                    if depth_bracket > 0:
                        depth_bracket -= 1
                    else:
                        break
                elif ch == "(":
                    depth_paren += 1
                    has_structured = True
                elif ch == ")":
                    if depth_paren > 0:
                        depth_paren -= 1
                    else:
                        break
                elif depth_brace == 0 and depth_bracket == 0 and depth_paren == 0:
                    if ch in (",", ";"):
                        break
                    if ch.isspace():
                        rem = msg[j:].lstrip()
                        if key_regex.match(rem):
                            break
                        if has_structured and not rem.startswith(("[", "{", "(")):
                            break
                j += 1
            val = msg[val_start:j].strip()

        val = val.rstrip(",;").strip()
        if key and val and len(key) >= 2 and not key.isdigit():
            if key.lower() not in ("http", "https"):
                kv[key] = val

        i = max(j, val_start + 1)

    return kv


def parse_android_log(raw: str, default_year: Optional[int] = None) -> UnifiedEvent:
    """
    Parse a single Android logcat threadtime log entry into standard OCSF schema.
    """
    m = _ANDROID_LOGCAT_RE.match(raw.strip())
    if not m:
        # Fallback to generic parser if logcat format doesn't match
        from app.parsers.generic_parser import parse_generic_log
        return parse_generic_log(raw)

    ts_raw, pid_str, tid_str, level_code, tag_raw, message_text = m.groups()
    tag = tag_raw.strip()

    # 1. Timestamp parsing (MM-DD HH:MM:SS.mmm -> ISO 8601 UTC)
    year = default_year or datetime.now(timezone.utc).year
    month, day = ts_raw[:5].split("-")
    time_part = ts_raw[6:]
    dt_str = f"{year}-{month}-{day} {time_part}"
    try:
        dt = datetime.strptime(dt_str, "%Y-%m-%d %H:%M:%S.%f").replace(tzinfo=timezone.utc)
    except ValueError:
        dt = datetime.now(timezone.utc)

    # 2. Deterministic Severity
    severity, severity_id = _SEVERITY_MAP.get(level_code.upper(), ("Informational", 1))

    # 3. Tag-driven Taxonomy
    tax = _TAG_TAXONOMY.get(tag, _DEFAULT_TAXONOMY)
    category_name = tax["category_name"]
    category_uid = tax["category_uid"]
    class_name = tax["class_name"]
    class_uid = tax["class_uid"]
    activity_name = tax["activity_name"]
    activity_id = tax["activity_id"]
    type_name = f"{class_name}: {activity_name}"
    type_uid = class_uid * 100 + activity_id

    # 4. Extract structured key-value pairs with balanced braces
    kv_extracted = _extract_balanced_kv(message_text)

    # 5. Schema mapping & unmapped preservation
    mapped: Dict[str, Any] = {
        "timestamp": dt,
        "severity": severity,
        "severity_id": severity_id,
        "category_name": category_name,
        "category_uid": category_uid,
        "class_name": class_name,
        "class_uid": class_uid,
        "activity_name": activity_name,
        "activity_id": activity_id,
        "type_name": type_name,
        "type_uid": type_uid,
        "service_name": tag,
        "vendor": "Google",
        "product": "Android",
        "message": message_text,
        "log_format": "android",
        "raw_event": raw,
    }

    unmapped: Dict[str, Any] = {
        "pid": pid_str,
        "tid": tid_str,
        "log_level": level_code,
    }

    # Extract user / user_uid if available
    user_val = None
    user_uid_val = None
    user_domain_val = None

    for k, v in kv_extracted.items():
        k_lower = k.lower()
        if k_lower == "user":
            user_val = v
        elif k_lower in ("userid", "user_id"):
            user_uid_val = v
            if not user_val:
                user_val = f"user_{v}"
        elif k_lower == "uid":
            user_uid_val = v
            if not user_val:
                user_val = f"app_{v}" if v.isdigit() and int(v) >= 10000 else v
        elif k_lower == "caller" and v.isdigit():
            user_uid_val = v
            if not user_val:
                user_val = f"app_{v}"
        else:
            # Map standard common keys or retain in unmapped
            unified_k = COMMON_FIELD_MAP.get(k_lower)
            if unified_k and unified_k not in mapped and unified_k not in ("severity", "timestamp"):
                mapped[unified_k] = v
            else:
                if k in unmapped:
                    unmapped[f"target_{k}"] = v
                else:
                    unmapped[k] = v

    # Also detect u0 / u1 domain in package names if present
    u_match = re.search(r"\b(u\d+)\s+([a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+)", message_text)
    if u_match:
        user_domain_val = u_match.group(1)
        if not user_val:
            user_val = u_match.group(2)

    if user_val:
        mapped["user"] = user_val
    if user_uid_val:
        mapped["user_uid"] = str(user_uid_val)
    if user_domain_val:
        mapped["user_domain"] = user_domain_val

    if unmapped:
        mapped["unmapped"] = unmapped

    return UnifiedEvent(**mapped)


class AndroidParser(BaseParser):
    format_name = "android"

    def parse(self, raw: str) -> UnifiedEvent:
        return parse_android_log(raw)
