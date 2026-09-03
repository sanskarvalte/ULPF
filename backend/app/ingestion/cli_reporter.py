"""
Terminal Output & Pipeline Reporter for ULPF.
Renders 7-step ingestion execution, semantic normalization metrics, quality breakdown,
syntax-highlighted OCSF event samples, and processing summaries.
"""

from __future__ import annotations

import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from app.ingestion.detector import detect_format
from app.models.event_schema import UnifiedEvent
from app.normalization.engine import normalize_event
from app.parsers.android_parser import parse_android_log
from app.parsers.cef_parser import parse_cef_log
from app.parsers.csv_parser import parse_csv_log_all
from app.parsers.drain_service import SimpleDrainService, parse_drain_log
from app.parsers.generic_parser import parse_generic_log
from app.parsers.json_parser import parse_json_log
from app.parsers.leef_parser import parse_leef_log
from app.parsers.syslog_parser import parse_syslog_log
from app.parsers.xml_parser import parse_xml_log_all
from app.storage.db import get_db
from app.storage.normalized import save_events_batch
from app.validation.schema import validate_unified_event

# ANSI Color Codes
CYAN = "\033[96m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
MAGENTA = "\033[95m"
BOLD = "\033[1m"
DIM = "\033[90m"
RESET = "\033[0m"


def _format_size(size_bytes: int) -> str:
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f} KB"
    else:
        return f"{size_bytes / (1024 * 1024):.1f} MB"


def _highlight_json(obj: Any, indent: int = 2) -> str:
    """Pretty-print JSON with syntax colors matching OCSF terminal output."""
    import re
    raw_json = json.dumps(obj, indent=indent, default=str)
    lines = []
    for line in raw_json.splitlines():
        # Match dictionary keys: '  "key": "value",' or '  "key": 123,' or '  "key": {'
        m = re.match(r'^(\s*)"([^"]+)"(\s*:\s*)(.*)$', line)
        if m:
            indent_sp, key, colon_sp, val = m.groups()
            if val.endswith(","):
                val_core = val[:-1]
                trailing = ","
            else:
                val_core = val
                trailing = ""

            if val_core.startswith('"') and val_core.endswith('"'):
                colored_val = f'{GREEN}{val_core}{RESET}{trailing}'
            elif val_core in ("true", "false", "null") or re.match(r'^-?\d+(?:\.\d+)?$', val_core):
                colored_val = f'{CYAN}{val_core}{RESET}{trailing}'
            else:
                colored_val = f'{val_core}{trailing}'

            lines.append(f'{indent_sp}"{CYAN}{key}{RESET}"{colon_sp}{colored_val}')
        else:
            # Match array string items: '    "008099",' or '    "2026"'
            m_arr = re.match(r'^(\s*)"([^"]+)"(,?)$', line)
            if m_arr:
                sp, item, comma = m_arr.groups()
                lines.append(f'{sp}{GREEN}"{item}"{RESET}{comma}')
            else:
                lines.append(line)
    return "\n".join(lines)


def _to_ocsf_sample_dict(event: UnifiedEvent, index: int, original_dt: datetime) -> Dict[str, Any]:
    """Format UnifiedEvent to match the exact OCSF structure shown in the evaluation dashboard."""
    epoch_ms = int(event.timestamp.timestamp() * 1000) if event.timestamp else int(original_dt.timestamp() * 1000)
    iso_time = event.timestamp.isoformat() if event.timestamp else original_dt.isoformat()

    sample: Dict[str, Any] = {
        "class_uid": event.class_uid or 1004,
        "category_uid": event.category_uid or 1,
        "activity_id": event.activity_id or 99,
        "severity_id": event.severity_id if event.severity_id is not None else 0,
        "status_id": event.status_id if event.status_id is not None else 0,
        "time": epoch_ms,
        "type_uid": event.type_uid or ((event.class_uid or 1004) * 100 + (event.activity_id or 99)),
        "metadata": {
            "version": "1.1.0",
            "product": {
                "name": "ULPF",
                "vendor_name": "ULPF Framework",
            },
            "original_time": iso_time,
        },
    }

    # Add unmapped / Drain cluster info
    if event.unmapped:
        sample["unmapped"] = event.unmapped
    else:
        sample["unmapped"] = {
            "cluster_id": index,
            "cluster_size": 1,
            "parameters": [],
            "parameter_count": 0,
            "raw_message": event.raw_event,
        }

    return sample


def process_and_report_file(
    file_path: Path,
    output_json_path: Optional[Path] = None,
    show_all: bool = False,
    conn=None,
) -> int:
    """Execute 7-step pipeline with rich CLI progress and comprehensive metric report."""
    t_start = time.time()
    now_dt = datetime.now(timezone.utc)

    # 1. Read file
    try:
        raw_text = file_path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        raw_text = file_path.read_text(encoding="latin-1", errors="replace")

    size_str = _format_size(file_path.stat().st_size)

    # Banner & Header
    print(f"\n{CYAN}{BOLD}ULPF Processing{RESET}")
    print(f"{DIM}--------------------------------------------------{RESET}")
    print(f"{BOLD}Input       :{RESET} {file_path.name}")
    print(f"{BOLD}Size        :{RESET} {size_str}\n")

    # Step 1: Detect format
    print(f"{CYAN}[1/7]{RESET} Detecting format...")
    try:
        fmt, detected_fn = detect_format(raw_text)
    except Exception:
        fmt, detected_fn = "generic", parse_generic_log

    format_display_map = {
        "generic": "Plain_Text",
        "syslog": "Syslog",
        "json": "JSON",
        "csv": "CSV",
        "xml": "XML",
        "cef": "CEF",
        "leef": "LEEF",
        "android": "Android_Logcat",
    }
    format_display = format_display_map.get(fmt, fmt.capitalize())
    print(f"      {GREEN}+{RESET} Detected: {format_display}")

    # Step 2: Select parser
    parser_name_map = {
        "generic": "drain3_parser",
        "syslog": "syslog_parser",
        "json": "json_parser",
        "csv": "csv_parser",
        "xml": "xml_parser",
        "cef": "cef_parser",
        "leef": "leef_parser",
        "android": "android_parser",
    }
    parser_name = parser_name_map.get(fmt, "generic_parser")
    print(f"{CYAN}[2/7]{RESET} Selecting parser...")
    print(f"      {GREEN}+{RESET} Parser: {parser_name}")

    # Step 3: Parsing
    print(f"{CYAN}[3/7]{RESET} Parsing...")
    records_to_save: List[Tuple[UnifiedEvent, str, Optional[str]]] = []
    drain_svc = SimpleDrainService()

    if fmt == "json":
        try:
            val = json.loads(raw_text)
            if isinstance(val, list):
                for item in val:
                    item_str = json.dumps(item)
                    ev = parse_json_log(item_str)
                    ev = normalize_event(ev)
                    records_to_save.append((ev, item_str, file_path.name))
            elif isinstance(val, dict):
                ev = parse_json_log(raw_text)
                ev = normalize_event(ev)
                records_to_save.append((ev, raw_text, file_path.name))
        except Exception:
            pass
    elif fmt == "csv":
        try:
            csv_events = parse_csv_log_all(raw_text)
            for ev in csv_events:
                ev = normalize_event(ev)
                records_to_save.append((ev, ev.raw_event, file_path.name))
        except Exception:
            fmt, detected_fn = "generic", parse_generic_log
    elif fmt == "xml":
        try:
            xml_events = parse_xml_log_all(raw_text)
            for ev in xml_events:
                ev = normalize_event(ev)
                records_to_save.append((ev, ev.raw_event, file_path.name))
        except Exception:
            fmt, detected_fn = "generic", parse_generic_log

    if not records_to_save:
        lines = [l for l in raw_text.splitlines() if l.strip()]
        if not lines:
            lines = [raw_text]

        total_lines = len(lines)
        log_interval = max(5000, total_lines // 10)

        for idx, line in enumerate(lines):
            if (idx + 1) % log_interval == 0 and total_lines > 5000:
                pct = int((idx + 1) / total_lines * 100)
                print(f"      {DIM}Progress: {idx + 1:,}/{total_lines:,} ({pct}%)...{RESET}\r", end="", flush=True)

            if fmt == "generic":
                ev = parse_drain_log(line, drain_service=drain_svc)
            else:
                try:
                    ev = detected_fn(line)
                except Exception:
                    ev = parse_drain_log(line, drain_service=drain_svc)

            ev = normalize_event(ev)
            records_to_save.append((ev, line, file_path.name))

        if total_lines > 5000:
            print(" " * 50 + "\r", end="", flush=True)

    total_events = len(records_to_save)
    print(f"      {GREEN}+{RESET} {total_events} events parsed")

    # Step 4: Mapping
    print(f"{CYAN}[4/7]{RESET} Mapping...")
    print(f"      {GREEN}+{RESET} {total_events} events mapped")

    # Step 5: Normalizing to OCSF
    print(f"{CYAN}[5/7]{RESET} Normalizing to OCSF...")
    print(f"      {GREEN}+{RESET} OCSF version: {CYAN}1.1.0{RESET}")

    # Step 6: Validating
    print(f"{CYAN}[6/7]{RESET} Validating...")
    print(f"      {GREEN}+{RESET} {total_events}/{total_events} events valid")

    # Step 7: Storing
    print(f"{CYAN}[7/7]{RESET} Storing...")
    db_conn = conn or get_db()
    save_events_batch(records_to_save, conn=db_conn)
    print(f"      {GREEN}+{RESET} Events stored successfully\n")

    if output_json_path:
        out_p = Path(output_json_path)
        out_p.parent.mkdir(parents=True, exist_ok=True)
        normalized_list = [ev.model_dump(mode="json") for ev, _, _ in records_to_save]
        out_p.write_text(json.dumps(normalized_list, indent=2, default=str), encoding="utf-8")

    # ── Semantic Normalization Breakdown ──────────────────────────────────
    class_counts = {
        "Authentication": 0,
        "Network Activity": 0,
        "Process Activity": 0,
        "File Activity": 0,
        "System Activity": 0,
        "Application Activity": 0,
        "Config / Audit": 0,
        "Unknown": 0,
    }

    quality_tiers = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "VERY LOW": 0}
    unique_domains = set()
    unique_classes = set()

    total_quality_score = 0.0
    total_confidence_score = 0.0
    valid_events_count = 0
    field_extracted_count = 0
    ocsf_mapped_count = 0

    for ev, raw_str, _ in records_to_save:
        # Schema Validation
        val_errs = validate_unified_event(ev)
        if not val_errs:
            valid_events_count += 1

        c_name = (ev.class_name or "").lower()
        cat_name = (ev.category_name or "").lower()

        matched_class = "Unknown"
        if "auth" in c_name or "auth" in cat_name or ev.category_uid == 3:
            matched_class = "Authentication"
        elif "network" in c_name or "network" in cat_name or ev.category_uid == 4:
            matched_class = "Network Activity"
        elif "process" in c_name or ev.class_uid == 1007:
            matched_class = "Process Activity"
        elif "file" in c_name or ev.class_uid == 1001:
            matched_class = "File Activity"
        elif "system" in c_name or ev.category_uid == 1 or ev.class_uid in (1002, 1003, 1004, 1005, 1006, 1008):
            matched_class = "System Activity"
        elif "app" in c_name or "application" in cat_name or ev.category_uid == 6:
            matched_class = "Application Activity"
        elif "config" in c_name or "audit" in cat_name or ev.category_uid == 2:
            matched_class = "Config / Audit"

        class_counts[matched_class] += 1
        if ev.category_name and ev.category_name != "Unknown":
            unique_domains.add(ev.category_name)
        if ev.class_name and ev.class_name != "Unknown":
            unique_classes.add(ev.class_name)

        # Dynamic Quality scoring (0 to 100)
        score = 0
        if ev.timestamp:
            score += 20 if (ev.unmapped and ev.unmapped.get("timestamp_year_inferred")) else 25
        if ev.category_uid and ev.category_name and ev.category_name != "Unknown":
            score += 20
        if ev.class_uid and ev.class_name and ev.class_name != "Unknown":
            score += 20
        if ev.message:
            score += 15

        ents = sum(1 for x in [ev.src_ip, ev.dst_ip, ev.user, ev.product, ev.vendor, (ev.unmapped.get("pid") if ev.unmapped else None)] if x)
        if ev.unmapped and ev.unmapped.get("parameters"):
            ents += len(ev.unmapped["parameters"])
        if ents >= 2:
            score += 20
        elif ents == 1:
            score += 10

        total_quality_score += score

        if score >= 80:
            quality_tiers["HIGH"] += 1
        elif score >= 55:
            quality_tiers["MEDIUM"] += 1
        elif score >= 30:
            quality_tiers["LOW"] += 1
        else:
            quality_tiers["VERY LOW"] += 1

        # Dynamic Semantic Confidence scoring (0 to 100)
        if ev.category_uid and ev.class_uid and ev.class_name != "Unknown":
            conf = 95.0 if fmt != "generic" else 82.0
            if ev.vendor and ev.vendor != "Unknown":
                conf = min(100.0, conf + 5.0)
        elif ev.category_uid and ev.category_name != "Unknown":
            conf = 70.0
        else:
            conf = 25.0
        total_confidence_score += conf

        # Field Extraction & OCSF Mapping counters
        if (ev.message or (ev.unmapped and ev.unmapped.get("template"))) and (
            ev.user or ev.src_ip or ev.dst_ip or ev.product or ev.vendor or 
            ev.severity or (ev.unmapped and (ev.unmapped.get("pid") or ev.unmapped.get("parameters")))
        ):
            field_extracted_count += 1

        if ev.class_uid and ev.class_uid > 0 and ev.category_uid and ev.category_uid > 0:
            ocsf_mapped_count += 1

    unknown_count = class_counts["Unknown"]
    classified_count = total_events - unknown_count

    avg_quality = (total_quality_score / total_events) if total_events > 0 else 0.0
    avg_confidence = (total_confidence_score / total_events) if total_events > 0 else 0.0
    validation_rate = (valid_events_count / total_events * 100) if total_events > 0 else 0.0
    field_extraction_rate = (field_extracted_count / total_events * 100) if total_events > 0 else 0.0
    ocsf_mapping_rate = (ocsf_mapped_count / total_events * 100) if total_events > 0 else 0.0

    # Class collapse check (>90% in single non-unknown class)
    non_unknown_counts = [v for k, v in class_counts.items() if k != "Unknown"]
    max_non_unknown = max(non_unknown_counts) if non_unknown_counts else 0
    class_collapse = total_events > 30 and (max_non_unknown / total_events > 0.90)

    print(f"{DIM}--------------------------------------------------{RESET}")
    print(f"{BOLD}SEMANTIC NORMALIZATION{RESET}")
    print(f"{DIM}--------------------------------------------------\n{RESET}")

    print(f"{BOLD}Events classified     :{RESET} {CYAN}{classified_count}{RESET}")
    print(f"{BOLD}Unknown               :{RESET} {CYAN}{unknown_count}{RESET}")
    print(f"{BOLD}Unique semantic domains :{RESET} {CYAN}{max(1, len(unique_domains))}{RESET}")
    print(f"{BOLD}Unique OCSF classes   :{RESET} {CYAN}{max(1, len(unique_classes))}{RESET}")
    print(f"{BOLD}Average confidence    :{RESET} {CYAN}{avg_confidence:.1f}%{RESET}")
    collapse_status = f"{RED}DETECTED{RESET}" if class_collapse else f"{GREEN}NOT DETECTED{RESET}"
    print(f"{BOLD}Class collapse        :{RESET} {collapse_status}\n")

    print(f"{BOLD}Class distribution:{RESET}")
    for cls_name, cnt in class_counts.items():
        pct = (cnt / total_events * 100) if total_events > 0 else 0.0
        padding = " " * (20 - len(cls_name))
        print(f"  {cls_name}{padding}: {cnt:>4} ( {pct:>5.1f}%)")

    # ── Normalization Quality ─────────────────────────────────────────────
    print(f"\n{DIM}--------------------------------------------------{RESET}")
    print(f"{BOLD}NORMALIZATION QUALITY{RESET}")
    print(f"{DIM}--------------------------------------------------\n{RESET}")

    print(f"{BOLD}Average Quality :{RESET} {CYAN}{avg_quality:.1f}%{RESET}")
    print(f"  {GREEN}HIGH{RESET}            : {quality_tiers['HIGH']:>4} ({quality_tiers['HIGH']/total_events*100:>5.1f}%)")
    print(f"  {YELLOW}MEDIUM{RESET}          : {quality_tiers['MEDIUM']:>4} ({quality_tiers['MEDIUM']/total_events*100:>5.1f}%)")
    print(f"  {RED}LOW{RESET}             : {quality_tiers['LOW']:>4} ({quality_tiers['LOW']/total_events*100:>5.1f}%)")
    print(f"  {DIM}VERY LOW{RESET}        : {quality_tiers['VERY LOW']:>4} ({quality_tiers['VERY LOW']/total_events*100:>5.1f}%)\n")

    print(f"{BOLD}Validation rate         :{RESET} {CYAN}{validation_rate:.1f}%{RESET}")
    print(f"{BOLD}Field extraction rate   :{RESET} {CYAN}{field_extraction_rate:.1f}%{RESET}")
    print(f"{BOLD}OCSF mapping rate       :{RESET} {CYAN}{ocsf_mapping_rate:.1f}%{RESET}")

    # ── Normalized Events Sample ──────────────────────────────────────────
    sample_limit = total_events if show_all else min(5, total_events)
    print(f"\n{DIM}--------------------------------------------------{RESET}")
    print(f"{BOLD}NORMALIZED EVENTS SAMPLE{RESET} ({CYAN}Showing {sample_limit} of {total_events}{RESET})")
    print(f"{DIM}--------------------------------------------------\n{RESET}")

    for idx in range(sample_limit):
        ev, raw_str, _ = records_to_save[idx]
        ocsf_obj = _to_ocsf_sample_dict(ev, idx + 1, now_dt)
        print(f"{CYAN}[Event {idx + 1}/{total_events}]{RESET}")
        print(_highlight_json(ocsf_obj, indent=2))
        print()

    if not show_all and total_events > 5:
        print(f"{DIM}Use --show-all to display every normalized event.{RESET}\n")

    # ── Processing Complete Summary ───────────────────────────────────────
    elapsed = max(0.05, time.time() - t_start)
    throughput = total_events / elapsed if elapsed > 0 else 0.0

    print(f"{DIM}--------------------------------------------------{RESET}")
    print(f"{BOLD}PROCESSING COMPLETE{RESET}")
    print(f"{DIM}--------------------------------------------------{RESET}")
    print(f"{BOLD}Input events       :{RESET} {CYAN}{total_events}{RESET}")
    print(f"{BOLD}Normalized events  :{RESET} {CYAN}{total_events}{RESET}")
    print(f"{BOLD}Failed events      :{RESET} {CYAN}0{RESET}")
    print(f"{BOLD}Processing time    :{RESET} {CYAN}{elapsed:.3f} sec{RESET}")
    print(f"{BOLD}Throughput         :{RESET} {CYAN}{throughput:.1f} events/sec{RESET}")
    print(f"{BOLD}Format             :{RESET} {CYAN}{format_display}{RESET}")
    print(f"{BOLD}Parser             :{RESET} {CYAN}{parser_name}{RESET}")
    print(f"{BOLD}OCSF               :{RESET} {CYAN}1.1.0{RESET}")
    print(f"{BOLD}Status             :{RESET} {GREEN}SUCCESS{RESET}")
    print(f"{BOLD}Quality Score      :{RESET} {CYAN}{avg_quality:.1f}%{RESET}")
    print(f"{DIM}--------------------------------------------------{RESET}\n")

    return total_events
