"""
Log to JSON Conversion Utility.
Uses LogPAI format regexes and Drain template clustering to convert any log file into JSON.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

_BACKEND_DIR = Path(__file__).resolve().parent.parent.parent
if str(_BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(_BACKEND_DIR))

from app.parsers.drain_service import SimpleDrainService, generate_logformat_regex

FORMATS_FILE = Path(__file__).resolve().parent.parent.parent.parent / "integrations" / "loghub" / "formats.json"


def load_loghub_formats() -> Dict[str, Any]:
    if FORMATS_FILE.exists():
        try:
            return json.loads(FORMATS_FILE.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {}


def parse_log_to_json_records(
    log_text: str,
    format_name: Optional[str] = None,
    custom_format_str: Optional[str] = None,
    mine_templates: bool = True,
) -> List[Dict[str, Any]]:
    """Parse unstructured log lines into structured JSON records."""
    formats = load_loghub_formats()
    format_str = custom_format_str or (formats.get(format_name, {}).get("log_format") if format_name else None)

    regex_matcher = None
    headers = []
    if format_str:
        regex_matcher, headers = generate_logformat_regex(format_str)

    drain_miner = SimpleDrainService() if mine_templates else None
    results: List[Dict[str, Any]] = []

    lines = [l for l in log_text.splitlines() if l.strip()]
    for idx, line in enumerate(lines, start=1):
        record: Dict[str, Any] = {"line_id": idx, "raw_log": line}

        if regex_matcher:
            match = regex_matcher.match(line)
            if match:
                record.update(match.groupdict())
            else:
                record["content"] = line
        else:
            record["content"] = line

        if drain_miner:
            content_to_mine = record.get("Content") or record.get("content") or record.get("message") or line
            mined = drain_miner.mine_template(str(content_to_mine))
            record["event_template"] = mined["template"]
            record["cluster_id"] = mined["cluster_id"]

        results.append(record)

    return results


def convert_log_file_to_json(
    input_file: Path,
    output_file: Optional[Path] = None,
    format_name: Optional[str] = None,
) -> Path:
    """Read a log file, convert to JSON, and save to output file."""
    text = input_file.read_text(encoding="utf-8", errors="replace")
    records = parse_log_to_json_records(text, format_name=format_name)

    out_path = output_file or input_file.with_suffix(".json")
    out_path.write_text(json.dumps(records, indent=2, default=str), encoding="utf-8")
    return out_path


def main():
    parser = argparse.ArgumentParser(description="Convert raw log files into JSON using LogPAI format extraction")
    parser.add_argument("input_log", help="Path to raw log file")
    parser.add_argument("-o", "--output", help="Output JSON file path")
    parser.add_argument("-f", "--format", help="Predefined format name (HDFS, Linux, Windows, BGL, Android, Apache, OpenSSH, etc.)")
    args = parser.parse_args()

    in_p = Path(args.input_log)
    out_p = Path(args.output) if args.output else None
    res = convert_log_file_to_json(in_p, out_p, format_name=args.format)
    print(f"✓ Successfully converted {in_p.name} -> {res.resolve()}")


if __name__ == "__main__":
    main()
