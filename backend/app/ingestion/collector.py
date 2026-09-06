"""
Log Collector (Node 1).
Single generic entry point for handing off raw log streams, lines, and files + source metadata
to the pipeline without any parsing or format assumptions.
Handles generic, format-agnostic multi-line continuation grouping (unclosed brackets/quotes,
stack traces, indented lines, timestamp-less followups) and stream header metadata scanning.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Optional

from app.ingestion.banner_scanner import scan_stream_header


@dataclass
class CollectedRawChunk:
    """Represents an isolated raw log chunk collected before storage and parsing."""
    raw_text: str
    source_name: str
    source_metadata: Dict[str, Any] = field(default_factory=dict)
    collected_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


def _has_timestamp_prefix(line: str) -> bool:
    """Check if line starts with an absolute or relative timestamp pattern or event header."""
    s = line.strip()
    if not s:
        return False
    # Priority syslog timestamp or Cisco ASA header
    if s.startswith("<") and ">" in s[:6]:
        return True
    if s.startswith("%ASA-") or re.match(r"^[a-zA-Z0-9_\-\.]+:\s*%ASA-", s):
        return True
    # ISO 8601 / RFC 3339 / Relative timestamp HH:MM:SS.ffffff / BSD syslog (with or without year)
    patterns = (
        r"^[0-9]{4}-[0-9]{2}-[0-9]{2}",                       # 2026-08-26...
        r"^[A-Z][a-z]{2}\s+\d{1,2}(?:\s+\d{4})?\s+\d{2}:\d{2}:\d{2}", # Aug 26 12:00:00 or Apr 15 2013 09:36:50
        r"^\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d{3}",           # 08-26 12:00:00.123 (Android)
        r"^\d{2}:\d{2}:\d{2}\.\d+",                           # 00:00:00.008099 (VirtualBox/relative)
        r"^\[\d{4}-\d{2}-\d{2}",                               # [2026-08-26...
        r"^\[[A-Z][a-z]{2}\s+\d{1,2}",                         # [Aug 26...
        r"^CEF:\s*\d+",                                        # CEF:0...
        r"^LEEF:\s*[\d\.]+",                                   # LEEF:1.0...
    )
    return any(bool(re.match(p, s)) for p in patterns)


def _has_unclosed_delimiters(text: str) -> bool:
    """Check if the accumulated text has unclosed structural curly braces."""
    # Never use quote-balance or parenthesis/bracket heuristics that can falsely absorb lines
    open_curly = text.count("{") - text.count("}")
    return open_curly > 0


def _split_raw_into_chunks(raw_text: str) -> List[str]:
    """
    Split raw text payload into individual logical log chunks/events.
    Format-agnostic multi-line grouping merges:
    1. Unclosed brackets, braces, parentheses, and quotes across lines.
    2. Stack traces and indented lines (starts with tab, multiple spaces, 'at ', 'Caused by:').
    3. Timestamp-less follow-up lines following a timestamped header.
    """
    stripped = raw_text.strip()
    if not stripped:
        return []

    # Check for JSON array payload
    if stripped.startswith("[") and stripped.endswith("]"):
        try:
            val = json.loads(stripped)
            if isinstance(val, list):
                return [json.dumps(item) for item in val]
        except json.JSONDecodeError:
            pass

    # Check for XML root document
    if stripped.startswith("<?xml") or (stripped.startswith("<") and stripped.endswith(">")):
        return [stripped]

    # Check for CSV format with header line
    first_line = stripped.split("\n", 1)[0].lower()
    if "," in first_line and any(h in first_line for h in ("timestamp", "time", "date", "user", "src_ip", "event_id", "severity", "level", "message", "action")):
        if "\n" in stripped:
            return [stripped]

    # Check for systemd / journald multi-line blocks separated by double-newlines
    if "__CURSOR=" in stripped and "\n\n" in stripped:
        blocks = [b.strip() for b in stripped.split("\n\n") if b.strip()]
        if len(blocks) > 1:
            return blocks

    lines = raw_text.splitlines()
    records: List[str] = []
    current_record: List[str] = []

    for line in lines:
        if not line.strip():
            continue

        stripped_line = line.strip()

        # Check stack trace / explicit continuation markers
        is_stack_trace_continuation = (
            line.startswith("\t")
            or line.startswith("   ")
            or stripped_line.startswith("at ")
            or stripped_line.startswith("Caused by:")
            or stripped_line.startswith("... ")
            or bool(re.match(r"^[a-zA-Z0-9_.]+(?:Exception|Error|Throwable):", stripped_line))
        )

        # Check closing marker continuation (e.g. "}, preserve=false ...")
        is_closing_continuation = (
            stripped_line.startswith("}")
            or stripped_line.startswith("]")
            or stripped_line.startswith(")")
            or stripped_line.startswith(");")
        )

        # If we have an active record, check if it should be continued
        if current_record:
            accumulated_text = "\n".join(current_record)
            is_unclosed = _has_unclosed_delimiters(accumulated_text)
            has_new_ts = _has_timestamp_prefix(line)

            # Continue current record if unclosed delimiters, explicit stack continuation, closing marker, or (no new timestamp and indented/continuation)
            if is_unclosed or is_stack_trace_continuation or is_closing_continuation or (not has_new_ts and (line.startswith(" ") or line.startswith("\t"))):
                current_record.append(line)
                continue
            elif not has_new_ts and not is_stack_trace_continuation:
                # Check if current line starts a new standalone known format (e.g. CEF:, LEEF:)
                if stripped_line.startswith("CEF:") or stripped_line.startswith("LEEF:") or stripped_line.startswith("<"):
                    records.append(accumulated_text)
                    current_record = [line]
                else:
                    # If accumulated record ends with an open delimiter or unclosed clause
                    if is_unclosed:
                        current_record.append(line)
                    else:
                        records.append(accumulated_text)
                        current_record = [line]
                continue

            # Starts a new event
            records.append(accumulated_text)
            current_record = [line]
        else:
            current_record = [line]

    if current_record:
        records.append("\n".join(current_record))

    return records if records else [stripped]


class LogCollector:
    """Generic Log Collector receiving raw streams/files and preparing raw chunks."""

    @staticmethod
    def collect_from_text(
        raw_text: str,
        source_name: str = "api_stream",
        source_metadata: Optional[Dict[str, Any]] = None,
    ) -> List[CollectedRawChunk]:
        """Collect and partition a raw text payload into raw chunks with stream metadata."""
        meta = dict(source_metadata or {})
        lines = raw_text.splitlines()

        # Scan stream headers for self-declared banner metadata and anchor timestamp
        stream_header_meta = scan_stream_header(lines)
        for k, v in stream_header_meta.items():
            meta.setdefault(k, v)

        chunks = _split_raw_into_chunks(raw_text)
        return [
            CollectedRawChunk(
                raw_text=c,
                source_name=source_name,
                source_metadata=meta,
            )
            for c in chunks
        ]

    @staticmethod
    def collect_from_file(
        file_path: str | Path,
        source_metadata: Optional[Dict[str, Any]] = None,
    ) -> List[CollectedRawChunk]:
        """Collect and read raw log chunks from a file on disk with encoding resilience."""
        p = Path(file_path)
        raw_bytes = p.read_bytes()

        # Resilient decoding supporting UTF-8, UTF-16 (with BOM), Latin-1
        if raw_bytes.startswith(b"\xff\xfe") or raw_bytes.startswith(b"\xfe\xff"):
            try:
                raw_text = raw_bytes.decode("utf-16")
            except Exception:
                raw_text = raw_bytes.decode("latin-1", errors="replace")
        else:
            try:
                raw_text = raw_bytes.decode("utf-8")
            except UnicodeDecodeError:
                raw_text = raw_bytes.decode("latin-1", errors="replace")

        meta = dict(source_metadata or {})
        meta.setdefault("file_path", str(p.resolve()))
        meta.setdefault("file_size_bytes", len(raw_bytes))

        return LogCollector.collect_from_text(
            raw_text=raw_text,
            source_name=p.name,
            source_metadata=meta,
        )

    @staticmethod
    def collect_from_lines(
        lines: Iterable[str],
        source_name: str = "api_stream",
        source_metadata: Optional[Dict[str, Any]] = None,
    ) -> List[CollectedRawChunk]:
        """Collect log chunks from an iterable collection of string lines."""
        raw_text = "\n".join(lines)
        return LogCollector.collect_from_text(
            raw_text=raw_text,
            source_name=source_name,
            source_metadata=source_metadata,
        )

    @staticmethod
    def collect_from_file_stream(
        file_path: str | Path,
        chunk_size: int = 1000,
        source_metadata: Optional[Dict[str, Any]] = None,
    ) -> Iterator[List[CollectedRawChunk]]:
        """
        Stream raw log chunks from a file in bounded batches without loading the whole file into RAM.
        Preserves multi-line record grouping across batch boundaries.
        """
        p = Path(file_path)
        meta = dict(source_metadata or {})
        meta.setdefault("file_path", str(p.resolve()))
        sz = 0
        try:
            sz = p.stat().st_size
            meta.setdefault("file_size_bytes", sz)
        except Exception:
            pass

        # If file begins with structured XML or JSON array, parse and chunk
        if sz < 512 * 1024:
            try:
                with open(p, "rb") as peek_f:
                    head = peek_f.read(256).strip()
                    if head.startswith(b"<") or head.startswith(b"["):
                        all_chunks = LogCollector.collect_from_file(p, source_metadata=meta)
                        for i in range(0, len(all_chunks), chunk_size):
                            yield all_chunks[i : i + chunk_size]
                        return
            except Exception:
                pass

        # Check if file is CSV (by suffix or header pattern)
        is_csv_file = p.suffix.lower() in (".csv", ".tsv")
        if not is_csv_file and p.suffix.lower() not in (".json", ".xml", ".ndjson") and sz > 0:
            try:
                with open(p, "r", encoding="utf-8", errors="replace") as peek_f:
                    sample_sniff = [peek_f.readline() for _ in range(4)]
                    from app.ingestion.detector import _looks_like_csv
                    sniff_str = "".join(sample_sniff).strip()
                    if not (sniff_str.startswith("{") or sniff_str.startswith("[") or sniff_str.startswith("<")):
                        if _looks_like_csv(sniff_str):
                            is_csv_file = True
            except Exception:
                pass

        if is_csv_file:
            with open(p, "r", encoding="utf-8", errors="replace") as f:
                header_line = f.readline().rstrip("\r\n")
                if header_line:
                    csv_meta = dict(meta)
                    csv_meta["log_format"] = "csv"
                    csv_meta["csv_header"] = header_line
                    csv_batch = []
                    for line in f:
                        line_clean = line.rstrip("\r\n")
                        if not line_clean.strip():
                            continue
                        csv_batch.append(
                            CollectedRawChunk(
                                raw_text=line_clean,
                                source_name=p.name,
                                source_metadata=csv_meta,
                            )
                        )
                        if len(csv_batch) >= chunk_size:
                            yield csv_batch
                            csv_batch = []
                    if csv_batch:
                        yield csv_batch
            return

        batch: List[CollectedRawChunk] = []
        with open(p, "r", encoding="utf-8", errors="replace") as f:
            current_record: List[str] = []
            for line in f:
                if not line.strip():
                    continue
                stripped_line = line.strip()
                is_stack = (
                    line.startswith("\t")
                    or line.startswith("   ")
                    or stripped_line.startswith("at ")
                    or stripped_line.startswith("Caused by:")
                )
                if current_record:
                    acc = "\n".join(current_record)
                    has_ts = _has_timestamp_prefix(line)
                    if _has_unclosed_delimiters(acc) or is_stack or (not has_ts and (line.startswith(" ") or line.startswith("\t"))):
                        current_record.append(line)
                        continue
                    else:
                        batch.append(CollectedRawChunk(raw_text=acc, source_name=p.name, source_metadata=meta))
                        current_record = [line]
                else:
                    current_record = [line]

                if len(batch) >= chunk_size:
                    yield batch
                    batch = []

            if current_record:
                batch.append(CollectedRawChunk(raw_text="\n".join(current_record), source_name=p.name, source_metadata=meta))

            if batch:
                yield batch
