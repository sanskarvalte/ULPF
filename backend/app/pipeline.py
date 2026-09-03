"""
Unified 8-Node Log Processing Pipeline Coordinator for ULPF.

Flow:
  1. Log Collector ────────► Accepts raw line/blob + source metadata
       │
       ▼
  2. Raw Storage ──────────► Unconditionally stores byte-for-byte in DuckDB raw_events
       │
       ▼
  3. Format Matcher ───────► Deterministic signature check (runtime-mutable registry)
    ├── YES (Known) ───────► 4. Rule-Based Parser (Syslog, JSON, XML, CSV, CEF, LEEF, Android, Custom)
    └── NO (Unknown) ──────► 5. Ollama AI Assistant (Fingerprints, enqueues to Node 6, emits non-blocking)
                                  │
       [both branches converge]   ▼
       │                     6. Human Review & 7. Save as New Parser (Dynamic reload)
       ▼                          │
  8. Unified Normalizer ◄─────────┘
       ├── Losslessness Substring Guard
       └── OCSF Taxonomy & Numeric UID mapping
       │
       ▼
  Output Sinks (DuckDB SQL, Parquet, JSON, ML Isolation Forest)
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import duckdb
from app.ai.ollama_detector import process_unmatched_log_with_ai
from app.blockchain.ledger import append_event_blocks_batch
from app.ingestion.collector import CollectedRawChunk, LogCollector
from app.ingestion.detector import match_format
from app.models.event_schema import UnifiedEvent
from app.normalization.engine import normalize_event
from app.parsers.csv_parser import parse_csv_log_all
from app.parsers.xml_parser import parse_xml_log_all
from app.storage.db import get_db
from app.storage.normalized import save_events_batch
from app.storage.raw import hash_raw_log, save_raw_events_batch


class PipelineEngine:
    """Core 8-Node Pipeline Engine."""

    def __init__(self, conn: Optional[duckdb.DuckDBPyConnection] = None):
        self.conn = conn

    def process_raw_chunks(
        self,
        chunks: List[CollectedRawChunk],
        persist_normalized: bool = True,
    ) -> List[Tuple[UnifiedEvent, str, str]]:
        """
        Process collected raw chunks through Nodes 2 to 8.
        Returns list of tuples: (UnifiedEvent, raw_event_id, source_name)
        """
        c = (self.conn or get_db()) if persist_normalized else None
        results: List[Tuple[UnifiedEvent, str, str]] = []
        batch_to_save: List[Tuple[UnifiedEvent, str, str]] = []
        raw_batch_to_save: List[Tuple[str, str, Optional[str]]] = []

        for chunk in chunks:
            raw_text = chunk.raw_text
            source_name = chunk.source_name

            # ── NODE 2: Raw Storage ID Computation ──────────────────────
            raw_id = hash_raw_log(raw_text)
            if persist_normalized:
                raw_batch_to_save.append((raw_id, raw_text, source_name))

            # ── NODE 3: Format Matcher ("Known Format?") ────────────────
            is_known, fmt_name, parser_fn = match_format(raw_text)

            # Multi-record format handling (CSV & XML audit logs)
            if is_known and fmt_name == "csv":
                try:
                    csv_events = parse_csv_log_all(raw_text)
                    for ev in csv_events:
                        norm_ev = normalize_event(ev)
                        norm_ev.raw_event_id = raw_id
                        results.append((norm_ev, raw_id, source_name))
                        if persist_normalized:
                            batch_to_save.append((norm_ev, ev.raw_event, source_name))
                    continue
                except Exception:
                    pass
            elif is_known and fmt_name == "xml":
                try:
                    xml_events = parse_xml_log_all(raw_text)
                    if len(xml_events) > 1:
                        for ev in xml_events:
                            norm_ev = normalize_event(ev)
                            norm_ev.raw_event_id = raw_id
                            results.append((norm_ev, raw_id, source_name))
                            if persist_normalized:
                                batch_to_save.append((norm_ev, ev.raw_event, source_name))
                        continue
                except Exception:
                    pass

            # ── NODE 4 & NODE 5: Branching ──────────────────────────────
            if is_known:
                # YES BRANCH: Rule-Based Parser (Deterministic <1ms, zero Ollama)
                try:
                    parsed_event = parser_fn(raw_text)
                except Exception as e:
                    logger.warning(f"Parser failed for {fmt_name}: {e}")
                    from app.parsers.generic_parser import parse_generic_log
                    parsed_event = parse_generic_log(raw_text)
            else:
                # NO BRANCH: Ollama AI Assistant (Fingerprints, non-blocking queue)
                parsed_event = process_unmatched_log_with_ai(raw_text, conn=c)

            # ── NODE 8: Unified Normalizer (Single Convergence Point) ────
            normalized_event = normalize_event(parsed_event)
            normalized_event.raw_event_id = raw_id

            # Stream metadata enrichment (self-declared banner vendor/product & anchor timestamp)
            if chunk.source_metadata:
                if not normalized_event.vendor and chunk.source_metadata.get("vendor"):
                    normalized_event.vendor = chunk.source_metadata["vendor"]
                if not normalized_event.product and chunk.source_metadata.get("product"):
                    normalized_event.product = chunk.source_metadata["product"]
                if not normalized_event.product_version and chunk.source_metadata.get("product_version"):
                    normalized_event.product_version = chunk.source_metadata["product_version"]
                if not normalized_event.timestamp and chunk.source_metadata.get("anchor_timestamp"):
                    from app.normalization.field_mapping import parse_timestamp
                    import re
                    rel_m = re.search(r"\b(\d{1,2}:\d{2}:\d{2}(?:\.\d+)?)\b", raw_text)
                    if rel_m:
                        ts = parse_timestamp(rel_m.group(1), anchor_date=chunk.source_metadata["anchor_timestamp"])
                        if ts:
                            normalized_event.timestamp = ts

            results.append((normalized_event, raw_id, source_name))
            if persist_normalized:
                batch_to_save.append((normalized_event, raw_text, source_name))

        # ── Output Persistence Sink (Batch Transaction) ────────────────
        if persist_normalized and c is not None:
            if raw_batch_to_save:
                try:
                    save_raw_events_batch(raw_batch_to_save, conn=c)
                except Exception as e:
                    logger.error(f"Raw storage batch error: {e}")
            if batch_to_save:
                try:
                    save_events_batch(batch_to_save, conn=c)
                    event_records = [
                        (ev.event_id, ev.raw_event_id or hash_raw_log(raw_t))
                        for ev, raw_t, _ in batch_to_save
                        if ev.event_id and (ev.raw_event_id or raw_t)
                    ]
                    if event_records:
                        append_event_blocks_batch(event_records, action="LOG_STORED", conn=c)
                except Exception as e:
                    logger.error(f"Normalized storage & blockchain batch error: {e}")

        return results

    def ingest_text(
        self,
        raw_text: str,
        source_name: str = "api_upload.log",
        source_metadata: Optional[Dict[str, Any]] = None,
        persist: bool = True,
    ) -> List[UnifiedEvent]:
        """Node 1 entrypoint for text payloads."""
        chunks = LogCollector.collect_from_text(
            raw_text=raw_text,
            source_name=source_name,
            source_metadata=source_metadata,
        )
        processed = self.process_raw_chunks(chunks, persist_normalized=persist)
        return [item[0] for item in processed]

    def ingest_file(
        self,
        file_path: str | Path,
        source_metadata: Optional[Dict[str, Any]] = None,
        persist: bool = True,
    ) -> List[UnifiedEvent]:
        """Node 1 entrypoint for files."""
        chunks = LogCollector.collect_from_file(
            file_path=file_path,
            source_metadata=source_metadata,
        )
        processed = self.process_raw_chunks(chunks, persist_normalized=persist)
        return [item[0] for item in processed]


# Global pipeline instance
pipeline = PipelineEngine()


def run_pipeline(
    raw_text: str,
    filename: str = "file.log",
    save_to_db: bool = False,
) -> Dict[str, Any]:
    """
    Convenience wrapper to run text through pipeline and return summary dict.
    """
    events = pipeline.ingest_text(raw_text, source_name=filename, persist=save_to_db)
    det_fmt = events[0].log_format if events else "unknown"
    return {
        "format": det_fmt,
        "events": events,
        "count": len(events),
        "unparsed_count": 0,
    }
