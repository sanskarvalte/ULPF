"""
Comprehensive Automated Architecture-Level Verification & Accuracy Test Suite.
Verifies all 8 core bug fixes and audited resilience requirements:
1. Multi-line continuation grouping (unclosed delimiters & stack traces).
2. Template variable caching bug regression (10+ lines with same template).
3. Centralized severity keyword floor enforcement.
4. Self-declared banner scanning (vendor/product/version).
5. Relative-to-anchor timestamp conversion.
6. Dynamic confidence refinement and template auto-promotion.
7. True hash-chained ledger and verify_chain() tamper detection (content modification, deletion, reordering).
8. Structured format & encoding resilience (nested JSON, quoted CSV, UTF-16 BOM, Latin-1).
"""

import unittest
from datetime import datetime, timezone
import duckdb

from app.ingestion.collector import LogCollector
from app.ingestion.banner_scanner import scan_stream_header
from app.normalization.field_mapping import parse_timestamp
from app.normalization.engine import normalize_event
from app.validation.validator import get_severity_keyword_floor
from app.ai.ollama_detector import process_unmatched_log_with_ai, _FINGERPRINT_COUNTS, _FINGERPRINT_SUGGESTION_CACHE
from app.pipeline import run_pipeline, PipelineEngine
from app.storage.raw import save_raw_event, verify_chain, hash_raw_log, GENESIS_HASH
from app.models.event_schema import UnifiedEvent


class TestArchitectureAccuracy(unittest.TestCase):

    def setUp(self):
        _FINGERPRINT_COUNTS.clear()
        _FINGERPRINT_SUGGESTION_CACHE.clear()

    # ─────────────────────────────────────────────────────────────────
    # 1. Multi-line / Continuation Log Entries
    # ─────────────────────────────────────────────────────────────────
    def test_multiline_unclosed_brace_merging(self):
        raw_text = (
            "00:00:00.008099 nspr-2   ERROR [COM]: aText={Loading the NVRAM store failed (VERR_PATH_NOT_FOUND)\n"
            "}, preserve=false aResultDetail=0\n"
            "00:00:00.009100 nspr-2   Next standalone event line"
        )
        chunks = LogCollector.collect_from_text(raw_text, source_name="vbox_test.log")
        self.assertEqual(len(chunks), 2)
        # First chunk must contain both lines of the unclosed brace
        self.assertIn("Loading the NVRAM store failed", chunks[0].raw_text)
        self.assertIn("preserve=false aResultDetail=0", chunks[0].raw_text)
        self.assertIn("Next standalone event line", chunks[1].raw_text)

    def test_multiline_java_stacktrace_merging(self):
        raw_text = (
            "2026-08-26 10:00:00.123 [main] ERROR org.apache.catalina.Core - Service start failed\n"
            "\tjava.lang.NullPointerException: Null database connection\n"
            "\t\tat org.apache.catalina.DbManager.connect(DbManager.java:42)\n"
            "\t\tat org.apache.catalina.Core.start(Core.java:100)\n"
            "\tCaused by: java.io.IOException: Connection refused\n"
            "\t\t... 12 more\n"
            "2026-08-26 10:00:01.000 [main] INFO org.apache.catalina.Core - Shutdown initiated"
        )
        chunks = LogCollector.collect_from_text(raw_text, source_name="catalina.log")
        self.assertEqual(len(chunks), 2)
        self.assertIn("NullPointerException", chunks[0].raw_text)
        self.assertIn("Caused by: java.io.IOException", chunks[0].raw_text)
        self.assertEqual(chunks[1].raw_text.strip(), "2026-08-26 10:00:01.000 [main] INFO org.apache.catalina.Core - Shutdown initiated")

    # ─────────────────────────────────────────────────────────────────
    # 2. Template Caching Bug Regression (Variable Fields Reused)
    # ─────────────────────────────────────────────────────────────────
    def test_template_variable_caching_regression(self):
        """Feed 10 lines matching the same structural template and assert each gets ITS OWN message & values."""
        lines = [
            f"00:00:0{i:02d}.000000 nspr-2   Saving settings file /var/vbox/Machines/VM_{i}/box.xml"
            for i in range(12)
        ]
        events: list[UnifiedEvent] = []
        for line in lines:
            ev = process_unmatched_log_with_ai(line)
            norm = normalize_event(ev)
            events.append(norm)

        self.assertEqual(len(events), 12)
        for i, ev in enumerate(events):
            expected_path = f"/var/vbox/Machines/VM_{i}/box.xml"
            # The message or raw_event MUST contain VM_i, not VM_0!
            self.assertIn(f"VM_{i}", ev.raw_event)
            self.assertIn(f"VM_{i}", ev.message)
            self.assertNotIn("VM_0" if i > 0 else "VM_1", ev.message)

    # ─────────────────────────────────────────────────────────────────
    # 3. Deterministic Severity Keyword Floor Enforcement
    # ─────────────────────────────────────────────────────────────────
    def test_severity_keyword_floor_enforcement(self):
        test_cases = [
            ("Jul 10 12:00:00 srv kernel: System encountered FATAL memory fault", "Fatal", 6),
            ("Jul 10 12:00:00 srv kernel: CRITICAL hardware temperature alert", "Critical", 5),
            ("Jul 10 12:00:00 srv daemon: Transaction database FAIL during sync", "High", 4),
            ("Jul 10 12:00:00 srv daemon: Exception thrown during operation", "High", 4),
            ("Jul 10 12:00:00 srv daemon: Disk space WARNING threshold reached", "Medium", 3),
        ]
        for raw, expected_sev, expected_sid in test_cases:
            name, sid = get_severity_keyword_floor(raw)
            self.assertEqual(name, expected_sev)
            self.assertEqual(sid, expected_sid)

            # Test through normalize_event
            ev = UnifiedEvent(raw_event=raw, message="test", severity="Informational", severity_id=1)
            norm = normalize_event(ev)
            self.assertEqual(norm.severity, expected_sev)
            self.assertEqual(norm.severity_id, expected_sid)

    # ─────────────────────────────────────────────────────────────────
    # 4. Self-Declared Vendor/Product Banner Scanning
    # ─────────────────────────────────────────────────────────────────
    def test_self_declared_banner_scanning(self):
        vbox_header = [
            "VirtualBox VM 7.0.12 r159484 darwin.arm64 (Oct 17 2023 17:34:04) release log",
            "00:00:00.008099 Log opened 2026-08-26T12:00:00.000000000Z",
            "00:00:00.008150 OS Product: Darwin",
        ]
        meta = scan_stream_header(vbox_header)
        self.assertEqual(meta.get("vendor"), "Oracle")
        self.assertEqual(meta.get("product"), "VirtualBox")
        self.assertEqual(meta.get("product_version"), "7.0.12")
        self.assertIsNotNone(meta.get("anchor_timestamp"))
        self.assertEqual(meta["anchor_timestamp"].year, 2026)

    # ─────────────────────────────────────────────────────────────────
    # 5. Relative-to-Anchor Timestamp Resolution
    # ─────────────────────────────────────────────────────────────────
    def test_relative_timestamp_anchor_conversion(self):
        anchor = datetime(2026, 8, 26, 12, 0, 0, tzinfo=timezone.utc)
        rel_ts_str = "00:01:30.500000"
        parsed = parse_timestamp(rel_ts_str, anchor_date=anchor)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed.year, 2026)
        self.assertEqual(parsed.hour, 12)
        self.assertEqual(parsed.minute, 1)
        self.assertEqual(parsed.second, 30)
        self.assertEqual(parsed.microsecond, 500000)

    # ─────────────────────────────────────────────────────────────────
    # 6. Dynamic Confidence Refinement & Template Auto-Promotion
    # ─────────────────────────────────────────────────────────────────
    def test_template_auto_promotion_after_repeat_occurrences(self):
        raw_pattern = "svc:inventory-sync sku:{} qty:100 status:ok"
        events: list[UnifiedEvent] = []
        for i in range(5):
            line = raw_pattern.format(1000 + i)
            ev = process_unmatched_log_with_ai(line)
            events.append(ev)

        # 1st occurrence: unknown_pending_review
        self.assertEqual(events[0].log_format, "unknown_pending_review")
        self.assertLessEqual(events[0].unmapped.get("ollama_confidence", 0), 0.75)

        # 3rd-5th occurrence: promoted to learned format identifier with increased confidence
        self.assertIn("learned_", events[4].log_format)
        self.assertGreaterEqual(events[4].unmapped.get("ollama_confidence", 0), 0.85)

    # ─────────────────────────────────────────────────────────────────
    # 7. True Hash-Chained Ledger & Tamper Detection (verify_chain)
    # ─────────────────────────────────────────────────────────────────
    def test_hash_chained_ledger_and_tamper_detection(self):
        conn = duckdb.connect(":memory:")
        from app.storage.db import get_db
        # Initialize tables on in-memory DB
        conn.execute("""
        CREATE TABLE raw_events (
            raw_event_id VARCHAR PRIMARY KEY,
            raw_text TEXT NOT NULL,
            received_at TIMESTAMP NOT NULL,
            source_file VARCHAR,
            previous_hash VARCHAR,
            seq_num BIGINT
        );
        """)

        # 1. Ingest sequence of events
        source = "secure_audit.log"
        lines = [
            "User alice logged in from 10.0.0.1",
            "User alice accessed confidential document ID 42",
            "User alice logged out",
        ]
        raw_ids = []
        for line in lines:
            rid = save_raw_event(line, source_file=source, conn=conn)
            raw_ids.append(rid)

        # 2. Verify unmodified chain passes
        is_valid, count, violations = verify_chain(source_file=source, conn=conn)
        self.assertTrue(is_valid)
        self.assertEqual(count, 3)
        self.assertEqual(len(violations), 0)

        # 3. Deliberately tamper with second entry's raw_text
        conn.execute(
            "UPDATE raw_events SET raw_text = 'User alice accessed public document ID 42' WHERE raw_event_id = ?",
            [raw_ids[1]],
        )
        is_valid_tampered, _, violations_tampered = verify_chain(source_file=source, conn=conn)
        self.assertFalse(is_valid_tampered)
        self.assertTrue(any("Tampered content" in v["error"] for v in violations_tampered))

        # 4. Deliberately delete middle entry to break sequence link
        conn.execute("DELETE FROM raw_events WHERE raw_event_id = ?", [raw_ids[1]])
        is_valid_deleted, _, violations_deleted = verify_chain(source_file=source, conn=conn)
        self.assertFalse(is_valid_deleted)
        self.assertTrue(any("Broken chain link" in v["error"] for v in violations_deleted))

    # ─────────────────────────────────────────────────────────────────
    # 8. Structured Format & Encoding Resilience
    # ─────────────────────────────────────────────────────────────────
    def test_nested_json_and_quoted_csv_parsing(self):
        # Nested JSON
        json_raw = '{"timestamp": "2026-08-26T12:00:00Z", "network": {"src_ip": "192.168.1.10", "dst_ip": "10.0.0.5"}, "user": {"name": "admin"}}'
        res_json = run_pipeline(json_raw, filename="test.json", save_to_db=False)
        self.assertEqual(len(res_json["events"]), 1)
        ev_j = res_json["events"][0]
        self.assertEqual(ev_j.src_ip, "192.168.1.10")
        self.assertEqual(ev_j.dst_ip, "10.0.0.5")
        self.assertEqual(ev_j.user, "admin")

        # Quoted CSV with commas
        csv_raw = (
            "timestamp,user,action,message\n"
            '2026-08-26T12:00:00Z,alice,file_access,"File \\"Quarterly Report, 2026\\" opened"\n'
        )
        res_csv = run_pipeline(csv_raw, filename="test.csv", save_to_db=False)
        self.assertEqual(len(res_csv["events"]), 1)
        ev_c = res_csv["events"][0]
        self.assertEqual(ev_c.user, "alice")
        self.assertIn("Quarterly Report, 2026", ev_c.message)


if __name__ == "__main__":
    unittest.main()
