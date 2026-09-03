"""
Unit Tests for the 8-Node Pipeline Architecture.
Tests every node independently and end-to-end.
"""

import os
import unittest
from pathlib import Path

# Use in-memory or dedicated test DuckDB
os.environ["ULPF_DB_PATH"] = ":memory:"

from app.ai.fingerprint import compute_log_fingerprint
from app.ingestion.collector import LogCollector
from app.ingestion.detector import load_and_register_all_custom_parsers, match_format, matcher_registry
from app.models.event_schema import UnifiedEvent
from app.normalization.engine import normalize_event
from app.pipeline import PipelineEngine
from app.storage.custom_parsers import list_custom_parsers, save_custom_parser
from app.storage.db import get_db
from app.storage.raw import get_raw_event, hash_raw_log, save_raw_event
from app.storage.review_queue import get_pending_reviews


class TestPipelineNodes(unittest.TestCase):

    def setUp(self):
        self.conn = get_db(":memory:")
        self.pipeline = PipelineEngine(conn=self.conn)

    # ── NODE 1: Log Collector ───────────────────────────────────────────
    def test_node1_collector_text_and_chunking(self):
        raw_text = "Line 1\nLine 2\nLine 3"
        chunks = LogCollector.collect_from_text(raw_text, source_name="test.log")
        self.assertEqual(len(chunks), 3)
        self.assertEqual(chunks[0].raw_text, "Line 1")
        self.assertEqual(chunks[0].source_name, "test.log")

    # ── NODE 2: Raw Storage (Unconditional) ─────────────────────────────
    def test_node2_raw_storage_unconditional(self):
        raw_line = "2026-09-01 08:00:00 totally unparseable garbage raw line @#$%^"
        raw_id = save_raw_event(raw_line, source_file="corrupt.log", conn=self.conn)
        
        expected_hash = hash_raw_log(raw_line)
        self.assertEqual(raw_id, expected_hash)

        saved = get_raw_event(raw_id, conn=self.conn)
        self.assertIsNotNone(saved)
        self.assertEqual(saved["raw_text"], raw_line)
        self.assertEqual(saved["source_file"], "corrupt.log")

    # ── NODE 3 & 4: Format Matcher (Yes Branch - Rule Parsers) ──────────
    def test_node3_node4_rule_based_parsers_never_touch_ollama(self):
        # 1. CEF
        cef = "CEF:0|SecurityCorp|WAF|1.0|100|SQLi|8|src=10.1.1.1 dst=10.2.2.2 msg=Blocked"
        is_known, fmt, _ = match_format(cef)
        self.assertTrue(is_known)
        self.assertEqual(fmt, "cef")

        # 2. Syslog
        syslog = "<134>Aug 26 12:33:07 fw-edge-01 iptables[4821]: action=drop src=203.0.113.99"
        is_known, fmt, _ = match_format(syslog)
        self.assertTrue(is_known)
        self.assertEqual(fmt, "syslog")

        # 3. JSON
        json_log = '{"src_ip": "1.2.3.4", "user": "admin", "action": "login"}'
        is_known, fmt, _ = match_format(json_log)
        self.assertTrue(is_known)
        self.assertEqual(fmt, "json")

        # Process through pipeline
        events = self.pipeline.ingest_text(cef, source_name="test_cef.log", persist=False)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].log_format, "cef")
        self.assertEqual(events[0].src_ip, "10.1.1.1")

    # ── NODE 5: Ollama AI Assistant (No Branch) ─────────────────────────
    def test_node5_ollama_fallback_and_fingerprinting(self):
        unknown_line_1 = "CUSTOM_SRV [2026-09-01 10:00:00] ip=192.168.50.10 user=jdoe op=file_read status=ok"
        unknown_line_2 = "CUSTOM_SRV [2026-09-01 10:00:05] ip=10.0.0.99 user=asmith op=file_read status=ok"

        # Check format matcher returns False
        is_known, _, _ = match_format(unknown_line_1)
        self.assertFalse(is_known)

        # Check structural fingerprint generates identical hash for same shape
        t1, regex1, fp1 = compute_log_fingerprint(unknown_line_1)
        t2, regex2, fp2 = compute_log_fingerprint(unknown_line_2)
        self.assertEqual(fp1, fp2)
        self.assertEqual(t1, t2)

        # Process first line: emits non-blocking unknown_pending_review
        events = self.pipeline.ingest_text(unknown_line_1, source_name="custom.log", persist=True)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].log_format, "unknown_pending_review")
        self.assertIn("fingerprint", events[0].unmapped)

        # Check review queue has enqueued it
        pending = get_pending_reviews(conn=self.conn)
        self.assertTrue(any(p["fingerprint"] == fp1 for p in pending))

    # ── NODE 6 & 7: Human Review & Dynamic Parser Registration ──────────
    def test_node6_node7_human_review_and_dynamic_parser_registration(self):
        from app.ingestion.detector import register_custom_parser_matcher

        unknown_line = "MY_APP_LOG: timestamp=2026-09-01 src=172.16.1.50 user=alice action=auth_pass"
        t, regex, fp = compute_log_fingerprint(unknown_line)

        # Before approval: Matcher returns unknown (No branch)
        is_known_before, _, _ = match_format(unknown_line)
        self.assertFalse(is_known_before)

        # Simulate Human Approval (Node 6 & 7)
        format_name = "my_app_auth"
        mapping = {
            "src": "src_ip",
            "user": "user",
            "action": "activity_name",
        }

        save_custom_parser(
            format_name=format_name,
            fingerprint=fp,
            pattern_regex=r"MY_APP_LOG:.*",
            field_mapping=mapping,
            approved_by="lead_analyst",
            conn=self.conn,
        )

        register_custom_parser_matcher(
            format_name=format_name,
            pattern_regex=r"MY_APP_LOG:.*",
            field_mapping=mapping,
        )

        # After approval: Matcher returns YES (Yes branch) and skips AI!
        is_known_after, matched_fmt, parser_fn = match_format(unknown_line)
        self.assertTrue(is_known_after)
        self.assertEqual(matched_fmt, format_name)

        # Test parser execution
        parsed = parser_fn(unknown_line)
        norm = normalize_event(parsed)
        self.assertEqual(norm.log_format, format_name)
        self.assertEqual(norm.src_ip, "172.16.1.50")
        self.assertEqual(norm.user, "alice")
        self.assertEqual(norm.activity_name, "auth_pass")

    # ── RESTART PERSISTENCE: Custom Parsers Reload on Startup ───────────
    def test_custom_parser_startup_reload(self):
        # Save a custom parser directly to DB
        save_custom_parser(
            format_name="persisted_daemon",
            fingerprint="fp123456",
            pattern_regex=r"DAEMON_ALERT_99:.*",
            field_mapping={"src_ip": "src_ip"},
            conn=self.conn,
        )

        # Reset in-memory matchers
        matcher_registry._entries = [e for e in matcher_registry._entries if e[0] != "persisted_daemon"]

        # Call startup reload function
        loaded_count = load_and_register_all_custom_parsers(conn=self.conn)
        self.assertGreaterEqual(loaded_count, 1)

        # Verify it is now in active matcher registry
        is_known, matched_fmt, _ = match_format("DAEMON_ALERT_99: host=edge-01 src=10.0.0.1")
        self.assertTrue(is_known)
        self.assertEqual(matched_fmt, "persisted_daemon")

    # ── NODE 8: Unified Normalizer & Losslessness Guard ─────────────────
    def test_node8_losslessness_substring_guard(self):
        # 1. Genuine event: all extracted values are substrings of raw_event
        genuine_raw = "Aug 26 12:00:00 host sshd: user=admin from 192.168.1.10"
        ev_genuine = UnifiedEvent(
            raw_event=genuine_raw,
            src_ip="192.168.1.10",
            user="admin",
            log_format="syslog",
        )
        norm_genuine = normalize_event(ev_genuine)
        self.assertEqual(norm_genuine.src_ip, "192.168.1.10")
        self.assertEqual(norm_genuine.user, "admin")

        # 2. Hallucinated / buggy parser event: IP & User NOT present in raw_event
        hallucinated_raw = "Aug 26 12:00:00 host cron[123]: daily job executed"
        ev_hallucinated = UnifiedEvent(
            raw_event=hallucinated_raw,
            src_ip="10.99.99.99",  # NOT in raw event!
            user="phantom_user",    # NOT in raw event!
            log_format="unknown_pending_review",
        )
        norm_hallucinated = normalize_event(ev_hallucinated)

        # Guard MUST null out fabricated fields and record traceability warnings
        self.assertIsNone(norm_hallucinated.src_ip)
        self.assertIsNone(norm_hallucinated.user)
        self.assertIn("traceability_warnings", norm_hallucinated.unmapped)
        self.assertEqual(len(norm_hallucinated.unmapped["traceability_warnings"]), 2)

    def test_secondary_signature_validation_crosscheck(self):
        from app.ai.confidence import validate_product_signature

        # Case 1: Heroku logfmt line hallucinated as Apache Log4j with high claimed confidence
        heroku_log = 'heroku[router]: at=info method=GET path="/" host=myapp.herokuapp.com fwd="17.17.17.17" dyno=web.1 connect=1ms service=15ms status=200 bytes=652'
        v, p, fmt, conf = validate_product_signature(
            raw_log=heroku_log,
            suggested_vendor="Apache",
            suggested_product="Log4j",
            suggested_format="apache_log4j",
            claimed_confidence=0.9,
        )
        # MUST reject Log4j, classify as logfmt, and clamp/adjust confidence
        self.assertEqual(fmt, "logfmt")
        self.assertNotEqual(p, "Log4j")
        self.assertLessEqual(conf, 0.35)

        # Case 2: Genuine Log4j line
        log4j_log = "2026-09-01 10:00:00 [main] INFO  org.apache.catalina.core.StandardService - Starting service [Tomcat]"
        v2, p2, fmt2, conf2 = validate_product_signature(
            raw_log=log4j_log,
            suggested_vendor="Apache",
            suggested_product="Log4j",
            suggested_format="log4j",
            claimed_confidence=0.9,
        )
        self.assertEqual(p2, "Log4j")
        self.assertEqual(conf2, 0.9)


if __name__ == "__main__":
    unittest.main()
