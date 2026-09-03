"""
Test Suite for 10 Unknown-Format Samples against the 8-Node Pipeline:
Verifies:
1. Format Matcher Stage 3 rejection / routing (#2 & #10 match JSON; #1, #3-#9 return is_known=False).
2. Distinct fingerprinting per format & collision-free grouping of repeat lines.
3. Ollama AI fallback routing, review queue deduplication, and secondary signature validation.
4. Multi-line record boundary chunking for journald & Java stack traces.
"""

import duckdb
import unittest
from typing import List

from app.ai.fingerprint import compute_log_fingerprint
from app.ai.confidence import validate_product_signature
from app.ingestion.collector import LogCollector
from app.ingestion.detector import match_format
from app.pipeline import PipelineEngine
from app.storage.db import get_db
from app.storage.review_queue import get_pending_reviews


SAMPLE_1_LOGFMT = [
    'at=info method=GET path=/api/v1/orders host=api.example.com request_id=8f3e1c2a fwd="203.0.113.5" dyno=web.3 connect=1ms service=18ms status=200 bytes=1024',
    'at=error method=POST path=/api/v1/charge host=api.example.com request_id=8f3e1c2b fwd="203.0.113.6" dyno=web.1 connect=1ms service=340ms status=500 bytes=512 error="upstream timeout"',
    'at=info method=GET path=/api/v1/users host=api.example.com request_id=8f3e1c2c fwd="203.0.113.7" dyno=web.2 connect=2ms service=25ms status=200 bytes=2048',
]

SAMPLE_2_GELF = [
    '{"version":"1.1","host":"web-node-03","short_message":"Database connection pool exhausted","full_message":"HikariPool-1 - Connection is not available, request timed out after 30000ms","timestamp":1756260855.123,"level":3,"_application":"orders-service","_environment":"production","_pool_size":20,"_pool_active":20}'
]

SAMPLE_3_W3C_IIS = [
    "#Software: Microsoft Internet Information Services 10.0\n#Version: 1.0\n#Date: 2026-08-27 02:14:15\n#Fields: date time c-ip cs-username s-ip s-port cs-method cs-uri-stem sc-status time-taken\n2026-08-27 02:14:15 203.0.113.5 - 10.20.30.5 443 GET /api/v1/orders 200 45\n2026-08-27 02:14:16 203.0.113.9 jdoe 10.20.30.5 443 POST /api/v1/login 401 12"
]

SAMPLE_4_APACHE_COMBINED = [
    '203.0.113.5 - - [27/Aug/2026:02:14:15 +0000] "GET /api/v1/orders HTTP/1.1" 200 5324 "https://example.com/dashboard" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"',
    '198.51.100.9 - jdoe [27/Aug/2026:02:14:20 +0000] "POST /api/v1/login HTTP/1.1" 401 512 "-" "curl/8.4.0"',
    '198.51.100.10 - alice [27/Aug/2026:02:14:25 +0000] "GET /api/v1/profile HTTP/1.1" 200 1024 "-" "curl/8.4.0"',
]

SAMPLE_5_JOURNALD = """__CURSOR=s=8f3e1c2a;i=5d3c1;b=9a1b2c3d4e5f;m=1a2b3c;t=61e2f3a4b5c6;x=1
__REALTIME_TIMESTAMP=1756260855123456
_HOSTNAME=web-node-03
_SYSTEMD_UNIT=nginx.service
MESSAGE=worker process 12345 exited on signal 9 (SIGKILL)
PRIORITY=3

__CURSOR=s=8f3e1c2a;i=5d3c2;b=9a1b2c3d4e5f;m=1a2b3d;t=61e2f3a4b5d1;x=2
__REALTIME_TIMESTAMP=1756260856200000
_HOSTNAME=web-node-03
_SYSTEMD_UNIT=nginx.service
MESSAGE=worker process 12346 forked to replace 12345
PRIORITY=6"""

SAMPLE_6_CUSTOM_PIPE = [
    "2026-08-27T02:14:15Z|AUTH-SVC|WARN|jdoe|203.0.113.5|LOGIN_FAILED|3|invalid_credentials",
    "2026-08-27T02:14:20Z|AUTH-SVC|INFO|admin|10.20.30.40|LOGIN_SUCCESS|1|mfa_verified",
    "2026-08-27T02:14:25Z|AUTH-SVC|WARN|asmith|203.0.113.9|LOGIN_FAILED|3|locked_account",
]

SAMPLE_7_JAVA_STACKTRACE = """2026-08-27 02:14:15,003 ERROR [http-nio-8080-exec-4] c.e.orders.PaymentService - Failed to process payment for order ORD-990213
java.lang.NullPointerException: Cannot invoke "com.example.orders.Customer.getPaymentMethod()" because "customer" is null
\tat com.example.orders.PaymentService.charge(PaymentService.java:142)
\tat com.example.orders.OrderController.checkout(OrderController.java:88)
\tat java.base/jdk.internal.reflect.NativeMethodAccessorImpl.invoke0(Native Method)
\tat java.base/jdk.internal.reflect.NativeMethodAccessorImpl.invoke(NativeMethodAccessorImpl.java:62)
Caused by: java.lang.IllegalStateException: Customer lookup returned empty result
\tat com.example.orders.CustomerRepository.findById(CustomerRepository.java:57)
\t... 12 more"""

SAMPLE_8_CUSTOM_DELIMS = [
    "ts:2026-08-27T02:14:15Z;svc:inventory-sync;lvl:WARN;sku:SKU-48213;warehouse:WH-EAST-04;msg:stock level below reorder threshold;qty_on_hand:3;reorder_point:10",
    "ts:2026-08-27T02:14:20Z;svc:inventory-sync;lvl:INFO;sku:SKU-99120;warehouse:WH-WEST-01;msg:stock replenishment initiated;qty_on_hand:100;reorder_point:50",
]

SAMPLE_9_FIXED_WIDTH = [
    "20260827021415AUTH01JDOE      LOGIN   SUCCESS 0000",
    "20260827021420AUTH01ADMIN     LOGOUT  SUCCESS 0000",
    "20260827021425PAYM02SYSTEM    CHARGE  FAILED  1042",
]

SAMPLE_10_GRAPHQL_JSON = [
    '{"traceId":"7f3e1c2a-11b0-4c2e-9a3d-6e7f1b2c3d4e","spanId":"a1b2c3d4","operationName":"CheckoutMutation","duration_ms":842,"errors":[{"message":"Insufficient inventory","path":["checkout","items",2],"extensions":{"code":"INVENTORY_ERROR","sku":"SKU-48213"}}],"variables":{"cartId":"cart_88213"}}'
]


class TestUnknownFormatSamples(unittest.TestCase):
    def setUp(self):
        from app.ai.ollama_detector import _FINGERPRINT_SUGGESTION_CACHE
        _FINGERPRINT_SUGGESTION_CACHE.clear()
        self.conn = get_db(":memory:")
        self.collector = LogCollector()
        self.pipeline = PipelineEngine(conn=self.conn)

    def tearDown(self):
        self.conn.close()

    # ── STEP 1: Format Matcher Rejection & Zero False-Positive Checks ───
    def test_step1_format_matcher_dispatch(self):
        # Samples 2 & 10 are valid JSON and SHOULD match JSON
        is_known_2, fmt_2, _ = match_format(SAMPLE_2_GELF[0])
        self.assertTrue(is_known_2, "GELF should match JSON signature")
        self.assertEqual(fmt_2, "json")

        is_known_10, fmt_10, _ = match_format(SAMPLE_10_GRAPHQL_JSON[0])
        self.assertTrue(is_known_10, "GraphQL JSON should match JSON signature")
        self.assertEqual(fmt_10, "json")

        # Samples 1, 3, 4, 5, 6, 7, 8, 9 MUST return is_known = False
        unknown_checks = [
            ("logfmt", SAMPLE_1_LOGFMT[0]),
            ("w3c_iis_header", "#Fields: date time c-ip cs-username s-ip s-port"),
            ("w3c_iis_row", "2026-08-27 02:14:15 203.0.113.5 - 10.20.30.5 443 GET /api/v1/orders 200 45"),
            ("apache_combined", SAMPLE_4_APACHE_COMBINED[0]),
            ("journald", "__CURSOR=s=8f3e1c2a;i=5d3c1\nMESSAGE=test"),
            ("custom_pipe", SAMPLE_6_CUSTOM_PIPE[0]),
            ("java_stacktrace", SAMPLE_7_JAVA_STACKTRACE.splitlines()[0]),
            ("custom_delims", SAMPLE_8_CUSTOM_DELIMS[0]),
            ("fixed_width", SAMPLE_9_FIXED_WIDTH[0]),
        ]

        for label, line in unknown_checks:
            is_known, matched_fmt, _ = match_format(line)
            self.assertFalse(
                is_known,
                f"Sample '{label}' FALSE-POSITIVE matched as '{matched_fmt}'! Expected rejection to Ollama fallback.",
            )

    # ── STEP 2: Fingerprint Grouping & Distinct Hashes ───────────────────
    def test_step2_fingerprint_distinctness_and_grouping(self):
        # 1. Verify repeat lines of the same format produce the EXACT SAME fingerprint
        _, _, fp_logfmt_1 = compute_log_fingerprint(SAMPLE_1_LOGFMT[0])
        _, _, fp_logfmt_3 = compute_log_fingerprint(SAMPLE_1_LOGFMT[2])
        self.assertEqual(fp_logfmt_1, fp_logfmt_3, "Logfmt lines 1 & 3 must share fingerprint")

        _, _, fp_apache_2 = compute_log_fingerprint(SAMPLE_4_APACHE_COMBINED[1])
        _, _, fp_apache_3 = compute_log_fingerprint(SAMPLE_4_APACHE_COMBINED[2])
        self.assertEqual(fp_apache_2, fp_apache_3, "Apache lines 2 & 3 with user must share fingerprint")

        _, _, fp_pipe_1 = compute_log_fingerprint(SAMPLE_6_CUSTOM_PIPE[0])
        _, _, fp_pipe_2 = compute_log_fingerprint(SAMPLE_6_CUSTOM_PIPE[1])
        _, _, fp_pipe_3 = compute_log_fingerprint(SAMPLE_6_CUSTOM_PIPE[2])
        self.assertEqual(fp_pipe_1, fp_pipe_2, "Custom pipe lines 1 & 2 must share fingerprint")
        self.assertEqual(fp_pipe_2, fp_pipe_3, "Custom pipe lines 2 & 3 must share fingerprint")

        _, _, fp_delim_1 = compute_log_fingerprint(SAMPLE_8_CUSTOM_DELIMS[0])
        _, _, fp_delim_2 = compute_log_fingerprint(SAMPLE_8_CUSTOM_DELIMS[1])
        self.assertEqual(fp_delim_1, fp_delim_2, "Custom delim lines 1 & 2 must share fingerprint")

        _, _, fp_fixed_1 = compute_log_fingerprint(SAMPLE_9_FIXED_WIDTH[0])
        _, _, fp_fixed_2 = compute_log_fingerprint(SAMPLE_9_FIXED_WIDTH[1])
        _, _, fp_fixed_3 = compute_log_fingerprint(SAMPLE_9_FIXED_WIDTH[2])
        self.assertEqual(fp_fixed_1, fp_fixed_2, "Fixed-width lines 1 & 2 must share fingerprint")
        self.assertEqual(fp_fixed_2, fp_fixed_3, "Fixed-width lines 2 & 3 must share fingerprint")

        # 2. Verify all different formats produce DISTINCT fingerprints (NO collisions)
        all_fps = {
            "logfmt": fp_logfmt_1,
            "apache": fp_apache_2,
            "pipe": fp_pipe_1,
            "custom_delims": fp_delim_1,
            "fixed_width": fp_fixed_1,
        }
        self.assertEqual(len(all_fps), len(set(all_fps.values())), "Fingerprint collision detected across different formats!")

    # ── STEP 3: Pipeline Execution & Deduplicated Review Queue ───────────
    def test_step3_pipeline_fallback_and_review_queue(self):
        # Ingest multiple lines from different unknown formats
        feed_lines = (
            SAMPLE_1_LOGFMT
            + SAMPLE_4_APACHE_COMBINED
            + SAMPLE_6_CUSTOM_PIPE
            + SAMPLE_8_CUSTOM_DELIMS
            + SAMPLE_9_FIXED_WIDTH
        )
        total_ingested = "\n".join(feed_lines)

        events = self.pipeline.ingest_text(total_ingested, source_name="heterogeneous_unknown.log", persist=True)
        self.assertEqual(len(events), len(feed_lines))

        # Check all emitted as non-blocking unknown_pending_review
        for ev in events:
            self.assertEqual(ev.log_format, "unknown_pending_review")
            self.assertIn("fingerprint", ev.unmapped)

        # Check Review Queue has deduplicated entries (exactly 5 distinct formats for the 5 sample types)
        pending = get_pending_reviews(conn=self.conn)
        pending_fps = {p["fingerprint"] for p in pending}
        self.assertGreaterEqual(len(pending_fps), 5)

    # ── STEP 4: Multi-Line Record Boundary Chunking ──────────────────────
    def test_step4_multiline_record_boundaries(self):
        # 1. Java Stack Trace: Multiple lines should be collected as ONE cohesive event
        chunks_java = self.collector.collect_from_text(SAMPLE_7_JAVA_STACKTRACE)
        self.assertEqual(len(chunks_java), 1, "Java stack trace was improperly split across multiple events!")
        self.assertIn("NullPointerException", chunks_java[0].raw_text)
        self.assertIn("Caused by:", chunks_java[0].raw_text)

        # 2. Journald export format: Double-newline separated blocks
        chunks_journald = self.collector.collect_from_text(SAMPLE_5_JOURNALD)
        self.assertEqual(len(chunks_journald), 2, "Journald blocks should be partitioned into 2 records")
        self.assertIn("12345", chunks_journald[0].raw_text)
        self.assertIn("12346", chunks_journald[1].raw_text)

    # ── REGRESSION: Inventory Alert Line & Full Attribute Extraction ─────
    def test_inventory_alert_regression(self):
        from app.ai.ollama_detector import process_unmatched_log_with_ai

        inv_line = "ts:2026-08-27T02:14:15Z;svc:inventory-sync;lvl:WARN;sku:SKU-48213;warehouse:WH-EAST-04;msg:stock level below reorder threshold;qty_on_hand:3;reorder_point:10"
        ev = process_unmatched_log_with_ai(inv_line, conn=self.conn)

        # 1. Vendor/Product are null (never Log4j)
        self.assertIsNone(ev.vendor)
        self.assertIsNone(ev.product)
        self.assertNotEqual(ev.product, "Log4j")

        # 2. Timestamp is promoted to top-level without key prefix
        self.assertIsNotNone(ev.timestamp)
        self.assertEqual(ev.timestamp.year, 2026)
        self.assertEqual(ev.timestamp.month, 8)
        self.assertEqual(ev.timestamp.day, 27)

        # 3. service_name (not action) holds 'inventory-sync'
        self.assertEqual(ev.service_name, "inventory-sync")
        self.assertNotEqual(ev.activity_name, "inventory-sync")
        self.assertNotEqual(ev.activity_name, "svc:inventory-sync")

        # 4. No field contains the literal string "null"
        for attr in ("src_ip", "src_port", "dst_ip", "dst_port", "user", "vendor", "product", "activity_name"):
            val = getattr(ev, attr, None)
            self.assertNotEqual(val, "null", f"Field '{attr}' contains literal string 'null'")

        # 5. Message and severity extraction
        self.assertEqual(ev.message, "stock level below reorder threshold")
        self.assertEqual(ev.severity, "Medium")  # WARN -> Medium

        # 6. Structured custom fields preserved in unmapped without data loss
        self.assertIn("sku", ev.unmapped)
        self.assertEqual(ev.unmapped["sku"], "SKU-48213")
        self.assertIn("warehouse", ev.unmapped)
        self.assertEqual(ev.unmapped["warehouse"], "WH-EAST-04")
        self.assertIn("qty_on_hand", ev.unmapped)
        self.assertEqual(ev.unmapped["qty_on_hand"], 3)
        self.assertIn("reorder_point", ev.unmapped)
        self.assertEqual(ev.unmapped["reorder_point"], 10)

    # ── REGRESSION: All 3 False-Log4j Lines Must Reject Log4j Bias ───────
    def test_no_false_log4j_bias(self):
        from app.ai.ollama_detector import process_unmatched_log_with_ai

        lines = [
            'at=info method=GET path=/api/v1/orders host=api.example.com request_id=8f3e1c2a fwd="203.0.113.5" dyno=web.3 connect=1ms service=18ms status=200 bytes=1024',
            'at=error method=POST path=/api/v1/charge host=api.example.com request_id=8f3e1c2b fwd="203.0.113.6" dyno=web.1 connect=1ms service=340ms status=500 bytes=512 error="upstream timeout"',
            'ts:2026-08-27T02:14:15Z;svc:inventory-sync;lvl:WARN;sku:SKU-48213;warehouse:WH-EAST-04;msg:stock level below reorder threshold;qty_on_hand:3;reorder_point:10',
        ]

        for line in lines:
            ev = process_unmatched_log_with_ai(line, conn=self.conn)
            self.assertNotEqual(ev.product, "Log4j", f"Line incorrectly classified as Log4j: {line}")
            self.assertNotEqual(ev.vendor, "Apache Log4j")
            if ev.vendor:
                self.assertNotIn("log4j", ev.vendor.lower())


if __name__ == "__main__":
    unittest.main()
