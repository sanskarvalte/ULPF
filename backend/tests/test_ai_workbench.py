"""
Unit and Integration Tests for AI Log Intelligence Workbench.
Tests field discovery, template inference, parser generation, validation,
and end-to-end API approval and dynamic runtime registration into ULPF pipeline.
"""

import os
import tempfile
import unittest
from pathlib import Path

from app.ai.workbench_engine import (
    discover_fields_from_log,
    infer_template_from_log,
    generate_parser_configuration,
    validate_proposed_parser,
    analyze_unknown_log,
)
from app.api.ai_workbench import (
    AnalyzeLogRequest,
    ApproveParserRequest,
    RejectParserRequest,
    ValidateParserRequest,
    analyze_log,
    approve_parser,
    get_ai_history,
    get_ai_stats,
    get_unknown_log,
    list_unknown_logs,
    reject_parser,
    run_batch_analysis,
    validate_parser,
)
from app.ingestion.detector import detect_format
from app.pipeline import pipeline
from app.storage.db import get_db


class TestAIWorkbench(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.TemporaryDirectory()
        cls.db_path = Path(cls.temp_dir.name) / "test_ai.duckdb"
        os.environ["ULPF_DB_PATH"] = str(cls.db_path)
        get_db(cls.db_path)

    @classmethod
    def tearDownClass(cls):
        os.environ.pop("ULPF_DB_PATH", None)
        cls.temp_dir.cleanup()

    def setUp(self):
        from app.ingestion.detector import matcher_registry
        self._orig_entries = list(matcher_registry._entries)
        self.juniper_sample = (
            "<14>Oct 27 08:14:22 fw-core-01 RT_FLOW: RT_FLOW_SESSION_CREATE: session created 192.168.1.100/54321->10.0.0.5/443 junos-https\n"
            "<14>Oct 27 08:14:25 fw-core-01 RT_FLOW: RT_FLOW_SESSION_CLOSE: session closed TCP RST: 192.168.1.100/54321->10.0.0.5/443 junos-https"
        )
        self.pipe_sample = (
            "2026-08-27T02:14:15Z|AUTH-SVC|WARN|jdoe|203.0.113.5|LOGIN_FAILED|3|invalid_credentials\n"
            "2026-08-27T02:14:20Z|AUTH-SVC|INFO|admin|10.20.30.40|LOGIN_SUCCESS|1|mfa_verified"
        )

    def tearDown(self):
        from app.ingestion.detector import matcher_registry
        matcher_registry._entries = list(self._orig_entries)

    def test_engine_field_discovery(self):
        fields = discover_fields_from_log(self.juniper_sample)
        self.assertGreater(len(fields), 0)
        field_names = [f["name"] for f in fields]
        field_types = {f["name"]: f["type"] for f in fields}

        self.assertIn("timestamp", field_names)
        self.assertEqual(field_types["timestamp"], "DATETIME")
        self.assertIn("src_ip", field_names)
        self.assertEqual(field_types["src_ip"], "IPV4")

    def test_engine_template_inference(self):
        fields = discover_fields_from_log(self.juniper_sample)
        fmt_name, grok_pattern, regex = infer_template_from_log(self.juniper_sample, fields)
        self.assertTrue(len(grok_pattern) > 0)
        self.assertTrue(len(regex) > 0)
        self.assertIn("juniper", fmt_name.lower())

    def test_engine_validation(self):
        analysis = analyze_unknown_log(self.juniper_sample, source="test-source")
        self.assertIn("format_name", analysis)
        self.assertGreaterEqual(analysis["confidence_percent"], 70)
        self.assertIn("suggested_parser_yaml", analysis)

        val = analysis["validation_result"]
        self.assertEqual(val["status"], "PASS")
        self.assertEqual(val["matched_records"], 2)
        self.assertIsNotNone(val["sample_record"])

    def test_api_stats_endpoint(self):
        data = get_ai_stats()
        self.assertEqual(data["ai_engine"], "READY")
        self.assertEqual(data["mode"], "OFFLINE")
        self.assertGreater(data["unknown_formats_count"], 0)

    def test_api_unknown_logs_endpoints(self):
        data = list_unknown_logs()
        self.assertIsInstance(data, list)
        self.assertGreater(len(data), 0)

        first_id = data[0]["id"]
        single = get_unknown_log(first_id)
        self.assertEqual(single["id"], first_id)

    def test_api_analyze_endpoint(self):
        req = AnalyzeLogRequest(raw_log=self.pipe_sample, source="test-pipe-auth")
        data = analyze_log(req)
        self.assertIn("discovered_fields", data)
        self.assertIn("inferred_template", data)
        self.assertIn("suggested_parser_yaml", data)
        self.assertIn("validation_result", data)

    def test_api_validate_parser_endpoint(self):
        pattern = r"^(?P<time>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)\|(?P<service>[^|]+)\|(?P<severity>[^|]+)\|(?P<user>[^|]+)\|(?P<ip>[^|]+)\|(?P<action>[^|]+)\|(?P<code_id>\d+)\|(?P<msg>.*)$"
        req = ValidateParserRequest(
            pattern_regex=pattern,
            sample_log=self.pipe_sample,
            field_mapping={
                "time": "time",
                "ip": "src_endpoint.ip",
                "user": "user.name",
                "action": "activity_name"
            },
            format_name="test-pipe-format"
        )
        val = validate_parser(req)
        self.assertEqual(val["status"], "PASS")
        self.assertEqual(val["matched_records"], 2)

    def test_api_approve_and_live_pipeline_registration(self):
        format_name = "test-live-ai-auth"
        pattern = r"^(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)\|AUTH-SVC\|(?P<severity>\w+)\|(?P<username>\w+)\|(?P<src_ip>\d+\.\d+\.\d+\.\d+)\|(?P<activity>\w+)\|(?P<attempts>\d+)\|(?P<reason>\w+)$"
        mapping = {
            "timestamp": "time",
            "src_ip": "src_endpoint.ip",
            "username": "user.name",
            "activity": "activity_name",
            "reason": "message"
        }

        req = ApproveParserRequest(
            format_name=format_name,
            pattern_regex=pattern,
            field_mapping=mapping,
            approved_by="sec_tester",
            vendor="TestAuthSec",
            product="GateKeeper"
        )
        data = approve_parser(req)
        self.assertEqual(data["status"], "success")
        self.assertIn("registered successfully", data["message"])

        # Test LIVE PIPELINE: newly approved parser must parse matching lines immediately!
        test_line = "2026-08-27T02:14:15Z|AUTH-SVC|WARN|secuser|198.51.100.22|LOGIN_FAILED|5|locked_out"
        detected_fmt, _ = detect_format(test_line)
        self.assertEqual(detected_fmt, format_name)

        events = pipeline.ingest_text(test_line, source_name="test-sec-relay", persist=False)
        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertEqual(event.src_ip, "198.51.100.22")
        self.assertEqual(event.user, "secuser")
        self.assertEqual(event.activity_name, "LOGIN_FAILED")

    def test_api_reject_and_history(self):
        req = RejectParserRequest(
            log_id="test-reject-01",
            reason="Ephemeral debug noise",
            rejected_by="sec_analyst"
        )
        res = reject_parser(req)
        self.assertEqual(res["status"], "success")

        hist = get_ai_history()
        self.assertIsInstance(hist, list)
        self.assertGreater(len(hist), 0)

    def test_api_batch_analysis(self):
        data = run_batch_analysis()
        self.assertEqual(data["status"], "success")
        self.assertGreater(data["total_analyzed"], 0)


if __name__ == "__main__":
    unittest.main()
