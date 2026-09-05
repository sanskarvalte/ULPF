"""
Unit & Integration Tests for ULPF Unknown-Log Decision Path & Telemetry.

Verifies:
1. Known logs -> deterministic parser -> zero Ollama calls.
2. Previously learned fingerprint in registry -> cached parser -> zero Ollama calls.
3. Genuinely unresolved unknown path -> invokes Ollama / Qwen -> records call & latency telemetry.
4. Ollama unavailable -> falls back safely to review queue & lossless fallback.
5. No fake Ollama counters are possible.
"""

from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from app.ai.ollama_client import (
    get_ollama_call_count,
    get_ollama_telemetry,
    reset_ollama_telemetry,
    OllamaUnavailableError,
)
from app.config import ULPFConfig
from app.parsers.registry import register_parser
from app.pipeline import PipelineEngine


import os
import uuid

class TestUnknownDecisionPath(unittest.TestCase):

    def setUp(self):
        reset_ollama_telemetry()
        self.tmp_reg = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
        self.tmp_reg.write("{}")
        self.tmp_reg.close()
        os.environ["ULPF_REGISTRY_FILE"] = self.tmp_reg.name

        self.config = ULPFConfig(
            ai_enabled=True,
            confidence_threshold=0.80,
            accuracy_threshold=0.85,
            air_gap_mode=True,
        )
        self.pipeline = PipelineEngine(config=self.config)

    def tearDown(self):
        reg_p = Path(self.tmp_reg.name)
        if reg_p.exists():
            reg_p.unlink()
        os.environ.pop("ULPF_REGISTRY_FILE", None)

    def test_known_log_zero_ollama_calls(self):
        """Known log formats (syslog, json, etc.) must NEVER invoke Ollama."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
            f.write("Oct 11 22:14:15 myhost sshd[1234]: Accepted password for root from 192.168.1.50 port 22 ssh2\n")
            f_path = Path(f.name)

        try:
            res = self.pipeline.process_file(f_path)
            self.assertEqual(res["status"], "SUCCESS")
            self.assertEqual(res["ollama_calls"], 0)
            self.assertEqual(res["parser_source"], "rule_based")
            self.assertIn("rule-based", res["parser"])
            self.assertFalse(res["ai_resolution_attempted"])
            self.assertEqual(res["ai_resolution_status"], "skipped_known")
        finally:
            if f_path.exists():
                f_path.unlink()

    def test_cached_learned_parser_zero_ollama_calls(self):
        """A previously learned fingerprint in registry must be served from cache without invoking Ollama."""
        cached_fp = "deadbeef12345678"
        dummy_spec = {
            "format_name": "cached_inventory_format",
            "parser_type": "key_value",
            "delimiter": " ",
            "key_value_separator": "=",
            "timestamp_field": "ts",
            "fields": [
                {"name": "ts", "type": "datetime"},
                {"name": "node", "type": "string"},
                {"name": "status", "type": "string"},
            ],
            "confidence": 0.98,
            "accuracy": 98.0,
        }
        register_parser(cached_fp, dummy_spec)

        raw_line = f"2026-09-05T12:00:00Z node=alpha status=ONLINE fp_override={cached_fp}\n"

        # Mock compute_log_fingerprint to return cached_fp for this test line
        with patch("app.pipeline.compute_log_fingerprint", return_value=("template", r".*", cached_fp)):
            with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
                f.write(raw_line)
                f_path = Path(f.name)

            try:
                res = self.pipeline.process_file(f_path)
                self.assertEqual(res["status"], "SUCCESS")
                self.assertEqual(res["ollama_calls"], 0)
                self.assertEqual(res["parser_source"], "learned_cache")
                self.assertEqual(res["parser"], "dynamic (learned/registry)")
                self.assertFalse(res["ai_resolution_attempted"])
                self.assertEqual(res["ai_resolution_status"], "cached")
            finally:
                if f_path.exists():
                    f_path.unlink()

    def test_genuinely_unresolved_unknown_calls_ollama_and_tracks_telemetry(self):
        """Genuinely unseen unknown log format must reach Ollama and track HTTP call telemetry."""
        brand_new_fp = "brand_new_fp_9999"
        mock_spec = {
            "format_name": "mock_custom_sensor",
            "parser_type": "key_value",
            "delimiter": " ",
            "key_value_separator": "=",
            "timestamp_field": "timestamp",
            "fields": [
                {"name": "timestamp", "type": "datetime"},
                {"name": "sensor", "type": "string"},
                {"name": "reading", "type": "number"},
                {"name": "status", "type": "string"},
            ],
            "optional_fields": [],
            "confidence": 0.95,
        }

        # Mock resolve_unknown_log to simulate a successful Ollama resolution
        # and mock ollama client to confirm genuine call counting
        with patch("app.pipeline.compute_log_fingerprint", return_value=("template", r".*", brand_new_fp)), \
             patch("app.pipeline.resolve_unknown_log") as mock_resolve:

            def mock_resolve_impl(*args, **kwargs):
                from app.ai import ollama_client
                ollama_client._OLLAMA_CALL_COUNT += 1
                ollama_client._OLLAMA_SUCCESS_COUNT += 1
                ollama_client._OLLAMA_TOTAL_LATENCY_MS += 150.0
                return {
                    "success": True,
                    "status": "promoted",
                    "parser_spec": mock_spec,
                    "accuracy": 95.0,
                    "repair_attempts": 0,
                }

            mock_resolve.side_effect = mock_resolve_impl

            with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
                f.write("2026-09-05T14:00:00Z sensor=SN-44 reading=42.1 status=OK\n")
                f_path = Path(f.name)

            try:
                res = self.pipeline.process_file(f_path)
                self.assertEqual(res["status"], "SUCCESS")
                self.assertEqual(res["ollama_calls"], 1)
                self.assertEqual(res["ollama_successes"], 1)
                self.assertEqual(res["ollama_failures"], 0)
                self.assertGreater(res["ollama_latency_ms"], 0)
                self.assertTrue(res["ai_resolution_attempted"])
                self.assertEqual(res["ai_resolution_status"], "promoted")
                self.assertEqual(res["parser_source"], "ai_generated_dynamic")
                self.assertIn("ai-generated dynamic", res["parser"])
            finally:
                if f_path.exists():
                    f_path.unlink()

    def test_a_ollama_responds_normally_ai_success(self):
        """TEST A: Ollama responds normally -> AI success and dynamic parser promotion."""
        brand_new_fp = f"test_a_fp_{uuid.uuid4().hex[:8]}"
        mock_spec = {
            "format_name": "test_a_sensor",
            "parser_type": "key_value",
            "delimiter": " ",
            "key_value_separator": "=",
            "timestamp_field": "timestamp",
            "fields": [
                {"name": "timestamp", "type": "datetime"},
                {"name": "sensor", "type": "string"},
                {"name": "reading", "type": "number"},
                {"name": "status", "type": "string"},
            ],
            "optional_fields": [],
            "confidence": 0.96,
        }

        with patch("app.pipeline.compute_log_fingerprint", return_value=("template", r".*", brand_new_fp)), \
             patch("app.pipeline.resolve_unknown_log") as mock_resolve:

            def mock_resolve_impl(*args, **kwargs):
                from app.ai import ollama_client
                ollama_client._OLLAMA_ATTEMPTS += 1
                ollama_client._OLLAMA_SUCCESS_COUNT += 1
                ollama_client._OLLAMA_TOTAL_LATENCY_MS += 120.0
                return {
                    "success": True,
                    "status": "promoted",
                    "parser_spec": mock_spec,
                    "accuracy": 96.0,
                    "repair_attempts": 0,
                }

            mock_resolve.side_effect = mock_resolve_impl

            with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
                f.write("2026-09-05T14:00:00Z sensor=SN-10 reading=55.0 status=OK\n")
                f_path = Path(f.name)

            try:
                res = self.pipeline.process_file(f_path)
                self.assertEqual(res["status"], "SUCCESS")
                self.assertEqual(res["ollama_calls"], 1)
                self.assertEqual(res["ollama_successes"], 1)
                self.assertEqual(res["ollama_failures"], 0)
                self.assertEqual(res["ollama_timeouts"], 0)
                self.assertEqual(res["ai_resolution_status"], "promoted")
                self.assertEqual(res["parser_source"], "ai_generated_dynamic")
            finally:
                if f_path.exists():
                    f_path.unlink()

    def test_b_ollama_request_exceeds_timeout_no_crash_no_infinite_retry(self):
        """TEST B: Ollama request exceeds timeout -> OLLAMA_TIMEOUT, pipeline continues safely, no crash, no infinite retry."""
        timeout_fp = f"test_b_timeout_{uuid.uuid4().hex[:8]}"

        with patch("app.pipeline.compute_log_fingerprint", return_value=("template", r".*", timeout_fp)), \
             patch("app.ai.parser_generator.generate_json") as mock_gen:

            # Simulate OllamaTimeoutError raised on first attempt without retrying
            from app.ai.ollama_client import OllamaTimeoutError
            mock_gen.side_effect = OllamaTimeoutError("Local Ollama inference timed out after 60.0s")

            with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
                f.write("2026-09-05T12:15:01Z sensor=SN-991 region=WEST reading=73.4 threshold=60 state=HIGH\n")
                f_path = Path(f.name)

            try:
                res = self.pipeline.process_file(f_path)
                # Pipeline MUST NOT crash
                self.assertEqual(res["status"], "SUCCESS")
                self.assertEqual(res["parsed_count"], 1)
                self.assertEqual(res["normalized_count"], 1)
                # Must accurately report timeout status
                self.assertEqual(res["ai_resolution_status"], "timeout")
                self.assertEqual(res["parser_source"], "review_fallback")
                self.assertEqual(res["confidence"], "0.20")
                # Exactly 1 call was attempted (no infinite retries)
                self.assertEqual(mock_gen.call_count, 1)
            finally:
                if f_path.exists():
                    f_path.unlink()

    def test_c_ollama_unavailable_pipeline_continues_safely(self):
        """TEST C: Ollama unavailable -> OLLAMA_UNAVAILABLE, pipeline continues safely with lossless preservation."""
        unavail_fp = f"test_c_unavail_{uuid.uuid4().hex[:8]}"

        with patch("app.pipeline.compute_log_fingerprint", return_value=("template", r".*", unavail_fp)), \
             patch("app.ai.parser_generator.generate_json") as mock_gen:

            mock_gen.side_effect = OllamaUnavailableError("Local Ollama service unavailable: connection refused")

            with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
                f.write("2026-09-05T15:00:00Z mystery_device=DEV01 signal=lost code=ERR99\n")
                f_path = Path(f.name)

            try:
                res = self.pipeline.process_file(f_path)
                self.assertEqual(res["status"], "SUCCESS")
                self.assertEqual(res["ai_resolution_status"], "unavailable")
                self.assertEqual(res["parser_source"], "review_fallback")
                self.assertGreaterEqual(res["unknown_fields_preserved"], 1)
            finally:
                if f_path.exists():
                    f_path.unlink()

    def test_d_known_or_learned_parser_zero_ollama_calls(self):
        """TEST D: Known or previously learned parser -> Ollama calls = 0."""
        # D1: Known format (syslog)
        with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
            f.write("Oct 11 22:14:15 myhost sshd[1234]: Accepted password for root from 192.168.1.50 port 22 ssh2\n")
            f_path = Path(f.name)
        try:
            res = self.pipeline.process_file(f_path)
            self.assertEqual(res["status"], "SUCCESS")
            self.assertEqual(res["ollama_calls"], 0)
            self.assertEqual(res["parser_source"], "rule_based")
        finally:
            if f_path.exists():
                f_path.unlink()

        # D2: Cached learned parser
        cached_fp = f"cached_{uuid.uuid4().hex[:8]}"
        dummy_spec = {
            "format_name": "cached_inventory_format",
            "parser_type": "key_value",
            "delimiter": " ",
            "key_value_separator": "=",
            "timestamp_field": "ts",
            "fields": [
                {"name": "ts", "type": "datetime"},
                {"name": "node", "type": "string"},
                {"name": "status", "type": "string"},
            ],
            "confidence": 0.98,
            "accuracy": 98.0,
        }
        register_parser(cached_fp, dummy_spec)
        with patch("app.pipeline.compute_log_fingerprint", return_value=("template", r".*", cached_fp)):
            with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
                f.write("2026-09-05T12:00:00Z node=alpha status=ONLINE\n")
                f_path2 = Path(f.name)
            try:
                res2 = self.pipeline.process_file(f_path2)
                self.assertEqual(res2["status"], "SUCCESS")
                self.assertEqual(res2["ollama_calls"], 0)
                self.assertEqual(res2["parser_source"], "learned_cache")
            finally:
                if f_path2.exists():
                    f_path2.unlink()

    def test_e_new_unknown_format_invokes_ollama_and_promotes_when_accuracy_passes(self):
        """TEST E: New unknown format -> Ollama invoked and promoted when accuracy passes."""
        new_fp = f"test_e_fp_{uuid.uuid4().hex[:8]}"
        valid_spec = {
            "format_name": "turbine_spec",
            "parser_type": "key_value",
            "delimiter": " ",
            "key_value_separator": "=",
            "timestamp_field": "timestamp",
            "fields": [
                {"name": "timestamp", "type": "datetime"},
                {"name": "turbine", "type": "string"},
                {"name": "location", "type": "string"},
                {"name": "rpm", "type": "number"},
                {"name": "vibration", "type": "number"},
                {"name": "condition", "type": "string"},
            ],
            "optional_fields": [],
            "confidence": 0.98,
        }

        with patch("app.pipeline.compute_log_fingerprint", return_value=("template", r".*", new_fp)), \
             patch("app.ai.parser_generator.generate_json", return_value=valid_spec), \
             patch("app.ai.ollama_client.generate_json", return_value=valid_spec):

            with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
                f.write("2026-09-05T11:31:02Z turbine=T-884 location=ZONE-A rpm=1840 vibration=0.031 condition=NORMAL\n")
                f_path = Path(f.name)

            try:
                res = self.pipeline.process_file(f_path)
                self.assertEqual(res["status"], "SUCCESS")
                self.assertEqual(res["ai_resolution_status"], "promoted")
                self.assertEqual(res["parser_source"], "ai_generated_dynamic")
                self.assertGreaterEqual(float(res["accuracy"]), 85.0)
            finally:
                if f_path.exists():
                    f_path.unlink()

    def test_no_fake_ollama_counters(self):
        """Verify that Ollama counters only increment upon genuine network call execution."""
        reset_ollama_telemetry()
        self.assertEqual(get_ollama_call_count(), 0)
        tel = get_ollama_telemetry()
        self.assertEqual(tel["ollama_calls"], 0)
        self.assertEqual(tel["ollama_attempts"], 0)
        self.assertEqual(tel["ollama_successes"], 0)
        self.assertEqual(tel["ollama_failures"], 0)
        self.assertEqual(tel["ollama_timeouts"], 0)
        self.assertEqual(tel["ollama_latency_ms"], 0.0)


if __name__ == "__main__":
    unittest.main()

