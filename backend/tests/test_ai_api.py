"""
Unit tests for Real ULPF Ollama AI API Endpoints.
Tests:
- GET /api/v1/ai/status and /api/ai/status
- GET /api/v1/ai/metrics and /api/ai/metrics
- GET /api/v1/ai/resolutions and /api/ai/resolutions
- Distinction between AI USED, AI AVAILABLE, and LEARNED PARSER
- Error handling when Ollama is unavailable
"""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from app.ai.telemetry import (
    check_ollama_status,
    get_real_ai_metrics,
    get_recent_ai_resolutions,
    record_ai_resolution,
)
from app.main import app
from app.storage.db import get_db


class TestAiApiEndpoints(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.TemporaryDirectory()
        cls.db_path = Path(cls.temp_dir.name) / "test_ai_api.duckdb"
        os.environ["ULPF_DB_PATH"] = str(cls.db_path)
        get_db(cls.db_path)
        cls.client = TestClient(app)

    @classmethod
    def tearDownClass(cls):
        os.environ.pop("ULPF_DB_PATH", None)
        cls.temp_dir.cleanup()

    def test_ai_status_endpoint(self):
        """Verify GET /api/v1/ai/status returns valid schema and status."""
        for endpoint in ["/api/v1/ai/status", "/api/ai/status"]:
            response = self.client.get(endpoint)
            self.assertEqual(response.status_code, 200)
            data = response.json()
            self.assertTrue(data["success"])
            status_data = data["data"]
            self.assertEqual(status_data["provider"], "ollama")
            self.assertIn("model", status_data)
            self.assertIn("status", status_data)
            self.assertIn("available", status_data)
            self.assertIn("air_gap_mode", status_data)
            self.assertIn(status_data["status"], ["CONNECTED", "UNAVAILABLE", "TIMEOUT", "MODEL_NOT_FOUND"])

    def test_ai_metrics_endpoint(self):
        """Verify GET /api/v1/ai/metrics returns observable accumulators."""
        for endpoint in ["/api/v1/ai/metrics", "/api/ai/metrics"]:
            response = self.client.get(endpoint)
            self.assertEqual(response.status_code, 200)
            data = response.json()
            self.assertTrue(data["success"])
            m = data["data"]
            self.assertIn("ollama_calls", m)
            self.assertIn("ollama_successes", m)
            self.assertIn("ollama_failures", m)
            self.assertIn("ollama_timeouts", m)
            self.assertIn("ollama_latency_ms", m)
            self.assertIn("ai_generated_parsers", m)
            self.assertIn("learned_parser_reuses", m)
            self.assertIn("review_required", m)
            self.assertIn("parser_accuracy", m)
            self.assertIn("validation_rate", m)
            self.assertIn("semantic_classification_status", m)

    def test_ai_resolutions_endpoint_and_telemetry_flow(self):
        """Verify recording an event reflects in /api/v1/ai/resolutions."""
        test_fp = "test_fp_telemetry_abc123"
        record_ai_resolution(
            fingerprint=test_fp,
            source="turbine_sensor.log",
            parser_type="ai_generated_dynamic",
            ai_used=True,
            resolution_status="promoted",
            model="qwen3:4b",
            ollama_calls=1,
            latency_ms=1234.5,
            accuracy=99.0,
            confidence=0.98,
            promoted_status="promoted",
            format_name="turbine_kv",
        )

        response = self.client.get("/api/v1/ai/resolutions")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertTrue(data["success"])
        resolutions = data["data"]
        self.assertIsInstance(resolutions, list)
        self.assertGreaterEqual(len(resolutions), 1)

        # Check latest record
        found = [r for r in resolutions if r.get("fingerprint") == test_fp]
        self.assertGreaterEqual(len(found), 1)
        rec = found[0]
        self.assertEqual(rec["source"], "turbine_sensor.log")
        self.assertEqual(rec["ai_used"], True)
        self.assertEqual(rec["ollama_calls"], 1)
        self.assertEqual(rec["accuracy"], 99.0)
        self.assertEqual(rec["confidence"], 0.98)
        self.assertEqual(rec["resolution_status"], "promoted")

    def test_learned_parser_record_distinction(self):
        """Learned parser cache hit must have ai_used=False and ollama_calls=0."""
        cache_fp = "test_fp_learned_cache_hit_456"
        record_ai_resolution(
            fingerprint=cache_fp,
            source="turbine_sensor_reingest.log",
            parser_type="learned_cache",
            ai_used=False,
            resolution_status="cached",
            model="qwen3:4b",
            ollama_calls=0,
            latency_ms=0.0,
            accuracy=99.0,
            confidence=0.98,
            promoted_status="promoted",
            format_name="turbine_kv",
        )

        response = self.client.get("/api/v1/ai/resolutions")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        found = [r for r in data["data"] if r.get("fingerprint") == cache_fp]
        self.assertGreaterEqual(len(found), 1)
        rec = found[0]
        self.assertFalse(rec["ai_used"])
        self.assertEqual(rec["ollama_calls"], 0)
        self.assertEqual(rec["parser_type"], "learned_cache")

    @patch("urllib.request.urlopen")
    def test_ollama_unavailable_handling(self, mock_urlopen):
        """Simulate Ollama offline / connection error."""
        import urllib.error
        mock_urlopen.side_effect = urllib.error.URLError("Connection refused")
        status = check_ollama_status()
        self.assertEqual(status["status"], "UNAVAILABLE")
        self.assertFalse(status["available"])
        self.assertIn("refused", status["error"].lower())


if __name__ == "__main__":
    unittest.main()
