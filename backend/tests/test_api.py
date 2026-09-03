"""
Unit tests for API functions and handlers in ULPF.
"""

import os
import tempfile
import unittest
from pathlib import Path

from app.api.analytics import get_anomalies, get_database_stats
from app.api.ingest import TextUploadRequest, upload_log_json
from app.api.mappings import MappingSuggestRequest, get_mappings, suggest_mapping
from app.api.sources import RegisterSourceRequest, get_sources, register_new_source
from app.main import health_check
from app.storage.db import get_db


class TestAPI(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.TemporaryDirectory()
        cls.db_path = Path(cls.temp_dir.name) / "test_api.duckdb"
        os.environ["ULPF_DB_PATH"] = str(cls.db_path)
        get_db(cls.db_path)

    @classmethod
    def tearDownClass(cls):
        os.environ.pop("ULPF_DB_PATH", None)
        cls.temp_dir.cleanup()

    def test_health_check(self):
        res = health_check()
        self.assertEqual(res["status"], "ok")

    def test_upload_json(self):
        payload = TextUploadRequest(
            raw_text='{"timestamp": "2026-08-26T12:00:00Z", "src_ip": "172.16.1.100", "user": "test_user", "severity": "medium", "message": "Test event"}',
            source_file="unit_test.json"
        )
        res = upload_log_json(payload)
        self.assertEqual(res.status, "success")
        self.assertGreaterEqual(res.event_count, 1)
        self.assertEqual(res.detected_format, "json")

    def test_stats_and_anomalies(self):
        stats = get_database_stats()
        self.assertIn("total_normalized_events", stats)

        anomalies = get_anomalies()
        self.assertIn("anomalies_detected", anomalies)

    def test_mappings_and_suggest(self):
        mappings = get_mappings()
        self.assertIn("mappings", mappings)

        suggest = suggest_mapping(MappingSuggestRequest(sample_keys=["client_ip", "user_name", "status"]))
        self.assertEqual(suggest["total_fields"], 3)
        self.assertGreater(suggest["overall_confidence"], 0)


if __name__ == "__main__":
    unittest.main()
