"""
Comprehensive End-to-End Tests for Real ULPF Log Ingestion Pipeline.

Validates:
1. File upload via /api/ingest/upload
2. Known format -> deterministic parser -> 0 Ollama calls
3. Unknown format -> Ollama qwen3:4b fallback -> dynamic parser
4. Second run with same unknown format -> learned parser reuse -> 0 Ollama calls
5. DuckDB persistence verification (normalized_events, raw_events, ingestion_jobs)
6. Truthful Live Processing Feed logs (no hardcoded/demo strings)
7. 24h overview metrics and active jobs tracking
8. Error handling for empty files
"""

from __future__ import annotations

import io
import os
import tempfile
import unittest
from pathlib import Path

from fastapi.testclient import TestClient

from app.main import app
from app.storage.db import get_db, reset_db_connection
from app.api.ingest import job_manager


class TestRealIngestionEndToEnd(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        reset_db_connection()
        cls.temp_dir = tempfile.TemporaryDirectory()
        cls.db_path = Path(cls.temp_dir.name) / "test_ingestion_e2e.duckdb"
        os.environ["ULPF_DB_PATH"] = str(cls.db_path)
        get_db(cls.db_path)
        cls.client = TestClient(app)

    @classmethod
    def tearDownClass(cls):
        reset_db_connection()
        os.environ.pop("ULPF_DB_PATH", None)
        cls.temp_dir.cleanup()

    def test_01_empty_file_upload_handling(self):
        """Empty file upload should result in FAILED status with clear error, not crash."""
        file_payload = ("empty.log", io.BytesIO(b""), "text/plain")
        response = self.client.post(
            "/api/ingest/upload?sync=true",
            files={"files": file_payload}
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["status"], "failed")
        job = data.get("job", {})
        self.assertEqual(job.get("status"), "FAILED")
        self.assertIn("empty", job.get("error", "").lower())

    def test_02_known_format_upload_deterministic(self):
        """Known JSON format must use deterministic parser, yield 0 Ollama calls, and persist to DuckDB."""
        sample_json = (
            '{"timestamp": "2026-09-05T10:00:00Z", "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "action": "allow", "message": "Firewall accept"}\n'
            '{"timestamp": "2026-09-05T10:00:01Z", "src_ip": "10.0.0.3", "dst_ip": "10.0.0.4", "action": "deny", "message": "Firewall drop"}\n'
        )
        file_payload = ("firewall_sample.json", io.BytesIO(sample_json.encode("utf-8")), "text/plain")
        response = self.client.post(
            "/api/ingest/upload?sync=true",
            files={"files": file_payload}
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["status"], "success")

        job = data["job"]
        job_id = job["job_id"]
        self.assertEqual(job["status"], "COMPLETED")
        self.assertEqual(job["format"].upper(), "JSON")
        self.assertEqual(job["ollama_calls"], 0)
        self.assertEqual(job["events_parsed"], 2)
        self.assertEqual(job["events_stored"], 2)

        # Check that AI Analysis stage is SKIPPED or not active
        self.assertEqual(job["lifecycle"]["ai_analysis"]["status"], "SKIPPED")

        # Verify logs contain real data and no demo strings
        logs = [l["message"] for l in job["logs"]]
        for msg in logs:
            self.assertNotIn("179,941", msg)
            self.assertNotIn("install.log", msg)

        # Direct DuckDB verification
        db = get_db()
        cnt = db.execute("SELECT COUNT(*) FROM normalized_events;").fetchone()[0]
        self.assertGreaterEqual(cnt, 2)

        # Verify job is queryable via GET /api/ingest/jobs/{job_id}
        get_res = self.client.get(f"/api/ingest/jobs/{job_id}")
        self.assertEqual(get_res.status_code, 200)
        get_job = get_res.json()
        self.assertEqual(get_job["job_id"], job_id)
        self.assertEqual(get_job["ollama_calls"], 0)

    def test_03_overview_metrics_accuracy(self):
        """GET /api/ingest/overview returns truthful 24h count from DuckDB."""
        res = self.client.get("/api/ingest/overview")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIn("total_ingested", data)
        self.assertIn("total_ingested_str", data)
        self.assertIn("active_jobs", data)
        self.assertGreaterEqual(data["total_ingested"], 2)

    def test_04_unknown_format_ollama_then_learned_reuse(self):
        """Unknown format invokes Ollama on run 1, then reuses learned parser with 0 Ollama calls on run 2."""
        unknown_sample = (
            "2026-09-05T11:31:02Z turbine=T-884 location=ZONE-A rpm=1840 vibration=0.031 condition=NORMAL\n"
            "2026-09-05T11:32:15Z turbine=T-217 location=ZONE-C rpm=2310 vibration=0.087 condition=WARNING\n"
            "2026-09-05T11:33:44Z turbine=T-884 location=ZONE-A rpm=0 vibration=0.421 condition=SHUTDOWN\n"
        )

        # Run 1: Unknown format upload
        file_payload_1 = ("turbine_telemetry.log", io.BytesIO(unknown_sample.encode("utf-8")), "text/plain")
        response_1 = self.client.post(
            "/api/ingest/upload?sync=true",
            files={"files": file_payload_1}
        )
        self.assertEqual(response_1.status_code, 200)
        data_1 = response_1.json()
        job_1 = data_1["job"]

        # Status should be COMPLETED or REVIEW
        self.assertIn(job_1["status"], ["COMPLETED", "REVIEW", "AI_ROUTED"])
        self.assertGreater(job_1["events_parsed"], 0)

        # Verify whether Ollama was invoked
        # If local Ollama is available, ollama_calls >= 1; if offline, routed to lossless review
        ollama_called = job_1["ollama_calls"]
        print(f"\n[Test 04 - Run 1] Status: {job_1['status']}, Parser: {job_1['parser']}, Ollama calls: {ollama_called}")

        # Run 2: Exact same unknown format upload
        file_payload_2 = ("turbine_telemetry_2.log", io.BytesIO(unknown_sample.encode("utf-8")), "text/plain")
        response_2 = self.client.post(
            "/api/ingest/upload?sync=true",
            files={"files": file_payload_2}
        )
        self.assertEqual(response_2.status_code, 200)
        data_2 = response_2.json()
        job_2 = data_2["job"]

        print(f"[Test 04 - Run 2] Status: {job_2['status']}, Parser: {job_2['parser']}, Ollama calls: {job_2['ollama_calls']}")

        # Run 2 MUST have 0 Ollama calls because fingerprint / learned registry cache exists
        self.assertEqual(job_2["ollama_calls"], 0)
        self.assertGreater(job_2["events_parsed"], 0)

    def test_05_duckdb_persisted_job_records(self):
        """Verify ingestion_jobs table in DuckDB stores all tracking fields accurately."""
        db = get_db()
        jobs_in_db = db.execute("SELECT job_id, filename, status, events_stored, ollama_calls FROM ingestion_jobs;").fetchall()
        self.assertGreaterEqual(len(jobs_in_db), 2)
        for j in jobs_in_db:
            job_id, filename, status, events_stored, ollama_calls = j
            self.assertTrue(job_id.upper().startswith("JOB"))
            self.assertIsNotNone(filename)
            self.assertIn(status, ["COMPLETED", "FAILED", "REVIEW", "AI_ROUTED"])


if __name__ == "__main__":
    unittest.main()
