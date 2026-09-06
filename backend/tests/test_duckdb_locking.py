"""
Focused tests for DuckDB Windows file-locking, connection lifecycle, and concurrency safety.
Verifies:
A. Normal CLI / database operation
B. Connection is released after operation
C. Repeated CLI processing works
D. API startup does not permanently lock the DB
E. Shutdown releases resources
F. A legitimate lock failure is reported clearly with DatabaseLockError
G. Cross-process concurrent access with retry & serialization
"""

import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

import duckdb
from fastapi.testclient import TestClient

from app.main import app, lifespan
from app.pipeline import PipelineEngine, run_pipeline
from app.storage.db import (
    DatabaseLockError,
    close_db_connection,
    connect_with_retry,
    get_db,
    get_db_connection,
    reset_db_connection,
)
from app.storage.normalized import get_total_events_count


class TestDuckDBLocking(unittest.TestCase):
    """Test suite for DuckDB Windows file-locking and connection lifecycle."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_locking.duckdb"
        reset_db_connection()

    def tearDown(self):
        reset_db_connection()
        try:
            self.temp_dir.cleanup()
        except Exception:
            pass

    def test_a_normal_database_operation(self):
        """A. Normal database operation connects, creates schema, and queries successfully."""
        conn = get_db(self.db_path)
        self.assertIsNotNone(conn)
        row = conn.execute("SELECT COUNT(*) FROM raw_events").fetchone()
        self.assertEqual(row[0], 0)
        reset_db_connection()

    def test_b_connection_released_after_operation(self):
        """B. Connection is released after operation, allowing another connection to open."""
        conn = get_db(self.db_path)
        conn.execute("SELECT 1").fetchone()
        reset_db_connection()

        # Another connection can immediately open read-write without lock error
        conn2 = duckdb.connect(str(self.db_path), read_only=False)
        self.assertIsNotNone(conn2)
        conn2.close()

    def test_c_repeated_pipeline_processing(self):
        """C. Repeated pipeline processing runs without stale lock retention."""
        pipeline = PipelineEngine()
        sample_log = "2026-09-01 10:00:00 [INFO] test event alpha"
        sample_log_2 = "2026-09-01 10:00:01 [WARN] test event beta"

        # Set environment to point to test db
        old_env = os.environ.get("ULPF_DB_PATH")
        os.environ["ULPF_DB_PATH"] = str(self.db_path)
        try:
            res1 = run_pipeline(sample_log, filename="test1.log", save_to_db=True)
            self.assertGreaterEqual(res1["count"], 1)

            # Immediately run second pipeline ingestion
            res2 = run_pipeline(sample_log_2, filename="test2.log", save_to_db=True)
            self.assertGreaterEqual(res2["count"], 1)

            # Verify both were stored in the database
            with get_db_connection(self.db_path, read_only=True) as conn:
                count = conn.execute("SELECT COUNT(*) FROM raw_events").fetchone()[0]
                self.assertGreaterEqual(count, 2)
        finally:
            reset_db_connection()
            if old_env is not None:
                os.environ["ULPF_DB_PATH"] = old_env
            else:
                os.environ.pop("ULPF_DB_PATH", None)

    def test_d_api_startup_does_not_permanently_lock_db(self):
        """D. API startup/lifespan releases startup write lock so DB is not permanently locked while idle."""
        old_env = os.environ.get("ULPF_DB_PATH")
        os.environ["ULPF_DB_PATH"] = str(self.db_path)
        try:
            # Simulate TestClient startup
            with TestClient(app) as client:
                resp = client.get("/health")
                self.assertEqual(resp.status_code, 200)

                # While API client is active, another writer can open because server is idle
                writer_conn = duckdb.connect(str(self.db_path), read_only=False)
                writer_conn.execute("SELECT 1")
                writer_conn.close()
        finally:
            reset_db_connection()
            if old_env is not None:
                os.environ["ULPF_DB_PATH"] = old_env
            else:
                os.environ.pop("ULPF_DB_PATH", None)

    def test_e_shutdown_releases_resources(self):
        """E. API shutdown explicitly cleans up all database resources."""
        old_env = os.environ.get("ULPF_DB_PATH")
        os.environ["ULPF_DB_PATH"] = str(self.db_path)
        try:
            with TestClient(app) as client:
                client.get("/health")

            # After context exit, shutdown hook has run. Verify clean direct file open
            conn = duckdb.connect(str(self.db_path), read_only=False)
            conn.execute("SELECT 1")
            conn.close()
        finally:
            reset_db_connection()
            if old_env is not None:
                os.environ["ULPF_DB_PATH"] = old_env
            else:
                os.environ.pop("ULPF_DB_PATH", None)

    def test_f_legitimate_lock_failure_reported_clearly(self):
        """F. When lock cannot be acquired within timeout, DatabaseLockError is raised clearly with PID."""
        holder_code = f"""
import duckdb, time
c = duckdb.connect(r"{self.db_path}", read_only=False)
print("ACQUIRED", flush=True)
time.sleep(2.0)
c.close()
"""
        proc = subprocess.Popen([sys.executable, "-c", holder_code], stdout=subprocess.PIPE, text=True)
        try:
            line = proc.stdout.readline()
            self.assertIn("ACQUIRED", line)

            # Attempt to connect via connect_with_retry with short timeout (0.2s)
            with self.assertRaises(DatabaseLockError) as ctx:
                connect_with_retry(str(self.db_path), read_only=False, timeout=0.2, retry_interval=0.04)

            err = ctx.exception
            self.assertIn("DuckDB lock conflict", str(err))
            self.assertEqual(err.db_path, str(self.db_path))
            self.assertIsNotNone(err.pid)
            self.assertGreater(err.pid, 0)
        finally:
            proc.kill()
            proc.wait()

    def test_g_subprocess_cross_process_locking_and_retry(self):
        """G. Cross-process test reproducing Windows locking: Process 2 retries and succeeds once Process 1 closes."""
        holder_code = f"""
import duckdb, time
c = duckdb.connect(r"{self.db_path}", read_only=False)
print("ACQUIRED", flush=True)
time.sleep(0.4)
c.close()
print("RELEASED", flush=True)
"""
        proc = subprocess.Popen([sys.executable, "-c", holder_code], stdout=subprocess.PIPE, text=True)
        line = proc.stdout.readline()
        self.assertIn("ACQUIRED", line)

        # In this process, attempt to connect with retry (timeout 3.0s)
        t0 = time.time()
        conn = connect_with_retry(str(self.db_path), read_only=False, timeout=3.0, retry_interval=0.05)
        elapsed = time.time() - t0

        self.assertIsNotNone(conn)
        self.assertGreaterEqual(elapsed, 0.3)  # Had to wait for holder to release
        conn.close()
        proc.wait()
        self.assertEqual(proc.returncode, 0)


if __name__ == "__main__":
    unittest.main()
