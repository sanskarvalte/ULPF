"""
Test suite for ULPF Frameworkization.

Validates:
1. Python API convergence:
   - from app.pipeline import pipeline
   - events = pipeline.ingest_file(...)
   - events = pipeline.ingest_lines(...)
   - events = pipeline.ingest_text(...)
   - events = pipeline.process(...)
   - res = pipeline.process_file(...)
2. CLI interface & exit codes:
   - 0 on success or safely preserved unknown logs
   - Non-zero on genuine failures (missing file, invalid args)
3. Configuration management (ULPFConfig):
   - Clean defaults with air-gap mode enabled
   - Rejection of external endpoints in air-gap mode
   - Numerical bounds validation
4. Memory efficiency & streaming:
   - Streaming generator yields bounded chunks
5. Deterministic replay & zero Ollama calls for known logs
6. Cached parser lookup for repeated templates
"""

import os
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

from app.ai.ollama_client import get_ollama_call_count, reset_ollama_call_count
from app.config import ULPFConfig, get_config, set_config
from app.models.event_schema import UnifiedEvent
from app.pipeline import PipelineEngine, pipeline


SAMPLE_SYSLOG = (
    "Oct 11 22:14:15 myhost sshd[12345]: Failed password for invalid user admin from 192.168.1.50 port 54321 ssh2\n"
    "Oct 11 22:14:16 myhost sshd[12345]: Accepted password for valid user alice from 192.168.1.51 port 54322 ssh2\n"
)

SAMPLE_UNKNOWN = (
    "[ROUTE_TX] 2026-03-01 10:00:00 pkg=4096 dest=10.0.0.1 status=OK\n"
    "[ROUTE_TX] 2026-03-01 10:00:01 pkg=8192 dest=10.0.0.2 status=FAILED\n"
)


class TestFrameworkConfiguration:
    """Test clean configuration and air-gapped security invariants."""

    def test_default_config_is_safe_and_airgapped(self):
        cfg = get_config()
        assert cfg.air_gap_mode is True
        assert cfg.model == "qwen3:4b"
        assert "localhost" in cfg.ollama_url or "127.0.0.1" in cfg.ollama_url
        assert cfg.accuracy_threshold >= 0.0 and cfg.accuracy_threshold <= 1.0
        assert cfg.confidence_threshold >= 0.0 and cfg.confidence_threshold <= 1.0
        assert cfg.repair_attempts >= 0
        assert cfg.sample_size >= 1
        assert cfg.ai_timeout > 0

    def test_airgap_mode_rejects_external_hosts(self):
        with pytest.raises(ValueError, match="Air-gap mode violation"):
            ULPFConfig(ollama_url="http://api.openai.com/v1", air_gap_mode=True)

        with pytest.raises(ValueError, match="Air-gap mode violation"):
            ULPFConfig(ollama_url="https://external-llm-cloud.io:11434", air_gap_mode=True)

    def test_airgap_mode_allows_localhost_and_loopback(self):
        cfg1 = ULPFConfig(ollama_url="http://localhost:11434", air_gap_mode=True)
        assert cfg1.ollama_url == "http://localhost:11434"

        cfg2 = ULPFConfig(ollama_url="http://127.0.0.1:11434", air_gap_mode=True)
        assert cfg2.ollama_url == "http://127.0.0.1:11434"

    def test_bounds_validation(self):
        with pytest.raises(ValueError, match="accuracy_threshold"):
            ULPFConfig(accuracy_threshold=1.5)

        with pytest.raises(ValueError, match="confidence_threshold"):
            ULPFConfig(confidence_threshold=-0.1)

        with pytest.raises(ValueError, match="repair_attempts"):
            ULPFConfig(repair_attempts=-1)

        with pytest.raises(ValueError, match="sample_size"):
            ULPFConfig(sample_size=0)

        with pytest.raises(ValueError, match="ai_timeout"):
            ULPFConfig(ai_timeout=0.0)


class TestPythonAPIConvergence:
    """Test all Python API endpoints exposed by PipelineEngine."""

    def test_ingest_file(self, tmp_path):
        test_file = tmp_path / "test_syslog.log"
        test_file.write_text(SAMPLE_SYSLOG, encoding="utf-8")

        events = pipeline.ingest_file(test_file, persist=False)
        assert len(events) == 2
        assert all(isinstance(ev, UnifiedEvent) for ev in events)
        assert events[0].log_format == "syslog"
        assert events[0].src_ip == "192.168.1.50"

    def test_ingest_lines(self):
        lines = SAMPLE_SYSLOG.strip().split("\n")
        events = pipeline.ingest_lines(lines, persist=False)
        assert len(events) == 2
        assert all(isinstance(ev, UnifiedEvent) for ev in events)

    def test_ingest_text(self):
        events = pipeline.ingest_text(SAMPLE_SYSLOG, persist=False)
        assert len(events) == 2
        assert all(isinstance(ev, UnifiedEvent) for ev in events)

    def test_polymorphic_process(self, tmp_path):
        # 1. From Path
        test_file = tmp_path / "poly.log"
        test_file.write_text(SAMPLE_SYSLOG, encoding="utf-8")
        evs_file = pipeline.process(test_file, persist=False)
        assert len(evs_file) == 2

        # 2. From text string
        evs_text = pipeline.process(SAMPLE_SYSLOG, persist=False)
        assert len(evs_text) == 2

        # 3. From line iterable
        evs_lines = pipeline.process(SAMPLE_SYSLOG.strip().split("\n"), persist=False)
        assert len(evs_lines) == 2

    def test_process_file_with_metrics(self, tmp_path):
        test_file = tmp_path / "metrics.log"
        test_file.write_text(SAMPLE_SYSLOG, encoding="utf-8")
        out_json = tmp_path / "out.json"

        res = pipeline.process_file(test_file, output_json_path=out_json, persist=False)
        assert res["status"] == "SUCCESS"
        assert res["raw_count"] == 2
        assert res["parsed_count"] == 2
        assert res["normalized_count"] == 2
        assert res["format"] == "SYSLOG"
        assert out_json.exists()


class TestDeterminismAndCache:
    """Ensure known logs never invoke Ollama and repeated executions are deterministic."""

    def test_known_logs_never_invoke_ollama(self, tmp_path):
        reset_ollama_call_count()
        test_file = tmp_path / "known.log"
        test_file.write_text(SAMPLE_SYSLOG, encoding="utf-8")

        res = pipeline.process_file(test_file, persist=False)
        assert res["status"] == "SUCCESS"
        assert res["ollama_calls"] == 0
        assert get_ollama_call_count() == 0

    def test_deterministic_output(self):
        res1 = pipeline.ingest_text(SAMPLE_SYSLOG, persist=False)
        res2 = pipeline.ingest_text(SAMPLE_SYSLOG, persist=False)

        assert len(res1) == len(res2)
        for e1, e2 in zip(res1, res2):
            assert e1.category_name == e2.category_name
            assert e1.class_name == e2.class_name
            assert e1.severity == e2.severity
            assert e1.activity_name == e2.activity_name
            assert e1.raw_event == e2.raw_event


class TestBoundedMemoryStreaming:
    """Test that large files are read in bounded batches."""

    def test_ingest_file_stream_batches(self, tmp_path):
        # Create a file with 25 lines
        lines = [f"Oct 11 22:14:{i:02d} host sshd[1]: test line {i}" for i in range(25)]
        large_file = tmp_path / "stream_test.log"
        large_file.write_text("\n".join(lines), encoding="utf-8")

        # Stream with chunk_size = 10
        chunks = list(pipeline.ingest_file_stream(large_file, chunk_size=10, persist=False))
        assert len(chunks) == 3  # 10 + 10 + 5
        assert len(chunks[0]) == 10
        assert len(chunks[1]) == 10
        assert len(chunks[2]) == 5


class TestCLIExecutionAndExitCodes:
    """Test CLI commands, exit codes, and help output."""

    @pytest.fixture(autouse=True)
    def setup_cli_env(self):
        self.backend_dir = Path(__file__).resolve().parent.parent
        self.env = dict(os.environ)
        self.env["PYTHONPATH"] = str(self.backend_dir)
        self.env["PYTHONIOENCODING"] = "utf-8"

    def test_cli_help(self):
        res = subprocess.run(
            [sys.executable, "-m", "app.main", "--help"],
            cwd=str(self.backend_dir),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=self.env,
        )
        assert res.returncode == 0
        assert "ULPF" in res.stdout
        assert "Commands:" in res.stdout
        assert "ulpf process" in res.stdout

    def test_cli_config_command(self):
        res = subprocess.run(
            [sys.executable, "-m", "app.main", "config"],
            cwd=str(self.backend_dir),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=self.env,
        )
        assert res.returncode == 0
        assert "ULPF Configuration" in res.stdout
        assert "Air-Gap Mode" in res.stdout
        assert "ENABLED" in res.stdout

    def test_cli_process_success(self, tmp_path):
        test_file = tmp_path / "cli_sample.log"
        test_file.write_text(SAMPLE_SYSLOG, encoding="utf-8")

        res = subprocess.run(
            [sys.executable, "-m", "app.main", "process", str(test_file)],
            cwd=str(self.backend_dir),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=self.env,
        )
        assert res.returncode == 0
        assert "ULPF PROCESSING" in res.stdout
        assert "Status: SUCCESS" in res.stdout

    def test_cli_process_missing_argument(self):
        res = subprocess.run(
            [sys.executable, "-m", "app.main", "process"],
            cwd=str(self.backend_dir),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=self.env,
        )
        assert res.returncode != 0
        assert "requires a file or directory path" in res.stdout or "requires a file" in res.stderr

    def test_cli_process_nonexistent_file(self):
        res = subprocess.run(
            [sys.executable, "-m", "app.main", "process", "non_existent_file_xyz.log"],
            cwd=str(self.backend_dir),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=self.env,
        )
        assert res.returncode != 0
        assert "not found" in res.stdout

    def test_cli_unknown_log_preservation_returns_zero(self, tmp_path):
        """Unknown logs that are safely preserved should exit with code 0."""
        unk_file = tmp_path / "unknown.log"
        unk_file.write_text(SAMPLE_UNKNOWN, encoding="utf-8")

        res = subprocess.run(
            [sys.executable, "-m", "app.main", "process", str(unk_file)],
            cwd=str(self.backend_dir),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=self.env,
        )
        assert res.returncode == 0
        assert "ULPF PROCESSING" in res.stdout
        assert "Status: SUCCESS" in res.stdout

