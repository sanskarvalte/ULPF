"""
Configuration Management for ULPF.
Centralized, validated configuration with safe air-gapped defaults.
Supports environment variables, runtime overrides, and programmatic access.
"""

from __future__ import annotations

import os
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, Optional
from urllib.parse import urlparse


@dataclass
class ULPFConfig:
    """
    Core framework configuration settings.
    Default settings enforce strict air-gapped, offline security.
    """
    # LLM and AI Settings
    model: str = field(default_factory=lambda: os.getenv("ULPF_MODEL", os.getenv("ULPF_OLLAMA_MODEL", "qwen3:4b")))
    ollama_url: str = field(default_factory=lambda: os.getenv("ULPF_OLLAMA_URL", os.getenv("ULPF_OLLAMA_HOST", "http://localhost:11434")))
    ai_enabled: bool = field(default_factory=lambda: os.getenv("ULPF_AI_ENABLED", "true").lower() in ("1", "true", "yes", "on"))
    ai_timeout: float = field(default_factory=lambda: float(os.getenv("OLLAMA_TIMEOUT_SECONDS", os.getenv("ULPF_AI_TIMEOUT", os.getenv("ULPF_OLLAMA_TIMEOUT", "60.0")))))
    connect_timeout: float = field(default_factory=lambda: float(os.getenv("OLLAMA_CONNECT_TIMEOUT_SECONDS", "5.0")))
    ai_max_retries: int = field(default_factory=lambda: int(os.getenv("OLLAMA_MAX_RETRIES", "1")))

    # Thresholds & Learning Parameters
    accuracy_threshold: float = field(default_factory=lambda: float(os.getenv("ULPF_ACCURACY_THRESHOLD", "1.00")))
    confidence_threshold: float = field(default_factory=lambda: float(os.getenv("ULPF_CONFIDENCE_THRESHOLD", "0.80")))
    repair_attempts: int = field(default_factory=lambda: int(os.getenv("ULPF_REPAIR_ATTEMPTS", os.getenv("ULPF_OLLAMA_RETRY_COUNT", "2"))))
    sample_size: int = field(default_factory=lambda: int(os.getenv("ULPF_SAMPLE_SIZE", os.getenv("ULPF_OLLAMA_SAMPLE_SIZE", "10"))))

    # Storage & Integrity
    database_path: str = field(default_factory=lambda: os.getenv("ULPF_DATABASE_PATH", os.getenv("ULPF_DB_PATH", "ulpf.duckdb")))

    # Security & Air-Gap Enforcement
    air_gap_mode: bool = field(default_factory=lambda: os.getenv("ULPF_AIR_GAP_MODE", "true").lower() in ("1", "true", "yes", "on"))

    def __post_init__(self):
        self.validate()

    def validate(self) -> None:
        """Validate configuration settings and enforce security invariants."""
        # 1. Enforce Air-Gap Mode
        if self.air_gap_mode:
            parsed = urlparse(self.ollama_url)
            hostname = parsed.hostname or self.ollama_url.split(":")[0].replace("http://", "").replace("https://", "")
            is_local = hostname.lower() in ("localhost", "127.0.0.1", "::1")
            if not is_local:
                raise ValueError(
                    f"Air-gap mode violation: ULPF enforces strictly local, offline execution. "
                    f"External Ollama host '{self.ollama_url}' rejected. Hostname must be localhost or 127.0.0.1."
                )

        # 2. Validate Numerical Bounds
        if not (0.0 <= self.accuracy_threshold <= 1.0):
            raise ValueError(f"accuracy_threshold must be between 0.0 and 1.0, got {self.accuracy_threshold}")
        if not (0.0 <= self.confidence_threshold <= 1.0):
            raise ValueError(f"confidence_threshold must be between 0.0 and 1.0, got {self.confidence_threshold}")
        if self.repair_attempts < 0:
            raise ValueError(f"repair_attempts must be non-negative, got {self.repair_attempts}")
        if not (1 <= self.sample_size <= 1000):
            raise ValueError(f"sample_size must be between 1 and 1000, got {self.sample_size}")
        if self.ai_timeout <= 0:
            raise ValueError(f"ai_timeout must be positive, got {self.ai_timeout}")
        if self.connect_timeout <= 0:
            raise ValueError(f"connect_timeout must be positive, got {self.connect_timeout}")
        if self.ai_max_retries < 0:
            raise ValueError(f"ai_max_retries must be non-negative, got {self.ai_max_retries}")

    def to_dict(self) -> Dict[str, Any]:
        """Return configuration as a dictionary."""
        return asdict(self)


# Singleton instance
_GLOBAL_CONFIG: Optional[ULPFConfig] = None


def get_config() -> ULPFConfig:
    """Retrieve active global ULPF configuration singleton."""
    global _GLOBAL_CONFIG
    if _GLOBAL_CONFIG is None:
        _GLOBAL_CONFIG = ULPFConfig()
    return _GLOBAL_CONFIG


def set_config(config: ULPFConfig) -> None:
    """Explicitly set active global ULPF configuration singleton."""
    global _GLOBAL_CONFIG
    config.validate()
    _GLOBAL_CONFIG = config
