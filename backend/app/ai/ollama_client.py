"""
Local Ollama client for ULPF AI components.

This module communicates only with the locally running
Ollama service and does not require cloud connectivity.

Optimized for fast, resilient local execution with qwen3:4b:
- think=False by default (bypasses deep reasoning loop that causes multi-minute hangs)
- num_ctx=2048 (bounded context window for fast inference on consumer GPUs/CPUs)
- temperature=0.0
- Configurable inference timeout (OLLAMA_TIMEOUT_SECONDS, default 60.0s)
- Fast socket connect timeout (OLLAMA_CONNECT_TIMEOUT_SECONDS, default 5.0s)
- Bounded retries (timeout failures NEVER retried; at most 1 retry for transient socket errors)
- Strict error classification (SUCCESS, TIMEOUT, UNAVAILABLE, INVALID_RESPONSE, MODEL_NOT_FOUND, CONNECTION_ERROR)
- Truthful observable telemetry (attempts, calls, successes, failures, timeouts, latency_ms)
"""

from __future__ import annotations

import json
import logging
import os
import re
import time
from typing import Any, Dict, Optional

from app.config import get_config

logger = logging.getLogger("ulpf.ai.ollama_client")

# Dynamically resolve defaults from centralized ULPFConfig
DEFAULT_MODEL = get_config().model
DEFAULT_HOST = get_config().ollama_url
DEFAULT_TIMEOUT = get_config().ai_timeout
DEFAULT_SAMPLE_SIZE = get_config().sample_size
DEFAULT_RETRY_COUNT = get_config().repair_attempts
DEFAULT_TEMPERATURE = float(os.environ.get("ULPF_OLLAMA_TEMPERATURE", "0.0"))

# ── Error Classification Constants ──────────────────────────────────
OLLAMA_SUCCESS = "OLLAMA_SUCCESS"
OLLAMA_TIMEOUT = "OLLAMA_TIMEOUT"
OLLAMA_UNAVAILABLE = "OLLAMA_UNAVAILABLE"
OLLAMA_INVALID_RESPONSE = "OLLAMA_INVALID_RESPONSE"
OLLAMA_MODEL_NOT_FOUND = "OLLAMA_MODEL_NOT_FOUND"
OLLAMA_CONNECTION_ERROR = "OLLAMA_CONNECTION_ERROR"


# ── Exception Hierarchy ──────────────────────────────────────────────
class OllamaClientError(RuntimeError):
    """Base exception for Ollama client interactions with error classification."""
    def __init__(self, message: str, error_type: str = OLLAMA_UNAVAILABLE):
        super().__init__(message)
        self.error_type = error_type


class OllamaUnavailableError(OllamaClientError):
    """Raised when the local Ollama service is offline or unreachable."""
    def __init__(self, message: str = "Local Ollama service is unavailable."):
        super().__init__(message, error_type=OLLAMA_UNAVAILABLE)


class OllamaTimeoutError(OllamaUnavailableError):
    """Raised when Ollama request exceeds configured timeout."""
    def __init__(self, message: str = "Ollama request timed out."):
        super().__init__(message)
        self.error_type = OLLAMA_TIMEOUT


class OllamaConnectionError(OllamaUnavailableError):
    """Raised when socket or transport connection fails."""
    def __init__(self, message: str = "Ollama connection error."):
        super().__init__(message)
        self.error_type = OLLAMA_CONNECTION_ERROR


class OllamaModelNotFoundError(OllamaClientError):
    """Raised when requested model is not found in local Ollama."""
    def __init__(self, message: str = "Ollama model not found."):
        super().__init__(message, error_type=OLLAMA_MODEL_NOT_FOUND)


class OllamaInvalidResponseError(OllamaClientError):
    """Raised when Ollama returns non-JSON or malformed payload."""
    def __init__(self, message: str = "Invalid response from Ollama."):
        super().__init__(message, error_type=OLLAMA_INVALID_RESPONSE)


def classify_ollama_error(exc: Exception) -> str:
    """Classify an exception into standard ULPF Ollama error categories."""
    if isinstance(exc, OllamaTimeoutError):
        return OLLAMA_TIMEOUT
    if isinstance(exc, OllamaModelNotFoundError):
        return OLLAMA_MODEL_NOT_FOUND
    if isinstance(exc, OllamaConnectionError):
        return OLLAMA_CONNECTION_ERROR
    if isinstance(exc, OllamaInvalidResponseError):
        return OLLAMA_INVALID_RESPONSE
    if isinstance(exc, OllamaUnavailableError):
        return OLLAMA_UNAVAILABLE

    msg = str(exc).lower()
    if "timeout" in msg or "timed out" in msg:
        return OLLAMA_TIMEOUT
    if "not found" in msg or ("model" in msg and "not found" in msg):
        return OLLAMA_MODEL_NOT_FOUND
    if "refused" in msg or "offline" in msg or "unavailable" in msg:
        return OLLAMA_UNAVAILABLE
    if "connection" in msg or "socket" in msg or "reset" in msg or "transport" in msg:
        return OLLAMA_CONNECTION_ERROR
    if "json" in msg or "parse" in msg:
        return OLLAMA_INVALID_RESPONSE
    return OLLAMA_UNAVAILABLE


# ── Observable Telemetry Counters ────────────────────────────────────
_OLLAMA_ATTEMPTS: int = 0
_OLLAMA_CALL_COUNT: int = 0
_OLLAMA_SUCCESS_COUNT: int = 0
_OLLAMA_FAILURE_COUNT: int = 0
_OLLAMA_TIMEOUT_COUNT: int = 0
_OLLAMA_TOTAL_LATENCY_MS: float = 0.0
_LAST_ERROR_TYPE: str = OLLAMA_SUCCESS


def _validate_local_host(host: str) -> None:
    """Ensure host is strictly local; reject cloud or external URLs."""
    cfg = get_config()
    if cfg.air_gap_mode:
        cfg.validate()
    h = host.lower()
    is_local = (
        h.startswith("http://localhost")
        or h.startswith("http://127.0.0.1")
        or h.startswith("localhost")
        or h.startswith("127.0.0.1")
        or h.startswith("::1")
    )
    if not is_local:
        raise ValueError(
            f"ULPF enforces strictly local, air-gapped execution. Non-local host '{host}' rejected."
        )


def get_ollama_call_count() -> int:
    """Return the total number of Ollama LLM calls attempted during current session."""
    return max(_OLLAMA_ATTEMPTS, _OLLAMA_CALL_COUNT)


def get_ollama_telemetry() -> Dict[str, Any]:
    """Return complete Ollama observability telemetry."""
    calls = max(_OLLAMA_ATTEMPTS, _OLLAMA_CALL_COUNT)
    return {
        "ollama_attempts": calls,
        "ollama_calls": calls,
        "ollama_successes": _OLLAMA_SUCCESS_COUNT,
        "ollama_failures": _OLLAMA_FAILURE_COUNT,
        "ollama_timeouts": _OLLAMA_TIMEOUT_COUNT,
        "ollama_latency_ms": round(_OLLAMA_TOTAL_LATENCY_MS, 2),
        "last_error_type": _LAST_ERROR_TYPE,
    }


def reset_ollama_call_count() -> None:
    """Reset the Ollama LLM call counter and telemetry."""
    global _OLLAMA_ATTEMPTS, _OLLAMA_CALL_COUNT, _OLLAMA_SUCCESS_COUNT, _OLLAMA_FAILURE_COUNT, _OLLAMA_TIMEOUT_COUNT, _OLLAMA_TOTAL_LATENCY_MS, _LAST_ERROR_TYPE
    _OLLAMA_ATTEMPTS = 0
    _OLLAMA_CALL_COUNT = 0
    _OLLAMA_SUCCESS_COUNT = 0
    _OLLAMA_FAILURE_COUNT = 0
    _OLLAMA_TIMEOUT_COUNT = 0
    _OLLAMA_TOTAL_LATENCY_MS = 0.0
    _LAST_ERROR_TYPE = OLLAMA_SUCCESS


def reset_ollama_telemetry() -> None:
    reset_ollama_call_count()


def is_ollama_available(host: Optional[str] = None) -> bool:
    """Check if the local Ollama instance is reachable with fast bounded connect timeout."""
    h = host or get_config().ollama_url
    try:
        _validate_local_host(h)
        import urllib.request
        connect_timeout = getattr(get_config(), "connect_timeout", 5.0)
        req = urllib.request.Request(f"{h.rstrip('/')}/api/tags", method="GET")
        with urllib.request.urlopen(req, timeout=connect_timeout) as resp:
            return resp.status == 200
    except Exception:
        return False


def _build_client(host: str, read_timeout: float) -> Any:
    """Build an ollama.Client configured with separate connect and read timeouts."""
    import ollama
    cfg = get_config()
    connect_timeout = getattr(cfg, "connect_timeout", 5.0)
    try:
        import httpx
        client_timeout = httpx.Timeout(timeout=read_timeout, connect=connect_timeout)
        return ollama.Client(host=host, timeout=client_timeout)
    except Exception:
        return ollama.Client(host=host, timeout=read_timeout)


def _clean_json_text(text: str) -> str:
    """Strip markdown fences, leading/trailing thought tags, trailing commas, or comments."""
    if not text:
        return "{}"

    cleaned = text.strip()

    # Strip Qwen <think>...</think> tags if present or orphan </think>
    if "</think>" in cleaned:
        cleaned = cleaned.split("</think>")[-1].strip()
    else:
        cleaned = re.sub(r"<think>.*?</think>", "", cleaned, flags=re.DOTALL).strip()

    # Strip markdown ```json ... ``` code fences
    if cleaned.startswith("```"):
        lines = cleaned.splitlines()
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        cleaned = "\n".join(lines).strip()

    # Find the outermost { ... }
    first_brace = cleaned.find("{")
    last_brace = cleaned.rfind("}")
    if first_brace != -1 and last_brace != -1 and last_brace > first_brace:
        cleaned = cleaned[first_brace : last_brace + 1]

    # Remove single line comments
    cleaned = re.sub(r"//.*$", "", cleaned, flags=re.MULTILINE)

    # Remove trailing commas before } or ]
    cleaned = re.sub(r",\s*([\]}])", r"\1", cleaned)

    return cleaned


def generate(
    prompt: str,
    model: Optional[str] = None,
    temperature: Optional[float] = None,
    num_ctx: int = 2048,
    think: bool = False,
    timeout: Optional[float] = None,
    retries: Optional[int] = None,
    host: Optional[str] = None,
) -> str:
    """
    Send a prompt to a locally running Ollama model.
    Bounded execution: timeouts are never retried.
    """
    cfg = get_config()
    active_model = model or cfg.model
    active_temp = float(os.environ.get("ULPF_OLLAMA_TEMPERATURE", "0.0")) if temperature is None else temperature
    active_timeout = cfg.ai_timeout if timeout is None else timeout
    active_host = host or cfg.ollama_url
    max_transient_retries = cfg.ai_max_retries if retries is None else min(1, retries)

    _validate_local_host(active_host)

    try:
        import ollama
    except ImportError:
        raise OllamaUnavailableError("The 'ollama' Python library is required for AI components.")

    options = {
        "temperature": active_temp,
        "num_ctx": num_ctx,
    }

    kwargs: Dict[str, Any] = {
        "model": active_model,
        "messages": [{"role": "user", "content": prompt}],
        "options": options,
        "think": think,
    }

    client = _build_client(active_host, active_timeout)

    for attempt in range(max_transient_retries + 1):
        t_start = time.perf_counter()
        global _OLLAMA_ATTEMPTS, _OLLAMA_SUCCESS_COUNT, _OLLAMA_FAILURE_COUNT, _OLLAMA_TIMEOUT_COUNT, _OLLAMA_TOTAL_LATENCY_MS, _LAST_ERROR_TYPE
        _OLLAMA_ATTEMPTS += 1
        try:
            response = client.chat(**kwargs)
            lat = (time.perf_counter() - t_start) * 1000
            _OLLAMA_TOTAL_LATENCY_MS += lat
            _OLLAMA_SUCCESS_COUNT += 1
            _LAST_ERROR_TYPE = OLLAMA_SUCCESS
            content = response["message"]["content"]
            return _clean_json_text(content)
        except Exception as exc:
            lat = (time.perf_counter() - t_start) * 1000
            _OLLAMA_TOTAL_LATENCY_MS += lat
            _OLLAMA_FAILURE_COUNT += 1
            err_type = classify_ollama_error(exc)
            _LAST_ERROR_TYPE = err_type

            if err_type == OLLAMA_TIMEOUT:
                _OLLAMA_TIMEOUT_COUNT += 1
                logger.warning(f"Ollama generate timed out after {active_timeout:.1f}s: {exc}")
                raise OllamaTimeoutError(f"Local Ollama inference timed out after {active_timeout:.1f}s: {exc}") from exc

            if err_type == OLLAMA_MODEL_NOT_FOUND:
                raise OllamaModelNotFoundError(f"Model '{active_model}' not found in local Ollama: {exc}") from exc

            if attempt < max_transient_retries:
                logger.warning(f"Ollama transient failure (attempt {attempt + 1}/{max_transient_retries + 1}): {exc}. Retrying once...")
                time.sleep(0.5)
                continue

            if err_type == OLLAMA_CONNECTION_ERROR:
                raise OllamaConnectionError(f"Ollama connection error: {exc}") from exc
            raise OllamaUnavailableError(f"Local Ollama service unavailable: {exc}") from exc

    raise OllamaUnavailableError(f"Local Ollama service unavailable after retries.")


def generate_json(
    prompt: str,
    model: Optional[str] = None,
    temperature: Optional[float] = None,
    num_ctx: int = 2048,
    think: bool = False,
    timeout: Optional[float] = None,
    retries: Optional[int] = None,
    host: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Send a prompt to Ollama and request a JSON-only response.
    Bounded execution: timeouts are never retried.
    """
    cfg = get_config()
    active_model = model or cfg.model
    active_temp = float(os.environ.get("ULPF_OLLAMA_TEMPERATURE", "0.0")) if temperature is None else temperature
    active_timeout = cfg.ai_timeout if timeout is None else timeout
    active_host = host or cfg.ollama_url
    max_transient_retries = cfg.ai_max_retries if retries is None else min(1, retries)

    _validate_local_host(active_host)

    try:
        import ollama
    except ImportError:
        raise OllamaUnavailableError("The 'ollama' Python library is required for AI components.")

    options = {
        "temperature": active_temp,
        "num_ctx": num_ctx,
    }

    kwargs: Dict[str, Any] = {
        "model": active_model,
        "messages": [{"role": "user", "content": prompt}],
        "format": "json",
        "options": options,
        "think": think,
    }

    client = _build_client(active_host, active_timeout)

    for attempt in range(max_transient_retries + 1):
        t_start = time.perf_counter()
        global _OLLAMA_ATTEMPTS, _OLLAMA_SUCCESS_COUNT, _OLLAMA_FAILURE_COUNT, _OLLAMA_TIMEOUT_COUNT, _OLLAMA_TOTAL_LATENCY_MS, _LAST_ERROR_TYPE
        _OLLAMA_ATTEMPTS += 1
        try:
            response = client.chat(**kwargs)
            lat = (time.perf_counter() - t_start) * 1000
            _OLLAMA_TOTAL_LATENCY_MS += lat
            _OLLAMA_SUCCESS_COUNT += 1
            _LAST_ERROR_TYPE = OLLAMA_SUCCESS
            content = response["message"]["content"]
            cleaned = _clean_json_text(content)
            try:
                return json.loads(cleaned)
            except Exception:
                repaired = re.sub(r",\s*([\]}])", r"\1", cleaned)
                repaired = re.sub(r"[\x00-\x1f\x7f-\x9f]", " ", repaired)
                try:
                    return json.loads(repaired)
                except Exception as parse_err:
                    _LAST_ERROR_TYPE = OLLAMA_INVALID_RESPONSE
                    raise OllamaInvalidResponseError(f"Ollama returned malformed JSON: {parse_err}")
        except Exception as exc:
            lat = (time.perf_counter() - t_start) * 1000
            _OLLAMA_TOTAL_LATENCY_MS += lat
            _OLLAMA_FAILURE_COUNT += 1
            err_type = classify_ollama_error(exc)
            _LAST_ERROR_TYPE = err_type

            # STRICT INVARIANT: Timeouts are NEVER retried.
            if err_type == OLLAMA_TIMEOUT:
                _OLLAMA_TIMEOUT_COUNT += 1
                logger.warning(f"Ollama generate_json timed out after {active_timeout:.1f}s: {exc}")
                raise OllamaTimeoutError(f"Local Ollama inference timed out after {active_timeout:.1f}s: {exc}") from exc

            # Model not found is fatal and never retried
            if err_type == OLLAMA_MODEL_NOT_FOUND:
                raise OllamaModelNotFoundError(f"Model '{active_model}' not found in local Ollama: {exc}") from exc

            # Malformed response is not retried
            if err_type == OLLAMA_INVALID_RESPONSE:
                raise

            # For transient connection errors, allow at most 1 controlled retry
            if attempt < max_transient_retries:
                logger.warning(f"Ollama transient failure (attempt {attempt + 1}/{max_transient_retries + 1}): {exc}. Retrying once...")
                time.sleep(0.5)
                continue

            if err_type == OLLAMA_CONNECTION_ERROR:
                raise OllamaConnectionError(f"Ollama connection error: {exc}") from exc
            raise OllamaUnavailableError(f"Local Ollama service unavailable: {exc}") from exc

    raise OllamaUnavailableError(f"Local Ollama service unavailable after retries.")
