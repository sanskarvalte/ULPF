"""
Tests for Local Ollama / Qwen Unknown-Log Parser Intelligence.

Validates the hardened pipeline:
RAW UNKNOWN LOG
-> structural fingerprint
-> representative samples
-> deterministic observations
-> Ollama/Qwen
-> strict parser specification
-> schema validation
-> parser execution
-> deterministic validation
-> accuracy evaluation
-> repair if needed
-> promotion/rejection

Covers all 12 required scenarios:
1. Ollama available
2. Ollama unavailable (graceful deterministic fallback, low confidence, review queue)
3. Malformed JSON handling
4. Hallucinated fields detection & rejection
5. Wrong / impossible delimiter rejection
6. Wrong field order detection & repair
7. Missing field detection & repair
8. Extra field lossless preservation in unmapped
9. Repair loop success & promotion
10. Repair loop failure & strict rejection
11. Cache hit by fingerprint + version
12. Cache miss on unknown or unvalidated/rejected parsers
"""

import json
from unittest.mock import MagicMock, patch
import pytest

from app.ai.ai_fallback import resolve_unknown_log
from app.ai.dynamic_parser import parse_with_spec
from app.ai.fingerprint import compute_log_fingerprint
from app.ai.ollama_client import (
    DEFAULT_MODEL,
    DEFAULT_HOST,
    OllamaUnavailableError,
    _validate_local_host,
    _clean_json_text,
    is_ollama_available,
)
from app.ai.parser_accuracy import evaluate_parser_accuracy
from app.ai.parser_generator import (
    extract_deterministic_observations,
    format_observations,
    generate_parser_spec,
)
from app.ai.parser_repair import repair_parser_spec
from app.ai.parser_resolver import resolve_parser_spec
from app.ai.parser_validator import validate_parser_spec
from app.parsers.registry import (
    clear_parsers,
    get_cache_stats,
    get_parser,
    get_parser_version,
    has_parser,
    register_parser,
    reset_cache_stats,
)


@pytest.fixture(autouse=True)
def clean_registry():
    """Ensure a clean parser registry and cache stats for each test."""
    clear_parsers()
    reset_cache_stats()
    yield
    clear_parsers()
    reset_cache_stats()


# =====================================================================
# 0. AIR-GAP & CONFIGURATION
# =====================================================================

def test_air_gap_and_defaults():
    """Verify local-only constraints, default qwen3:4b model, and rejection of external hosts."""
    assert DEFAULT_MODEL == "qwen3:4b"
    assert "localhost" in DEFAULT_HOST or "127.0.0.1" in DEFAULT_HOST

    # Must allow local hosts
    _validate_local_host("http://localhost:11434")
    _validate_local_host("http://127.0.0.1:11434")

    # Must strictly reject non-local/cloud hosts
    with pytest.raises(ValueError, match="strictly local"):
        _validate_local_host("https://api.openai.com/v1")

    with pytest.raises(ValueError, match="strictly local"):
        _validate_local_host("https://cloud.ollama.ai")


# =====================================================================
# 1. OLLAMA AVAILABLE
# =====================================================================

def test_ollama_available():
    """Verify end-to-end resolution when local Ollama returns a valid specification."""
    sample_logs = (
        "2026-09-04T12:00:00Z|srv-inventory|alice|item_add|192.168.1.50\n"
        "2026-09-04T12:01:00Z|srv-inventory|bob|item_update|192.168.1.51\n"
        "2026-09-04T12:02:00Z|srv-inventory|charlie|item_delete|192.168.1.52"
    )

    mock_spec = {
        "format_name": "custom_inventory",
        "parser_type": "delimited",
        "delimiter": "|",
        "fields": [
            {"name": "timestamp", "type": "datetime"},
            {"name": "service_name", "type": "string"},
            {"name": "user", "type": "string"},
            {"name": "action", "type": "string"},
            {"name": "src_ip", "type": "ip"},
        ],
        "timestamp_field": "timestamp",
        "optional_fields": [],
        "confidence": 0.96,
    }

    with patch("app.ai.parser_generator.generate_json", return_value=mock_spec):
        res = resolve_unknown_log(sample_logs)

        assert res["success"] is True
        assert res["status"] == "promoted"
        assert res["parser_spec"]["format_name"] == "custom_inventory"
        assert len(res["events"]) == 3

        ev = res["events"][0]
        assert ev.user == "alice"
        assert ev.service_name == "srv-inventory"
        assert ev.src_ip == "192.168.1.50"
        assert "2026-09-04T12:00:00Z" in ev.raw_event


# =====================================================================
# 2. OLLAMA UNAVAILABLE (GRACEFUL FALLBACK)
# =====================================================================

def test_ollama_unavailable():
    """
    When local Ollama is down/unreachable:
    - Framework continues operating without crash
    - Deterministic parsing extracts all observable data
    - Raw event is preserved losslessly
    - Custom fields are preserved in unmapped
    - Parser confidence is marked low (0.20)
    - Routed to review queue
    """
    sample_logs = (
        "ts=2026-09-04T14:30:00Z svc=order-service usr=john_doe act=checkout src=10.0.0.5 sku=SKU-100 qty=5 status=success\n"
        "ts=2026-09-04T14:31:00Z svc=order-service usr=jane_doe act=checkout src=10.0.0.6 sku=SKU-200 qty=1 status=success"
    )

    with patch("app.ai.parser_generator.generate_json", side_effect=OllamaUnavailableError("Local Ollama offline")):
        res = resolve_unknown_log(sample_logs)

        # Framework continues operating
        assert res["success"] is False
        assert res["fallback"] is True
        assert res["confidence"] == 0.20
        assert len(res["events"]) == 2

        # Verify first event
        ev = res["events"][0]
        assert ev.raw_event.startswith("ts=2026-09-04T14:30:00Z")
        assert ev.unmapped is not None
        assert ev.unmapped.get("parser_confidence") == 0.20
        assert ev.unmapped.get("ollama_available") is False

        # Custom fields preserved
        assert ev.unmapped.get("sku") == "SKU-100"
        assert ev.unmapped.get("qty") == 5

        # Standard fields extracted deterministically
        assert ev.user == "john_doe"
        assert ev.service_name == "order-service"
        assert ev.src_ip == "10.0.0.5"


# =====================================================================
# 3. MALFORMED JSON
# =====================================================================

def test_malformed_json():
    """Verify validator flags invalid JSON structure, and _clean_json_text cleans messy LLM outputs."""
    # 1. Non-dict spec validation
    val_none = validate_parser_spec("string_instead_of_dict")
    assert val_none["valid"] is False
    assert any("must be a dictionary" in err for err in val_none["errors"])

    # 2. _clean_json_text robust repair of markdown code fences & thought tokens
    messy_llm_output = """
    <think>
    Thinking about the delimiter... It looks like a pipe delimiter.
    </think>
    ```json
    {
        "format_name": "clean_fmt",
        "parser_type": "delimited",
        "delimiter": "|",
        "fields": [{"name": "timestamp", "type": "datetime"}],
    }
    ```
    """
    cleaned = _clean_json_text(messy_llm_output)
    parsed = json.loads(cleaned)
    assert parsed["format_name"] == "clean_fmt"
    assert parsed["delimiter"] == "|"


# =====================================================================
# 4. HALLUCINATED FIELDS
# =====================================================================

def test_hallucinated_fields():
    """Validator strictly catches and flags fields not present in raw sample logs."""
    # Case A: Key-Value log where model invents fields
    sample_kv = "ts=2026-09-04T10:00:00Z usr=alice act=login src=1.2.3.4"
    hallucinated_kv_spec = {
        "format_name": "kv_test",
        "parser_type": "key_value",
        "fields": [
            {"name": "timestamp", "type": "datetime"},
            {"name": "user", "type": "string"},
            {"name": "action", "type": "string"},
            {"name": "src_ip", "type": "ip"},
            {"name": "credit_card_number", "type": "string"},  # HALLUCINATED!
            {"name": "social_security_num", "type": "string"},  # HALLUCINATED!
        ],
        "timestamp_field": "timestamp",
    }

    val_kv = validate_parser_spec(hallucinated_kv_spec, log_samples=sample_kv)
    assert val_kv["valid"] is False
    assert any("Hallucinated field 'credit_card_number'" in err for err in val_kv["errors"])
    assert any("Hallucinated field 'social_security_num'" in err for err in val_kv["errors"])

    # Case B: Delimited log where model specifies more fields than columns
    sample_delim = "2026-09-04|auth|admin"  # exactly 3 columns
    hallucinated_delim_spec = {
        "format_name": "delim_test",
        "parser_type": "delimited",
        "delimiter": "|",
        "fields": [
            {"name": "timestamp", "type": "datetime"},
            {"name": "service", "type": "string"},
            {"name": "user", "type": "string"},
            {"name": "action", "type": "string"},
            {"name": "src_ip", "type": "ip"},
            {"name": "dst_ip", "type": "ip"},
        ],  # 6 fields for 3 columns!
        "timestamp_field": "timestamp",
    }

    val_delim = validate_parser_spec(hallucinated_delim_spec, log_samples=sample_delim)
    assert val_delim["valid"] is False
    assert any("defines 6 fields, but sample logs only have 3 columns" in err for err in val_delim["errors"])


# =====================================================================
# 5. WRONG DELIMITER
# =====================================================================

def test_wrong_delimiter():
    """Validator catches impossible delimiters (alphanumeric or absent from log samples)."""
    sample_pipe = "2026-09-04T10:00:00Z|user1|action1"

    # Impossible alphanumeric delimiter
    spec_alnum = {
        "format_name": "test_alnum",
        "parser_type": "delimited",
        "delimiter": "abc",
        "fields": [{"name": "timestamp", "type": "datetime"}],
    }
    val_alnum = validate_parser_spec(spec_alnum, log_samples=sample_pipe)
    assert val_alnum["valid"] is False
    assert any("must be non-alphanumeric" in err for err in val_alnum["errors"])

    # Delimiter not found in samples
    spec_wrong = {
        "format_name": "test_wrong",
        "parser_type": "delimited",
        "delimiter": ";",  # pipe is present, not semicolon
        "fields": [{"name": "timestamp", "type": "datetime"}],
    }
    val_wrong = validate_parser_spec(spec_wrong, log_samples=sample_pipe)
    assert val_wrong["valid"] is False
    assert any("delimiter does not appear anywhere in sample logs" in err for err in val_wrong["errors"])


# =====================================================================
# 6. WRONG FIELD ORDER
# =====================================================================

def test_wrong_field_order():
    """Accuracy evaluator detects positional order mismatches and repair corrects them."""
    sample_logs = "2026-09-04T10:00:00Z|admin|login|10.0.0.1"
    accuracy_samples = [
        {
            "raw": "2026-09-04T10:00:00Z|admin|login|10.0.0.1",
            "expected": {
                "timestamp": "2026-09-04T10:00:00Z",
                "user": "admin",
                "action": "login",
                "src_ip": "10.0.0.1",
            },
        }
    ]

    # Inverted order: user before timestamp
    wrong_order_spec = {
        "format_name": "audit_auth",
        "parser_type": "delimited",
        "delimiter": "|",
        "fields": [
            {"name": "user", "type": "string"},
            {"name": "timestamp", "type": "datetime"},
            {"name": "action", "type": "string"},
            {"name": "src_ip", "type": "ip"},
        ],
        "timestamp_field": "timestamp",
        "confidence": 0.85,
    }

    correct_order_spec = {
        "format_name": "audit_auth",
        "parser_type": "delimited",
        "delimiter": "|",
        "fields": [
            {"name": "timestamp", "type": "datetime"},
            {"name": "user", "type": "string"},
            {"name": "action", "type": "string"},
            {"name": "src_ip", "type": "ip"},
        ],
        "timestamp_field": "timestamp",
        "confidence": 0.98,
    }

    # Accuracy evaluator catches mismatches
    acc = evaluate_parser_accuracy(accuracy_samples, wrong_order_spec)
    assert acc["passed_gate"] is False
    assert len(acc["failing_fields"]) > 0

    # Test repair correcting the order
    with patch("app.ai.parser_generator.generate_json", return_value=wrong_order_spec), \
         patch("app.ai.parser_repair.generate_json", return_value=correct_order_spec):
        res = resolve_parser_spec(
            log_samples=sample_logs,
            accuracy_samples=accuracy_samples,
            accuracy_threshold=100.0,
        )
        assert res["success"] is True
        assert res["status"] == "promoted"
        assert res["accuracy"] == 100.0
        assert res["repair_attempts"] == 1


# =====================================================================
# 7. MISSING FIELD
# =====================================================================

def test_missing_field():
    """Accuracy evaluator detects missing fields and repair adds them."""
    sample_logs = "ts=2026-09-04T10:00:00Z usr=alice act=login src=10.0.0.1 status=success"
    accuracy_samples = [
        {
            "raw": "ts=2026-09-04T10:00:00Z usr=alice act=login src=10.0.0.1 status=success",
            "expected": {
                "timestamp": "2026-09-04T10:00:00Z",
                "user": "alice",
                "action": "login",
                "src_ip": "10.0.0.1",
                "status": "success",
            },
        }
    ]

    # Incomplete spec omitting 'status'
    incomplete_spec = {
        "format_name": "app_kv",
        "parser_type": "key_value",
        "fields": [
            {"name": "timestamp", "type": "datetime"},
            {"name": "user", "type": "string"},
            {"name": "action", "type": "string"},
            {"name": "src_ip", "type": "ip"},
        ],
        "timestamp_field": "timestamp",
        "confidence": 0.80,
    }

    completed_spec = {
        "format_name": "app_kv",
        "parser_type": "key_value",
        "fields": [
            {"name": "timestamp", "type": "datetime"},
            {"name": "user", "type": "string"},
            {"name": "action", "type": "string"},
            {"name": "src_ip", "type": "ip"},
            {"name": "status", "type": "string"},
        ],
        "timestamp_field": "timestamp",
        "confidence": 0.99,
    }

    with patch("app.ai.parser_generator.generate_json", return_value=incomplete_spec), \
         patch("app.ai.parser_repair.generate_json", return_value=completed_spec):
        res = resolve_parser_spec(
            log_samples=sample_logs,
            accuracy_samples=accuracy_samples,
            accuracy_threshold=100.0,
        )
        assert res["success"] is True
        assert res["status"] == "promoted"
        assert res["accuracy"] == 100.0


# =====================================================================
# 8. EXTRA FIELD
# =====================================================================

def test_extra_field():
    """Unmapped and custom fields beyond parser spec are preserved losslessly."""
    raw_log = "2026-09-04T10:00:00Z|srv1|admin|login|10.0.0.1|EXTRA_METADATA_1|EXTRA_METADATA_2"

    spec = {
        "format_name": "core_auth",
        "parser_type": "delimited",
        "delimiter": "|",
        "fields": [
            {"name": "timestamp", "type": "datetime"},
            {"name": "service_name", "type": "string"},
            {"name": "user", "type": "string"},
            {"name": "action", "type": "string"},
            {"name": "src_ip", "type": "ip"},
        ],
        "timestamp_field": "timestamp",
    }

    event = parse_with_spec(raw_log, spec)
    assert event.user == "admin"
    assert event.service_name == "srv1"
    assert event.raw_event == raw_log

    # Verify extra columns were captured losslessly in unmapped
    assert event.unmapped is not None
    assert event.unmapped.get("extra_col_6") == "EXTRA_METADATA_1"
    assert event.unmapped.get("extra_col_7") == "EXTRA_METADATA_2"


# =====================================================================
# 9. REPAIR SUCCESS
# =====================================================================

def test_repair_success():
    """Verify flawed spec triggering schema validation error is repaired and promoted."""
    sample_logs = "2026-09-04T10:00:00Z,user1,auth_ok,1.1.1.1"

    # Initially missing required format_name and having invalid timestamp type
    flawed_spec = {
        "format_name": "",  # invalid
        "parser_type": "delimited",
        "delimiter": ",",
        "fields": [
            {"name": "timestamp", "type": "string"},  # should be datetime
            {"name": "user", "type": "string"},
            {"name": "action", "type": "string"},
            {"name": "src_ip", "type": "ip"},
        ],
        "timestamp_field": "timestamp",
    }

    repaired_spec = {
        "format_name": "repaired_csv_format",
        "parser_type": "delimited",
        "delimiter": ",",
        "fields": [
            {"name": "timestamp", "type": "datetime"},
            {"name": "user", "type": "string"},
            {"name": "action", "type": "string"},
            {"name": "src_ip", "type": "ip"},
        ],
        "timestamp_field": "timestamp",
        "confidence": 0.95,
    }

    with patch("app.ai.parser_generator.generate_json", return_value=flawed_spec), \
         patch("app.ai.parser_repair.generate_json", return_value=repaired_spec):
        res = resolve_parser_spec(log_samples=sample_logs)

        assert res["success"] is True
        assert res["status"] == "promoted"
        assert res["repair_attempts"] == 1
        assert res["parser_spec"]["format_name"] == "repaired_csv_format"


# =====================================================================
# 10. REPAIR FAILURE
# =====================================================================

def test_repair_failure():
    """Verify spec that repeatedly fails validation after MAX_REPAIR_ATTEMPTS is strictly rejected."""
    sample_logs = "2026-09-04T10:00:00Z|alice|active"

    # Persistently invalid spec (unsupported parser_type)
    persistently_broken_spec = {
        "format_name": "broken_fmt",
        "parser_type": "unsupported_brain_parser",
        "fields": [{"name": "timestamp", "type": "datetime"}],
    }

    with patch("app.ai.parser_generator.generate_json", return_value=persistently_broken_spec), \
         patch("app.ai.parser_repair.generate_json", return_value=persistently_broken_spec):
        res = resolve_parser_spec(log_samples=sample_logs)

        assert res["success"] is False
        assert res["status"] == "rejected"
        assert res["repair_attempts"] >= 2
        assert any("Invalid parser_type" in err for err in res["errors"])


# =====================================================================
# 11. CACHE HIT
# =====================================================================

def test_cache_hit():
    """Active validated parser is retrieved from registry; cache hit counter increments."""
    fp = "fp_test_cache_hit_123"
    spec = {
        "format_name": "cached_inventory",
        "parser_type": "delimited",
        "delimiter": "|",
        "fields": [
            {"name": "timestamp", "type": "datetime"},
            {"name": "user", "type": "string"},
        ],
        "timestamp_field": "timestamp",
    }

    # Register active validated parser
    register_parser(
        fingerprint=fp,
        parser_spec=spec,
        status="active",
        version=1,
        validation_passed=True,
    )

    stats_before = get_cache_stats()
    retrieved = get_parser(fp)
    stats_after = get_cache_stats()

    assert retrieved is not None
    assert retrieved["format_name"] == "cached_inventory"
    assert stats_after["hits"] == stats_before["hits"] + 1

    # Version-specific hit
    ver_retrieved = get_parser_version(fp, version=1)
    assert ver_retrieved is not None
    assert ver_retrieved["format_name"] == "cached_inventory"


# =====================================================================
# 12. CACHE MISS
# =====================================================================

def test_cache_miss():
    """Unseen fingerprints or rejected/unvalidated parsers never return from cache."""
    stats_before = get_cache_stats()

    # 1. Totally unseen fingerprint
    miss_unseen = get_parser("fp_never_seen_99999")
    assert miss_unseen is None

    # 2. Registered parser that was REJECTED
    fp_rejected = "fp_rejected_failure_555"
    register_parser(
        fingerprint=fp_rejected,
        parser_spec={"format_name": "rejected_spec"},
        status="rejected",
        validation_passed=False,
    )
    miss_rejected = get_parser(fp_rejected)
    assert miss_rejected is None

    # 3. Non-existent version
    miss_version = get_parser_version("fp_never_seen_99999", version=99)
    assert miss_version is None

    stats_after = get_cache_stats()
    assert stats_after["misses"] >= stats_before["misses"] + 3
