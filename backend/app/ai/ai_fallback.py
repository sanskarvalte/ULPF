"""
ULPF AI Parser Fallback.

Connects the format-detection layer with the AI parser resolver.
The AI layer is only used for unknown/custom formats.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from app.ai.dynamic_parser import parse_with_spec
from app.ai.parser_resolver import resolve_parser_spec


MAX_AI_SAMPLE_LINES = 20


def _build_accuracy_samples(
    log_samples: str,
) -> List[Dict[str, Any]]:
    """
    Build samples for live execution testing.
    These are used to verify that the generated parser executes without error.
    """
    samples: List[Dict[str, Any]] = []

    for line in log_samples.splitlines():
        line = line.strip()
        if not line:
            continue

        samples.append(
            {
                "raw": line,
                "expected": {},
            }
        )

        if len(samples) >= MAX_AI_SAMPLE_LINES:
            break

    return samples


def _deterministic_fallback_event(raw_line: str) -> Any:
    """
    Parse an unknown log deterministically when Ollama is unavailable or spec was rejected.
    Preserves raw event and custom fields losslessly, marks confidence low (0.20),
    and routes the template for human review.
    """
    from app.ai.fingerprint import compute_log_fingerprint
    from app.ai.ollama_detector import process_unmatched_log_with_ai
    from app.storage.review_queue import enqueue_for_review

    raw_stripped = raw_line.strip()
    ev = process_unmatched_log_with_ai(raw_stripped, sync_ai=False)

    if ev.unmapped is None:
        ev.unmapped = {}
    ev.unmapped["parser_confidence"] = 0.20
    ev.unmapped["ollama_available"] = False
    ev.unmapped["status"] = "pending_review"

    # Route for human review with low confidence
    _, _, fp_hash = compute_log_fingerprint(raw_stripped)
    try:
        enqueue_for_review(
            fingerprint=fp_hash,
            format_name="unknown_custom",
            suggested_mapping={
                "format_name": "unknown_custom",
                "custom_fields": {
                    k: v
                    for k, v in ev.unmapped.items()
                    if not k.startswith("ollama_") and k != "fingerprint"
                },
            },
            confidence=0.20,
            sample_line=raw_stripped,
        )
    except Exception:
        pass

    return ev


def resolve_unknown_log(
    log_samples: str,
    accuracy_samples: Optional[List[Dict[str, Any]]] = None,
    accuracy_threshold: float = 85.0,
    timeout: Optional[float] = None,
) -> Dict[str, Any]:
    """
    High-level unknown log resolver with automatic offline fallback.

    For labelled testing, accuracy_samples can contain expected values.
    For normal live ingestion, accuracy_samples can be omitted.

    When Ollama is unavailable:
    - Continues operating without raising unhandled exceptions
    - Deterministic parsing extracts all available fields
    - Raw event is preserved losslessly
    - Custom fields are preserved in unmapped
    - Parser confidence is marked low (0.20)
    - Enqueued into review queue
    """
    if not log_samples or not log_samples.strip():
        return {
            "success": False,
            "fallback": False,
            "confidence": 0.0,
            "parser_spec": None,
            "events": [],
            "accuracy": None,
            "repair_attempts": 0,
            "errors": ["Log samples cannot be empty."],
        }

    if accuracy_samples is None:
        execution_samples = _build_accuracy_samples(log_samples)
        resolver_accuracy_samples: List[Dict[str, Any]] = []
    else:
        execution_samples = accuracy_samples
        resolver_accuracy_samples = accuracy_samples

    resolution = resolve_parser_spec(
        log_samples=log_samples,
        accuracy_samples=resolver_accuracy_samples,
        accuracy_threshold=accuracy_threshold,
        timeout=timeout,
    )

    if not resolution["success"]:
        # Fallback to deterministic parsing: preserve raw event and custom fields, route to review
        fallback_events = []
        for sample in execution_samples:
            raw_log = sample.get("raw", "")
            if not raw_log.strip():
                continue
            try:
                ev = _deterministic_fallback_event(raw_log)
                fallback_events.append(ev)
            except Exception:
                pass

        return {
            "success": False,
            "status": resolution.get("status", "rejected"),
            "fallback": True,
            "confidence": 0.20,
            "parser_spec": resolution.get("parser_spec"),
            "events": fallback_events,
            "accuracy": resolution.get("accuracy"),
            "repair_attempts": resolution.get("repair_attempts", 0),
            "errors": resolution.get("errors", []),
        }

    parser_spec = resolution["parser_spec"]
    events = []

    for sample in execution_samples:
        raw_log = sample.get("raw", "")
        if not raw_log.strip():
            continue

        try:
            event = parse_with_spec(
                raw=raw_log,
                parser_spec=parser_spec,
            )
            events.append(event)
        except Exception as exc:
            # Fallback deterministically for individual line execution error
            fallback_ev = _deterministic_fallback_event(raw_log)
            if fallback_ev.unmapped is None:
                fallback_ev.unmapped = {}
            fallback_ev.unmapped["execution_error"] = str(exc)
            events.append(fallback_ev)

    return {
        "success": True,
        "status": resolution.get("status", "promoted"),
        "fallback": False,
        "confidence": (parser_spec.get("confidence", 0.90) if isinstance(parser_spec, dict) else 0.90),
        "parser_spec": parser_spec,
        "events": events,
        "accuracy": resolution.get("accuracy"),
        "repair_attempts": resolution.get("repair_attempts", 0),
        "errors": [],
    }
