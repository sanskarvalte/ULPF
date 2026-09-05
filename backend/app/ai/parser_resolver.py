"""
ULPF AI Parser Resolver.

Coordinates:
1. Parser specification generation
2. Deterministic validation
3. Dynamic parser execution
4. Multi-metric accuracy verification
5. Automatic AI repair loop
6. Re-validation and re-accuracy testing
7. Parser promotion or rejection against strict accuracy gate

The resolver never executes AI-generated Python code.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from app.ai.parser_accuracy import evaluate_parser_accuracy
from app.ai.parser_generator import generate_parser_spec
from app.ai.parser_repair import repair_parser_spec
from app.ai.parser_validator import validate_parser_spec


MAX_REPAIR_ATTEMPTS = 2
DEFAULT_ACCURACY_THRESHOLD = 100.0


def _accuracy_errors(
    accuracy_result: Dict[str, Any],
    threshold: float = DEFAULT_ACCURACY_THRESHOLD,
) -> List[str]:
    """
    Convert accuracy failures and failing fields into detailed repair instructions.
    """
    errors: List[str] = []
    accuracy = accuracy_result.get("accuracy", 0.0)
    event_pct = accuracy_result.get("event_level_match", 0.0)

    errors.append(
        f"Parser extraction accuracy is {accuracy}% (event match: {event_pct}%). "
        f"Required target accuracy is {threshold}%."
    )

    failing = accuracy_result.get("failing_fields", [])
    for f in failing[:10]:
        errors.append(
            f"Sample {f.get('sample_number')}: field '{f.get('field')}' "
            f"expected '{f.get('expected')}' but extracted '{f.get('extracted')}'. "
            f"Reason: {f.get('reason')}."
        )

    return errors


def _result(
    success: bool,
    parser_spec: Optional[Dict[str, Any]],
    errors: List[str],
    repair_attempts: int,
    accuracy: Optional[float] = None,
    accuracy_result: Optional[Dict[str, Any]] = None,
    status: str = "unverified",
) -> Dict[str, Any]:
    """Build a consistent resolver response with lifecycle status."""
    return {
        "success": success,
        "status": status,  # "promoted", "rejected", "unverified"
        "parser_spec": parser_spec,
        "errors": errors,
        "repair_attempts": repair_attempts,
        "accuracy": accuracy,
        "accuracy_result": accuracy_result,
    }


def resolve_parser_spec(
    log_samples: str,
    accuracy_samples: Optional[List[Dict[str, Any]]] = None,
    accuracy_threshold: float = DEFAULT_ACCURACY_THRESHOLD,
    timeout: Optional[float] = None,
) -> Dict[str, Any]:
    """
    Generate, validate, execute and verify an AI parser specification.
    Enforces strict accuracy gate: if below threshold after repairs, the parser is rejected.
    """
    if not log_samples or not log_samples.strip():
        return _result(
            success=False,
            status="rejected",
            parser_spec=None,
            errors=["Log samples cannot be empty."],
            repair_attempts=0,
        )

    if accuracy_threshold < 0 or accuracy_threshold > 100:
        return _result(
            success=False,
            status="rejected",
            parser_spec=None,
            errors=["accuracy_threshold must be between 0 and 100."],
            repair_attempts=0,
        )

    # ---------------------------------------------------------
    # STEP 1: GENERATE
    # ---------------------------------------------------------
    try:
        parser_spec = generate_parser_spec(log_samples, timeout=timeout)
    except Exception as exc:
        is_timeout = "timeout" in str(exc).lower() or "timed out" in str(exc).lower()
        is_unavail = is_timeout or "unavailable" in str(exc).lower() or "connection" in str(exc).lower() or "refused" in str(exc).lower()
        err_status = "timeout" if is_timeout else ("unavailable" if is_unavail else "rejected")
        return _result(
            success=False,
            status=err_status,
            parser_spec=None,
            errors=[f"Parser generation failed: {exc}"],
            repair_attempts=0,
        )

    # ---------------------------------------------------------
    # STEP 2: VALIDATE
    # ---------------------------------------------------------
    total_repairs = 0
    validation = validate_parser_spec(parser_spec, log_samples=log_samples)

    if not validation["valid"]:
        current_spec = parser_spec
        current_errors = validation["errors"]

        for attempt in range(1, MAX_REPAIR_ATTEMPTS + 1):
            try:
                repaired_spec = repair_parser_spec(
                    log_samples=log_samples,
                    parser_spec=current_spec,
                    errors=current_errors,
                    timeout=timeout,
                )
            except Exception as exc:
                is_timeout = "timeout" in str(exc).lower() or "timed out" in str(exc).lower()
                is_unavail = is_timeout or "unavailable" in str(exc).lower() or "connection" in str(exc).lower() or "refused" in str(exc).lower()
                err_status = "timeout" if is_timeout else ("unavailable" if is_unavail else "rejected")
                return _result(
                    success=False,
                    status=err_status,
                    parser_spec=current_spec,
                    errors=[f"Parser repair failed: {exc}"],
                    repair_attempts=attempt,
                )

            repaired_validation = validate_parser_spec(repaired_spec, log_samples=log_samples)
            if repaired_validation["valid"]:
                parser_spec = repaired_spec
                total_repairs = attempt
                break

            current_spec = repaired_spec
            current_errors = repaired_validation["errors"]
        else:
            return _result(
                success=False,
                status="rejected",
                parser_spec=current_spec,
                errors=current_errors,
                repair_attempts=MAX_REPAIR_ATTEMPTS,
            )

    # ---------------------------------------------------------
    # STEP 3: ACCURACY VERIFICATION & STRICT GATE
    # ---------------------------------------------------------
    if accuracy_samples:
        accuracy_result = evaluate_parser_accuracy(
            samples=accuracy_samples,
            parser_spec=parser_spec,
            accuracy_threshold=accuracy_threshold,
        )

        accuracy = accuracy_result.get("accuracy", 0.0)

        if accuracy_result.get("passed_gate"):
            return _result(
                success=True,
                status="promoted",
                parser_spec=parser_spec,
                errors=[],
                repair_attempts=total_repairs,
                accuracy=accuracy,
                accuracy_result=accuracy_result,
            )

        # -----------------------------------------------------
        # STEP 4: ACCURACY-BASED REPAIR LOOP
        # -----------------------------------------------------
        current_spec = parser_spec
        current_errors = _accuracy_errors(accuracy_result, accuracy_threshold)

        for attempt in range(1, MAX_REPAIR_ATTEMPTS + 1):
            try:
                repaired_spec = repair_parser_spec(
                    log_samples=log_samples,
                    parser_spec=current_spec,
                    errors=current_errors,
                    field_mismatches=accuracy_result.get("failing_fields") if accuracy_result else None,
                    expected_values=[s.get("expected") for s in accuracy_samples if isinstance(s, dict) and s.get("expected")],
                    timeout=timeout,
                )
            except Exception as exc:
                is_timeout = "timeout" in str(exc).lower() or "timed out" in str(exc).lower()
                is_unavail = is_timeout or "unavailable" in str(exc).lower() or "connection" in str(exc).lower() or "refused" in str(exc).lower()
                err_status = "timeout" if is_timeout else ("unavailable" if is_unavail else "rejected")
                return _result(
                    success=False,
                    status=err_status,
                    parser_spec=current_spec,
                    errors=[f"Parser repair failed: {exc}"],
                    repair_attempts=total_repairs + attempt,
                    accuracy=accuracy,
                    accuracy_result=accuracy_result,
                )

            repaired_validation = validate_parser_spec(repaired_spec, log_samples=log_samples)
            if not repaired_validation["valid"]:
                current_spec = repaired_spec
                current_errors = repaired_validation["errors"]
                continue

            repaired_accuracy_result = evaluate_parser_accuracy(
                samples=accuracy_samples,
                parser_spec=repaired_spec,
                accuracy_threshold=accuracy_threshold,
            )
            repaired_accuracy = repaired_accuracy_result.get("accuracy", 0.0)

            if repaired_accuracy_result.get("passed_gate"):
                return _result(
                    success=True,
                    status="promoted",
                    parser_spec=repaired_spec,
                    errors=[],
                    repair_attempts=total_repairs + attempt,
                    accuracy=repaired_accuracy,
                    accuracy_result=repaired_accuracy_result,
                )

            current_spec = repaired_spec
            current_errors = _accuracy_errors(repaired_accuracy_result, accuracy_threshold)
            accuracy = repaired_accuracy
            accuracy_result = repaired_accuracy_result

        # STRICT REJECTION: If still below target after all repairs, reject parser!
        return _result(
            success=False,
            status="rejected",
            parser_spec=current_spec,
            errors=current_errors,
            repair_attempts=total_repairs + MAX_REPAIR_ATTEMPTS,
            accuracy=accuracy,
            accuracy_result=accuracy_result,
        )

    # ---------------------------------------------------------
    # NO ACCURACY SAMPLES (Validation Passed, Unverified Live Ingest)
    # ---------------------------------------------------------
    return _result(
        success=True,
        status="promoted",
        parser_spec=parser_spec,
        errors=[],
        repair_attempts=total_repairs,
        accuracy=None,
        accuracy_result=None,
    )
