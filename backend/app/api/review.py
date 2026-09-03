"""
Human Review & Dynamic Parser Registration API (Node 6 & Node 7).
Provides endpoints to list pending AI suggestions, approve new formats into custom parsers,
and reject/dismiss unknown suggestions.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field

from app.ingestion.detector import register_custom_parser_matcher
from app.storage.custom_parsers import (
    delete_custom_parser,
    get_custom_parser,
    list_custom_parsers,
    save_custom_parser,
)
from app.storage.review_queue import (
    get_pending_reviews,
    get_review_by_fingerprint,
    update_review_status,
)

router = APIRouter(prefix="/reviews", tags=["Human Review & Dynamic Parsers"])


class ApproveReviewRequest(BaseModel):
    format_name: Optional[str] = Field(None, description="Approved format name (e.g. 'nginx_access', 'custom_auth').")
    pattern_regex: Optional[str] = Field(None, description="Optional regex pattern to match this format shape.")
    field_mapping: Optional[Dict[str, Any]] = Field(None, description="Final approved OCSF field mappings.")
    approved_by: Optional[str] = Field("security_analyst", description="Name/ID of reviewer.")


class ReviewActionResponse(BaseModel):
    status: str
    message: str
    fingerprint: str
    format_name: str


@router.get("/pending", summary="List all pending format suggestions awaiting human review (Node 6)")
def list_pending() -> List[Dict[str, Any]]:
    """Retrieve all pending format shapes and Ollama suggestions."""
    return get_pending_reviews()


@router.get("/parsers", summary="List all persistent approved custom parsers (Node 7)")
def list_parsers() -> List[Dict[str, Any]]:
    """Retrieve all registered dynamic custom parsers."""
    return list_custom_parsers()


@router.get("/{fingerprint}", summary="Get review details by fingerprint")
def get_review(fingerprint: str) -> Dict[str, Any]:
    item = get_review_by_fingerprint(fingerprint)
    if not item:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Review item for fingerprint '{fingerprint}' not found.",
        )
    return item


@router.post("/{fingerprint}/approve", response_model=ReviewActionResponse, summary="Approve mapping & save as new parser (Node 6 & 7)")
def approve_review(fingerprint: str, payload: Optional[ApproveReviewRequest] = None) -> ReviewActionResponse:
    """
    Approve an AI suggestion:
    1. Persists { format_name, fingerprint, pattern_regex, field_mapping, approved_by, approved_at } to custom_parsers table.
    2. Dynamically registers the new signature matcher (Node 3) and dynamic parser (Node 4).
    3. Future logs matching this shape will hit the YES branch and bypass Ollama completely!
    """
    item = get_review_by_fingerprint(fingerprint)
    if not item:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Review item for fingerprint '{fingerprint}' not found.",
        )

    suggested = item.get("suggested_mapping") or {}
    
    # Resolve format name
    format_name = (
        (payload and payload.format_name)
        or suggested.get("format_name")
        or item.get("format_name")
        or f"custom_{fingerprint[:8]}"
    ).strip().lower().replace(" ", "_")

    # Resolve pattern regex
    pattern_regex = (
        (payload and payload.pattern_regex)
        or suggested.get("regex_pattern")
        or item.get("sample_line")
    )

    # Resolve field mappings
    field_mapping = (
        (payload and payload.field_mapping)
        or suggested.get("field_mapping")
        or {}
    )

    approved_by = (payload and payload.approved_by) or "security_analyst"

    # 1. Save to persistent storage (Node 7)
    save_custom_parser(
        format_name=format_name,
        fingerprint=fingerprint,
        pattern_regex=pattern_regex,
        field_mapping=field_mapping,
        approved_by=approved_by,
    )

    # 2. Dynamically register in Node 3 (Format Matcher) and Node 4 (Rule Parser)
    register_custom_parser_matcher(
        format_name=format_name,
        pattern_regex=pattern_regex,
        field_mapping=field_mapping,
        vendor=suggested.get("vendor"),
        product=suggested.get("product"),
    )

    # 3. Mark review queue item as approved
    update_review_status(fingerprint, "approved")

    return ReviewActionResponse(
        status="success",
        message=f"Parser '{format_name}' successfully compiled, saved, and registered into active pipeline.",
        fingerprint=fingerprint,
        format_name=format_name,
    )


@router.post("/{fingerprint}/reject", response_model=ReviewActionResponse, summary="Reject / dismiss a suggested format")
def reject_review(fingerprint: str) -> ReviewActionResponse:
    """Dismiss a pending review suggestion."""
    item = get_review_by_fingerprint(fingerprint)
    if not item:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Review item for fingerprint '{fingerprint}' not found.",
        )

    update_review_status(fingerprint, "rejected")
    return ReviewActionResponse(
        status="success",
        message=f"Suggestion for fingerprint '{fingerprint}' rejected.",
        fingerprint=fingerprint,
        format_name=item.get("format_name", "unknown"),
    )


@router.delete("/parsers/{format_name}", summary="Delete an approved custom parser")
def delete_parser(format_name: str) -> Dict[str, str]:
    delete_custom_parser(format_name)
    return {"status": "success", "message": f"Custom parser '{format_name}' removed."}
