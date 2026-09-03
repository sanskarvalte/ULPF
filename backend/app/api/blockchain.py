"""
FastAPI REST API router for Local Blockchain Integrity and Chain-of-Custody operations.
Provides ledger query, full-chain cryptographic audit, per-event integrity verification,
and controlled tampering demonstration endpoints.
"""

from __future__ import annotations

from typing import List, Optional
from fastapi import APIRouter, HTTPException, Query

from app.blockchain.ledger import (
    get_all_blocks,
    get_blocks_for_event,
    get_blockchain_overview,
    init_blockchain,
)
from app.blockchain.models import (
    BlockchainBlock,
    BlockchainOverview,
    ChainVerificationResult,
    EventIntegrityResult,
)
from app.blockchain.verifier import (
    verify_chain,
    verify_event_integrity,
)
from app.storage.db import get_db

router = APIRouter(prefix="/api/blockchain", tags=["Blockchain Integrity"])


@router.get("", response_model=BlockchainOverview, summary="Get Blockchain Overview")
@router.get("/", response_model=BlockchainOverview, include_in_schema=False)
def get_overview():
    """Returns overview statistics of the local blockchain ledger and recent blocks."""
    return get_blockchain_overview()


@router.get("/blocks", response_model=List[BlockchainBlock], summary="Get Paginated Ledger Blocks")
def list_blocks(
    limit: int = Query(50, ge=1, le=1000, description="Number of blocks to retrieve"),
    offset: int = Query(0, ge=0, description="Pagination offset"),
):
    """Retrieves paginated blocks from the immutable blockchain ledger in descending order."""
    return get_all_blocks(limit=limit, offset=offset)


@router.get("/verify", response_model=ChainVerificationResult, summary="Verify Entire Blockchain Integrity")
def audit_blockchain():
    """
    Performs a complete cryptographic verification of the blockchain ledger:
    Validates Genesis block, hashes of every block, and unbroken previous_hash chaining.
    """
    return verify_chain()


@router.get("/event/{event_id}", response_model=List[BlockchainBlock], summary="Get Chain-of-Custody for Event")
def get_event_chain_of_custody(event_id: str):
    """Retrieves all blockchain proof records associated with a specific event ID."""
    blocks = get_blocks_for_event(event_id)
    if not blocks:
        raise HTTPException(
            status_code=404,
            detail=f"No blockchain proof blocks found for event '{event_id}'.",
        )
    return blocks


@router.get("/integrity/{event_id}", response_model=EventIntegrityResult, summary="Verify Event Cryptographic Integrity")
def verify_event(event_id: str):
    """
    Recalculates the stored log's SHA-256 hash in DuckDB and compares it against
    the immutable blockchain proof recorded at ingestion.
    Returns VERIFIED or TAMPERED.
    """
    return verify_event_integrity(event_id)


@router.post("/simulate-tamper/{event_id}", summary="Simulate Log Tampering (Demonstration / Test Only)")
def simulate_tampering(event_id: str):
    """
    Controlled demonstration endpoint for cybersecurity evaluations:
    Modifies the stored raw_text of an event in DuckDB without updating the blockchain proof.
    Subsequent calls to /integrity/{event_id} will immediately detect and flag TAMPERED.
    """
    conn = get_db()
    # Find raw_event_id
    row = conn.execute(
        "SELECT raw_event_id FROM normalized_events WHERE event_id = ?",
        [event_id],
    ).fetchone()

    raw_id = row[0] if row and row[0] else event_id

    # Modify raw_text in raw_events to simulate unauthorized tampering
    raw_exists = conn.execute(
        "SELECT raw_text FROM raw_events WHERE raw_event_id = ?",
        [raw_id],
    ).fetchone()

    if not raw_exists:
        raise HTTPException(
            status_code=404,
            detail=f"Event '{event_id}' not found in DuckDB storage.",
        )

    original_text = raw_exists[0]
    tampered_text = original_text + " [UNAUTHORIZED_MODIFICATION_TEST]"

    conn.execute(
        "UPDATE raw_events SET raw_text = ? WHERE raw_event_id = ?",
        [tampered_text, raw_id],
    )

    return {
        "status": "tampered_for_demo",
        "event_id": event_id,
        "raw_event_id": raw_id,
        "original_sample": original_text[:60] + "...",
        "tampered_sample": tampered_text[:90] + "...",
        "message": "Event evidence in DuckDB has been modified. Call GET /api/blockchain/integrity/" + event_id + " to observe TAMPERED detection.",
    }


@router.post("/restore/{event_id}")
def restore_event(event_id: str):
    """
    Restores an event that had its raw text modified by the tamper simulation back to its authentic state.
    """
    conn = get_db()
    row = conn.execute(
        "SELECT raw_event_id FROM normalized_events WHERE event_id = ?",
        [event_id],
    ).fetchone()

    raw_id = row[0] if row and row[0] else event_id

    raw_exists = conn.execute(
        "SELECT raw_text FROM raw_events WHERE raw_event_id = ?",
        [raw_id],
    ).fetchone()

    if not raw_exists:
        raise HTTPException(
            status_code=404,
            detail=f"Event '{event_id}' not found in DuckDB storage.",
        )

    current_text = raw_exists[0]
    restored_text = current_text.replace(" [UNAUTHORIZED_MODIFICATION_TEST]", "").replace("[UNAUTHORIZED_MODIFICATION_TEST]", "")

    conn.execute(
        "UPDATE raw_events SET raw_text = ? WHERE raw_event_id = ?",
        [restored_text, raw_id],
    )

    return {
        "status": "restored",
        "event_id": event_id,
        "raw_event_id": raw_id,
        "message": "Event evidence restored to authentic text. Integrity verification will now report VERIFIED.",
    }
