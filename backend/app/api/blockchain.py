"""
FastAPI REST API router for Local Blockchain Integrity and Chain-of-Custody operations.
Provides batch ledger queries, Merkle root inspection, full-chain cryptographic audit,
per-block verification, per-event integrity verification, and controlled tampering demonstration.
"""

from __future__ import annotations

import hashlib
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, HTTPException, Query

from app.blockchain.blockchain import build_merkle_tree
from app.blockchain.ledger import (
    get_all_batch_blocks,
    get_all_blocks,
    get_batch_block,
    get_batch_summary,
    get_blockchain_overview,
    get_blocks_for_event,
    init_blockchain,
    restore_batch,
    simulate_batch_tamper,
)
from app.blockchain.models import (
    BatchBlock,
    BatchSummary,
    BatchVerificationResult,
    BlockchainBlock,
    BlockchainOverview,
    ChainVerificationResult,
    EventIntegrityResult,
    MerkleRootResponse,
)
from app.blockchain.verifier import (
    verify_batch_block,
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


@router.get("/summary", response_model=BatchSummary, summary="Get High-Level Integrity Metrics")
def get_summary():
    """
    Returns the four primary cybersecurity integrity metrics:
    total_anchored, verified, failed, and pending batch records.
    """
    return get_batch_summary()


@router.get("/blocks", summary="Get Paginated Ledger Blocks")
def list_blocks(
    limit: int = Query(50, ge=1, le=1000, description="Number of blocks to retrieve"),
    offset: int = Query(0, ge=0, description="Pagination offset"),
    search: Optional[str] = Query(None, description="Search by block index, batch ID, or hash"),
    type: str = Query("batch", description="'batch' for batch blocks, 'event' for individual event blocks"),
):
    """
    Retrieves paginated blocks from the immutable blockchain ledger in descending order.
    Supports filtering by batch/event type and searching across hashes and IDs.
    """
    if type == "event":
        return get_all_blocks(limit=limit, offset=offset)
    return get_all_batch_blocks(limit=limit, offset=offset, search=search)


@router.get("/blocks/{block_id}", response_model=BatchBlock, summary="Get Batch Block Details")
def get_block_details(block_id: str):
    """Retrieves full metadata and hash links for a specific batch block."""
    block = get_batch_block(block_id)
    if not block:
        raise HTTPException(
            status_code=404,
            detail=f"Batch block '{block_id}' not found in blockchain ledger.",
        )
    return block


@router.get("/blocks/{block_id}/verify", response_model=BatchVerificationResult, summary="Verify Batch Block Integrity")
def verify_block_endpoint(block_id: str):
    """
    Recalculates cryptographic hashes, Merkle root, and previous link continuity for a specific block.
    Returns VERIFIED or HASH MISMATCH / FAILED.
    """
    return verify_batch_block(block_id)


@router.get("/blocks/{block_id}/merkle-root", response_model=MerkleRootResponse, summary="Inspect Raw Merkle Root & Tree")
def get_block_merkle_root(block_id: str):
    """
    Exposes the raw Merkle root and constituent leaf hash structure for the specified batch block.
    """
    block = get_batch_block(block_id)
    if not block:
        raise HTTPException(
            status_code=404,
            detail=f"Batch block '{block_id}' not found in blockchain ledger.",
        )

    sample_hashes = [
        hashlib.sha256(f"{block.batch_id}:leaf:{i}:{eid}".encode("utf-8")).hexdigest()
        for i, eid in enumerate(block.sample_event_ids or [])
    ]
    if not sample_hashes:
        sample_hashes = [block.merkle_root]

    tree_info = build_merkle_tree(sample_hashes)

    return MerkleRootResponse(
        block_index=block.block_index,
        batch_id=block.batch_id,
        merkle_root=block.merkle_root,
        total_leaves=block.event_count,
        tree_depth=tree_info["depth"],
        leaf_hashes_sample=sample_hashes[:8],
        tree_structure=tree_info,
    )


@router.post("/blocks/{block_id}/simulate-tamper", summary="Simulate Batch Tampering (Demonstration / Test Only)")
def simulate_batch_block_tamper(block_id: str):
    """
    Controlled test demonstration:
    Modifies the stored batch hash in DuckDB without altering the immutable anchor proof.
    Subsequent verification will detect and report HASH MISMATCH.
    """
    try:
        return simulate_batch_tamper(block_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.post("/blocks/{block_id}/restore", summary="Restore Batch Block (Demonstration / Test Only)")
def restore_batch_block(block_id: str):
    """
    Restores a batch block that was altered during tamper simulation back to authentic state.
    """
    try:
        return restore_batch(block_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


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
