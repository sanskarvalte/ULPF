"""
Pydantic data models for the Local Blockchain Integrity and Chain-of-Custody Layer.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class BlockchainBlock(BaseModel):
    """
    Lightweight, tamper-evident cryptographic block storing only evidence metadata and hashes.
    Actual log text/payload remains exclusively in DuckDB (raw_events / normalized_events).
    """
    block_index: int = Field(..., description="Monotonically increasing sequence index (0 = Genesis).")
    timestamp: str = Field(..., description="ISO 8601 UTC timestamp when block was created.")
    event_id: str = Field(..., description="Event UUID or GENESIS identifier.")
    action: str = Field(..., description="Lifecycle action (e.g. GENESIS, LOG_RECEIVED, LOG_NORMALIZED, LOG_STORED).")
    event_hash: str = Field(..., description="SHA-256 hash of the event's raw log content.")
    previous_hash: str = Field(..., description="SHA-256 hash of the preceding block in the chain.")
    block_hash: str = Field(..., description="Deterministic SHA-256 hash of this block's attributes.")


class EventIntegrityResult(BaseModel):
    """Result of verifying an individual stored log/event against its blockchain proof."""
    event_id: str
    status: str = Field(..., description="VERIFIED or TAMPERED")
    stored_hash: Optional[str] = None
    blockchain_hash: Optional[str] = None
    block_index: Optional[int] = None
    action: Optional[str] = None
    timestamp: Optional[str] = None
    message: str


class ChainVerificationResult(BaseModel):
    """Result of verifying the entire blockchain ledger continuity and block hashes."""
    valid: bool
    total_blocks: int
    verified_blocks: int
    invalid_block: Optional[int] = None
    reason: Optional[str] = None
    message: str


class BlockchainOverview(BaseModel):
    """Summary overview of the local blockchain ledger state."""
    total_blocks: int
    chain_status: str
    last_block_index: int
    last_block_hash: str
    last_updated: Optional[str] = None
    recent_blocks: List[BlockchainBlock] = []


class BatchBlock(BaseModel):
    """
    Tamper-evident batch block anchoring a processed set of security events.
    Contains cryptographic Merkle root of constituent event hashes, batch hash, and previous link.
    """
    block_index: int = Field(..., description="Monotonically increasing sequence index.")
    batch_id: str = Field(..., description="Unique batch identifier (e.g. SYNC_BATCH_X992A).")
    timestamp: str = Field(..., description="UTC ISO 8601 timestamp.")
    event_count: int = Field(..., description="Number of events anchored in this batch.")
    merkle_root: str = Field(..., description="SHA-256 Merkle root of all event hashes in the batch.")
    batch_hash: str = Field(..., description="Local stored hash representing the batch content.")
    previous_hash: str = Field(..., description="Hash of the preceding batch block in the chain.")
    anchor_hash: str = Field(..., description="Cryptographic sealed anchor hash of this block.")
    status: str = Field(default="VERIFIED", description="VERIFIED, FAILED, or PENDING.")
    verification_reason: Optional[str] = Field(None, description="Detailed verification status or failure reason.")
    verified_at: Optional[str] = None
    sample_event_ids: List[str] = Field(default_factory=list, description="Sample event IDs in this batch.")


class BatchSummary(BaseModel):
    """Integrity metrics summary for the top dashboard cards."""
    total_anchored: int = Field(..., description="Total batch blocks anchored in the ledger.")
    verified: int = Field(..., description="Count of successfully verified blocks.")
    failed: int = Field(..., description="Count of failed/hash-mismatched blocks.")
    pending: int = Field(..., description="Count of pending/unconfirmed blocks.")
    chain_status: str = Field(default="VALID", description="Overall chain state: VALID or CORRUPTED.")
    last_block_index: int = 0
    last_block_hash: str = ""
    last_updated: Optional[str] = None


class MerkleRootResponse(BaseModel):
    """Detailed Merkle root response for the raw inspector."""
    block_index: int
    batch_id: str
    merkle_root: str
    total_leaves: int
    tree_depth: int
    leaf_hashes_sample: List[str] = []
    tree_structure: Optional[Dict[str, Any]] = None


class BatchVerificationResult(BaseModel):
    """Result of recalculating and verifying a batch block."""
    block_index: int
    batch_id: str
    status: str  # VERIFIED, FAILED, PENDING
    is_valid: bool
    local_stored_hash: str
    ledger_anchor_hash: str
    merkle_root: str
    previous_hash_valid: bool
    message: str

