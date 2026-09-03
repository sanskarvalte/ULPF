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
