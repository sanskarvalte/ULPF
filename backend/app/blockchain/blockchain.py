"""
Core blockchain cryptographic calculations and block generator.
Provides deterministic SHA-256 block hashing, stable genesis block generation,
and block construction.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Optional

from app.blockchain.models import BlockchainBlock

GENESIS_HASH = "0" * 64
GENESIS_TIMESTAMP = "2026-01-01T00:00:00Z"
GENESIS_EVENT_ID = "GENESIS"
GENESIS_ACTION = "GENESIS"


def calculate_block_hash(
    block_index: int,
    timestamp: str,
    event_id: str,
    action: str,
    event_hash: str,
    previous_hash: str,
) -> str:
    """
    Deterministically computes SHA-256 hash of canonical block contents.
    Ensures identical block attributes always produce the exact same block hash.
    """
    payload = f"{block_index}|{timestamp}|{event_id}|{action}|{event_hash}|{previous_hash}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def get_genesis_block() -> BlockchainBlock:
    """
    Generates the deterministic Genesis block (Block 0).
    The Genesis block is mathematically fixed and invariant across application restarts.
    """
    block_hash = calculate_block_hash(
        block_index=0,
        timestamp=GENESIS_TIMESTAMP,
        event_id=GENESIS_EVENT_ID,
        action=GENESIS_ACTION,
        event_hash=GENESIS_HASH,
        previous_hash=GENESIS_HASH,
    )
    return BlockchainBlock(
        block_index=0,
        timestamp=GENESIS_TIMESTAMP,
        event_id=GENESIS_EVENT_ID,
        action=GENESIS_ACTION,
        event_hash=GENESIS_HASH,
        previous_hash=GENESIS_HASH,
        block_hash=block_hash,
    )


def create_block(
    block_index: int,
    event_id: str,
    event_hash: str,
    previous_hash: str,
    action: str = "LOG_STORED",
    timestamp: Optional[str] = None,
) -> BlockchainBlock:
    """
    Constructs a new blockchain block linked to the preceding block via previous_hash.
    """
    ts = timestamp or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    block_hash = calculate_block_hash(
        block_index=block_index,
        timestamp=ts,
        event_id=event_id,
        action=action,
        event_hash=event_hash,
        previous_hash=previous_hash,
    )
    return BlockchainBlock(
        block_index=block_index,
        timestamp=ts,
        event_id=event_id,
        action=action,
        event_hash=event_hash,
        previous_hash=previous_hash,
        block_hash=block_hash,
    )
