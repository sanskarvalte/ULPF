"""
Core blockchain cryptographic calculations and block generator.
Provides deterministic SHA-256 block hashing, stable genesis block generation,
and block construction.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Optional

from app.blockchain.models import BatchBlock, BlockchainBlock

GENESIS_HASH = "0" * 64
GENESIS_TIMESTAMP = "2026-01-01T00:00:00Z"
GENESIS_EVENT_ID = "GENESIS"
GENESIS_ACTION = "GENESIS"
GENESIS_BATCH_ID = "GENESIS_BATCH_0000"


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


def compute_merkle_root(leaf_hashes: List[str]) -> str:
    """
    Computes deterministic SHA-256 Merkle root from constituent event hashes.
    1. If list is empty, returns 64 zeroes.
    2. If single item, returns sha256(item) or item if already 64-char hex.
    3. If odd length at any level, duplicates the last item.
    4. Computes parent = sha256(left + right) for each pair iteratively until root.
    """
    if not leaf_hashes:
        return GENESIS_HASH

    current_layer = [
        h if len(h) == 64 else hashlib.sha256(h.encode("utf-8")).hexdigest()
        for h in leaf_hashes
    ]

    if len(current_layer) == 1:
        return current_layer[0]

    while len(current_layer) > 1:
        next_layer = []
        if len(current_layer) % 2 == 1:
            current_layer.append(current_layer[-1])

        for i in range(0, len(current_layer), 2):
            combined = current_layer[i] + current_layer[i + 1]
            parent_hash = hashlib.sha256(combined.encode("utf-8")).hexdigest()
            next_layer.append(parent_hash)

        current_layer = next_layer

    return current_layer[0]


def build_merkle_tree(leaf_hashes: List[str]) -> Dict[str, Any]:
    """
    Constructs full Merkle tree representation for cryptographic inspection and proofs.
    """
    if not leaf_hashes:
        return {
            "root": GENESIS_HASH,
            "depth": 0,
            "total_leaves": 0,
            "levels_sample": [],
        }

    current_layer = [
        h if len(h) == 64 else hashlib.sha256(h.encode("utf-8")).hexdigest()
        for h in leaf_hashes
    ]
    levels = [[h[:16] + "..." for h in current_layer[:8]]]
    depth = 1

    while len(current_layer) > 1:
        next_layer = []
        if len(current_layer) % 2 == 1:
            current_layer.append(current_layer[-1])

        for i in range(0, len(current_layer), 2):
            combined = current_layer[i] + current_layer[i + 1]
            parent_hash = hashlib.sha256(combined.encode("utf-8")).hexdigest()
            next_layer.append(parent_hash)

        current_layer = next_layer
        depth += 1
        levels.append([h[:16] + "..." for h in current_layer[:8]])

    return {
        "root": current_layer[0],
        "depth": depth,
        "total_leaves": len(leaf_hashes),
        "levels_sample": levels,
    }


def calculate_batch_block_hash(
    block_index: int,
    timestamp: str,
    batch_id: str,
    event_count: int,
    merkle_root: str,
    previous_hash: str,
) -> str:
    """
    Deterministically computes SHA-256 anchor hash of canonical batch block contents.
    """
    payload = f"{block_index}|{timestamp}|{batch_id}|{event_count}|{merkle_root}|{previous_hash}"
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


def get_genesis_batch_block() -> BatchBlock:
    """
    Generates the deterministic Genesis Batch Block (Block 0).
    """
    anchor_hash = calculate_batch_block_hash(
        block_index=0,
        timestamp=GENESIS_TIMESTAMP,
        batch_id=GENESIS_BATCH_ID,
        event_count=0,
        merkle_root=GENESIS_HASH,
        previous_hash=GENESIS_HASH,
    )
    return BatchBlock(
        block_index=0,
        batch_id=GENESIS_BATCH_ID,
        timestamp=GENESIS_TIMESTAMP,
        event_count=0,
        merkle_root=GENESIS_HASH,
        batch_hash=anchor_hash,
        previous_hash=GENESIS_HASH,
        anchor_hash=anchor_hash,
        status="VERIFIED",
        verification_reason="Genesis batch anchor mathematically initialized.",
        verified_at=GENESIS_TIMESTAMP,
        sample_event_ids=[],
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


def create_batch_block(
    block_index: int,
    batch_id: str,
    event_hashes: List[str],
    previous_hash: str,
    timestamp: Optional[str] = None,
    status: str = "VERIFIED",
    verification_reason: Optional[str] = None,
    sample_event_ids: Optional[List[str]] = None,
) -> BatchBlock:
    """
    Constructs an anchored batch block with computed real Merkle root.
    """
    ts = timestamp or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    merkle_root = compute_merkle_root(event_hashes)
    event_count = len(event_hashes)
    anchor_hash = calculate_batch_block_hash(
        block_index=block_index,
        timestamp=ts,
        batch_id=batch_id,
        event_count=event_count,
        merkle_root=merkle_root,
        previous_hash=previous_hash,
    )
    return BatchBlock(
        block_index=block_index,
        batch_id=batch_id,
        timestamp=ts,
        event_count=event_count,
        merkle_root=merkle_root,
        batch_hash=anchor_hash,
        previous_hash=previous_hash,
        anchor_hash=anchor_hash,
        status=status,
        verification_reason=verification_reason or ("Cryptographically sealed and verified." if status == "VERIFIED" else None),
        verified_at=ts if status == "VERIFIED" else None,
        sample_event_ids=sample_event_ids or [],
    )

