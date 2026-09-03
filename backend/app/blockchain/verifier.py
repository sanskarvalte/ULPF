"""
Integrity verification engine for individual security events and the full blockchain ledger.
Detects data tampering, block corruption, broken previous_hash links, and missing proofs.
"""

from __future__ import annotations

import hashlib
from typing import Optional

import duckdb
from app.blockchain.blockchain import (
    GENESIS_HASH,
    calculate_block_hash,
    get_genesis_block,
)
from app.blockchain.ledger import append_block, get_blocks_for_event, init_blockchain
from app.blockchain.models import ChainVerificationResult, EventIntegrityResult
from app.storage.db import get_db
from app.storage.raw import hash_raw_log


def verify_event_integrity(
    event_id: str,
    conn: Optional[duckdb.DuckDBPyConnection] = None,
) -> EventIntegrityResult:
    """
    Verifies the cryptographic integrity of a stored security event against its blockchain proof.
    1. Retrieves the actual stored event & raw text from DuckDB.
    2. Recalculates its SHA-256 hash using the same hash_raw_log logic used at ingestion.
    3. Retrieves the recorded blockchain proof from blockchain_ledger (or anchors if valid uncommitted log).
    4. Compares the two hashes to detect any tampering or modification.
    """
    c = conn or get_db()
    init_blockchain(c)

    # 1. Fetch actual stored event from DuckDB (normalized_events and raw_events)
    norm_row = c.execute(
        """
        SELECT event_id, raw_event_id
        FROM normalized_events
        WHERE event_id = ?
        """,
        [event_id],
    ).fetchone()

    raw_text = None
    raw_id = None
    if norm_row and norm_row[1]:
        raw_id = norm_row[1]
        raw_row = c.execute(
            """
            SELECT raw_text
            FROM raw_events
            WHERE raw_event_id = ?
            """,
            [raw_id],
        ).fetchone()
        if raw_row:
            raw_text = raw_row[0]

    # Fallback: check if event_id is directly a raw_event_id
    if raw_text is None:
        raw_direct = c.execute(
            """
            SELECT raw_text
            FROM raw_events
            WHERE raw_event_id = ?
            """,
            [event_id],
        ).fetchone()
        if raw_direct:
            raw_text = raw_direct[0]
            raw_id = event_id

    # 2. Fetch blockchain blocks for this event
    blocks = get_blocks_for_event(event_id, conn=c)

    # If no blockchain proof exists yet, check if this is an unanchored valid database record
    if not blocks:
        if raw_text is not None:
            calculated_hash = hash_raw_log(raw_text)
            if raw_id and calculated_hash == raw_id:
                # Valid unanchored event: anchor to blockchain ledger
                new_block = append_block(event_id=event_id, event_hash=calculated_hash, action="LOG_STORED", conn=c)
                return EventIntegrityResult(
                    event_id=event_id,
                    status="VERIFIED",
                    stored_hash=calculated_hash,
                    blockchain_hash=new_block.event_hash,
                    block_index=new_block.block_index,
                    action=new_block.action,
                    timestamp=new_block.timestamp,
                    message="Event cryptographic integrity verified and anchored to immutable blockchain ledger.",
                )
        return EventIntegrityResult(
            event_id=event_id,
            status="TAMPERED",
            stored_hash=hash_raw_log(raw_text) if raw_text else None,
            blockchain_hash=None,
            block_index=None,
            action=None,
            timestamp=None,
            message=f"No blockchain proof found for event '{event_id}'. Event may be uncommitted or forged.",
        )

    latest_block = blocks[-1]
    expected_hash = latest_block.event_hash

    if raw_text is None:
        return EventIntegrityResult(
            event_id=event_id,
            status="TAMPERED",
            stored_hash=None,
            blockchain_hash=expected_hash,
            block_index=latest_block.block_index,
            action=latest_block.action,
            timestamp=latest_block.timestamp,
            message=f"Stored event evidence missing from DuckDB. Record may have been deleted or corrupted.",
        )

    # 3. Recalculate SHA-256
    calculated_hash = hash_raw_log(raw_text)

    # 4. Compare
    if calculated_hash == expected_hash:
        return EventIntegrityResult(
            event_id=event_id,
            status="VERIFIED",
            stored_hash=calculated_hash,
            blockchain_hash=expected_hash,
            block_index=latest_block.block_index,
            action=latest_block.action,
            timestamp=latest_block.timestamp,
            message="Event cryptographic integrity successfully verified against immutable blockchain proof.",
        )
    else:
        return EventIntegrityResult(
            event_id=event_id,
            status="TAMPERED",
            stored_hash=calculated_hash,
            blockchain_hash=expected_hash,
            block_index=latest_block.block_index,
            action=latest_block.action,
            timestamp=latest_block.timestamp,
            message=f"Cryptographic hash mismatch! Stored evidence has been altered after blockchain commitment.",
        )


def verify_chain(conn: Optional[duckdb.DuckDBPyConnection] = None) -> ChainVerificationResult:
    """
    Performs full cryptographic audit across the entire blockchain ledger:
    1. Validates Genesis block (#0).
    2. Validates block hash recalculation for every block.
    3. Validates continuity (block.previous_hash == previous_block.block_hash).
    4. Validates monotonic block sequence indices.
    """
    c = conn or get_db()
    init_blockchain(c)

    rows = c.execute(
        """
        SELECT block_index, timestamp, event_id, action, event_hash, previous_hash, block_hash
        FROM blockchain_ledger
        ORDER BY block_index ASC
        """
    ).fetchall()

    if not rows:
        return ChainVerificationResult(
            valid=False,
            total_blocks=0,
            verified_blocks=0,
            invalid_block=0,
            reason="Blockchain ledger is empty (missing Genesis block).",
            message="Blockchain validation failed.",
        )

    genesis = get_genesis_block()
    first = rows[0]

    # Check Genesis block
    if (
        int(first[0]) != 0
        or str(first[2]) != genesis.event_id
        or str(first[4]) != genesis.event_hash
        or str(first[5]) != genesis.previous_hash
        or str(first[6]) != genesis.block_hash
    ):
        return ChainVerificationResult(
            valid=False,
            total_blocks=len(rows),
            verified_blocks=0,
            invalid_block=0,
            reason=f"Genesis block (#0) is corrupted or altered. Expected hash {genesis.block_hash}, got {first[6]}.",
            message="Genesis block validation failed.",
        )

    expected_prev_hash = genesis.block_hash
    verified_count = 1

    for idx, r in enumerate(rows[1:], start=1):
        b_idx = int(r[0])
        b_ts = str(r[1])
        b_evt = str(r[2])
        b_act = str(r[3])
        b_evt_hash = str(r[4])
        b_prev_hash = str(r[5])
        b_stored_hash = str(r[6])

        # 1. Check index continuity
        if b_idx != idx:
            return ChainVerificationResult(
                valid=False,
                total_blocks=len(rows),
                verified_blocks=verified_count,
                invalid_block=b_idx,
                reason=f"Broken sequence index: expected #{idx}, got #{b_idx}.",
                message=f"Blockchain validation failed at block #{b_idx}.",
            )

        # 2. Check previous_hash link
        if b_prev_hash != expected_prev_hash:
            return ChainVerificationResult(
                valid=False,
                total_blocks=len(rows),
                verified_blocks=verified_count,
                invalid_block=b_idx,
                reason=f"Broken chain link at block #{b_idx}: previous_hash does not match preceding block's hash. Expected {expected_prev_hash}, got {b_prev_hash}.",
                message=f"Blockchain validation failed at block #{b_idx}.",
            )

        # 3. Check block hash recalculation
        recalculated_hash = calculate_block_hash(
            block_index=b_idx,
            timestamp=b_ts,
            event_id=b_evt,
            action=b_act,
            event_hash=b_evt_hash,
            previous_hash=b_prev_hash,
        )
        if b_stored_hash != recalculated_hash:
            return ChainVerificationResult(
                valid=False,
                total_blocks=len(rows),
                verified_blocks=verified_count,
                invalid_block=b_idx,
                reason=f"Tampered block payload at block #{b_idx}: stored block_hash {b_stored_hash} does not match recalculated hash {recalculated_hash}.",
                message=f"Blockchain validation failed at block #{b_idx}.",
            )

        expected_prev_hash = b_stored_hash
        verified_count += 1

    return ChainVerificationResult(
        valid=True,
        total_blocks=len(rows),
        verified_blocks=verified_count,
        invalid_block=None,
        reason=None,
        message=f"Blockchain integrity verified successfully ({verified_count}/{len(rows)} blocks cryptographically validated).",
    )
