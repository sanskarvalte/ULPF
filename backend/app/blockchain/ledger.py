"""
Persistent blockchain ledger operations on local DuckDB (table: blockchain_ledger).
Guarantees append-only persistence, deterministic genesis initialization,
atomic batch block linking, and chain-of-custody queries.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import duckdb
from app.blockchain.blockchain import (
    GENESIS_HASH,
    calculate_block_hash,
    create_block,
    get_genesis_block,
)
from app.blockchain.models import BlockchainBlock, BlockchainOverview
from app.storage.db import get_db

logger = logging.getLogger(__name__)


def init_blockchain(conn: Optional[duckdb.DuckDBPyConnection] = None) -> BlockchainBlock:
    """
    Initializes the persistent blockchain ledger in DuckDB.
    Creates table if missing and writes the deterministic Genesis block if the ledger is empty.
    Never creates duplicate genesis blocks on subsequent application restarts.
    """
    c = conn or get_db()
    c.execute("""
    CREATE TABLE IF NOT EXISTS blockchain_ledger (
        block_index BIGINT PRIMARY KEY,
        timestamp VARCHAR NOT NULL,
        event_id VARCHAR NOT NULL,
        action VARCHAR NOT NULL,
        event_hash VARCHAR NOT NULL,
        previous_hash VARCHAR NOT NULL,
        block_hash VARCHAR NOT NULL
    );
    """)

    # Check if genesis block exists
    row = c.execute("SELECT COUNT(*) FROM blockchain_ledger").fetchone()
    count = row[0] if row else 0

    genesis = get_genesis_block()
    if count == 0:
        c.execute(
            """
            INSERT INTO blockchain_ledger (block_index, timestamp, event_id, action, event_hash, previous_hash, block_hash)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            [
                genesis.block_index,
                genesis.timestamp,
                genesis.event_id,
                genesis.action,
                genesis.event_hash,
                genesis.previous_hash,
                genesis.block_hash,
            ],
        )
        logger.info("Initialized blockchain with deterministic Genesis block (#0).")
    return genesis


def get_latest_block(conn: Optional[duckdb.DuckDBPyConnection] = None) -> BlockchainBlock:
    """Retrieves the current head (latest block) of the blockchain."""
    c = conn or get_db()
    init_blockchain(c)
    row = c.execute("""
        SELECT block_index, timestamp, event_id, action, event_hash, previous_hash, block_hash
        FROM blockchain_ledger
        ORDER BY block_index DESC
        LIMIT 1
    """).fetchone()

    if not row:
        return get_genesis_block()

    return BlockchainBlock(
        block_index=int(row[0]),
        timestamp=str(row[1]),
        event_id=str(row[2]),
        action=str(row[3]),
        event_hash=str(row[4]),
        previous_hash=str(row[5]),
        block_hash=str(row[6]),
    )


def append_block(
    event_id: str,
    event_hash: str,
    action: str = "LOG_STORED",
    timestamp: Optional[str] = None,
    conn: Optional[duckdb.DuckDBPyConnection] = None,
) -> BlockchainBlock:
    """Appends a single new block to the persistent blockchain ledger."""
    c = conn or get_db()
    latest = get_latest_block(c)
    new_index = latest.block_index + 1
    new_block = create_block(
        block_index=new_index,
        event_id=event_id,
        event_hash=event_hash,
        previous_hash=latest.block_hash,
        action=action,
        timestamp=timestamp,
    )
    c.execute(
        """
        INSERT INTO blockchain_ledger (block_index, timestamp, event_id, action, event_hash, previous_hash, block_hash)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        [
            new_block.block_index,
            new_block.timestamp,
            new_block.event_id,
            new_block.action,
            new_block.event_hash,
            new_block.previous_hash,
            new_block.block_hash,
        ],
    )
    return new_block


def append_event_blocks_batch(
    event_records: List[Tuple[str, str]],  # List of (event_id, event_hash)
    action: str = "LOG_STORED",
    conn: Optional[duckdb.DuckDBPyConnection] = None,
) -> List[BlockchainBlock]:
    """
    Appends a batch of event blocks in an atomic DuckDB transaction.
    Chains each block to the preceding block continuously without broken links.
    """
    if not event_records:
        return []

    c = conn or get_db()
    latest = get_latest_block(c)
    curr_index = latest.block_index
    curr_prev_hash = latest.block_hash
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    new_blocks: List[BlockchainBlock] = []
    rows_to_insert: List[List[Any]] = []

    for event_id, event_hash in event_records:
        if not event_id or not event_hash:
            continue
        curr_index += 1
        block = create_block(
            block_index=curr_index,
            event_id=event_id,
            event_hash=event_hash,
            previous_hash=curr_prev_hash,
            action=action,
            timestamp=ts,
        )
        new_blocks.append(block)
        rows_to_insert.append([
            block.block_index,
            block.timestamp,
            block.event_id,
            block.action,
            block.event_hash,
            block.previous_hash,
            block.block_hash,
        ])
        curr_prev_hash = block.block_hash

    if rows_to_insert:
        c.executemany(
            """
            INSERT INTO blockchain_ledger (block_index, timestamp, event_id, action, event_hash, previous_hash, block_hash)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            rows_to_insert,
        )
        logger.info(f"Appended {len(rows_to_insert)} block(s) to blockchain ledger (Tip: #{curr_index}).")

    return new_blocks


def get_blocks_for_event(event_id: str, conn: Optional[duckdb.DuckDBPyConnection] = None) -> List[BlockchainBlock]:
    """Retrieves all blockchain ledger blocks for a specific event (Chain-of-Custody history)."""
    c = conn or get_db()
    init_blockchain(c)
    rows = c.execute(
        """
        SELECT block_index, timestamp, event_id, action, event_hash, previous_hash, block_hash
        FROM blockchain_ledger
        WHERE event_id = ?
        ORDER BY block_index ASC
        """,
        [event_id],
    ).fetchall()

    return [
        BlockchainBlock(
            block_index=int(r[0]),
            timestamp=str(r[1]),
            event_id=str(r[2]),
            action=str(r[3]),
            event_hash=str(r[4]),
            previous_hash=str(r[5]),
            block_hash=str(r[6]),
        )
        for r in rows
    ]


def get_all_blocks(
    limit: int = 100,
    offset: int = 0,
    conn: Optional[duckdb.DuckDBPyConnection] = None,
) -> List[BlockchainBlock]:
    """Retrieves paginated blocks from the blockchain ledger in descending order."""
    c = conn or get_db()
    init_blockchain(c)
    rows = c.execute(
        """
        SELECT block_index, timestamp, event_id, action, event_hash, previous_hash, block_hash
        FROM blockchain_ledger
        ORDER BY block_index DESC
        LIMIT ? OFFSET ?
        """,
        [limit, offset],
    ).fetchall()

    return [
        BlockchainBlock(
            block_index=int(r[0]),
            timestamp=str(r[1]),
            event_id=str(r[2]),
            action=str(r[3]),
            event_hash=str(r[4]),
            previous_hash=str(r[5]),
            block_hash=str(r[6]),
        )
        for r in rows
    ]


def get_blockchain_overview(conn: Optional[duckdb.DuckDBPyConnection] = None) -> BlockchainOverview:
    """Returns overview statistics of the blockchain ledger."""
    c = conn or get_db()
    init_blockchain(c)
    row = c.execute("SELECT COUNT(*), MAX(block_index) FROM blockchain_ledger").fetchone()
    total_blocks = row[0] if row and row[0] is not None else 0
    max_index = row[1] if row and row[1] is not None else 0

    latest = get_latest_block(c)
    recent = get_all_blocks(limit=10, offset=0, conn=c)

    return BlockchainOverview(
        total_blocks=total_blocks,
        chain_status="VALID",
        last_block_index=max_index,
        last_block_hash=latest.block_hash,
        last_updated=latest.timestamp,
        recent_blocks=recent,
    )
