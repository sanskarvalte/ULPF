"""
ULPF Local Blockchain Integrity & Chain-of-Custody Layer.
Provides tamper-evident cryptographic proof ledgers for security log preservation.
"""

from app.blockchain.blockchain import (
    GENESIS_HASH,
    build_merkle_tree,
    calculate_batch_block_hash,
    calculate_block_hash,
    compute_merkle_root,
    create_batch_block,
    create_block,
    get_genesis_batch_block,
    get_genesis_block,
)
from app.blockchain.ledger import (
    append_batch_block,
    append_block,
    append_event_blocks_batch,
    get_all_batch_blocks,
    get_all_blocks,
    get_batch_block,
    get_batch_summary,
    get_blockchain_overview,
    get_blocks_for_event,
    get_latest_block,
    init_batch_ledger,
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

__all__ = [
    "BatchBlock",
    "BatchSummary",
    "BatchVerificationResult",
    "BlockchainBlock",
    "BlockchainOverview",
    "ChainVerificationResult",
    "EventIntegrityResult",
    "GENESIS_HASH",
    "MerkleRootResponse",
    "append_batch_block",
    "append_block",
    "append_event_blocks_batch",
    "build_merkle_tree",
    "calculate_batch_block_hash",
    "calculate_block_hash",
    "compute_merkle_root",
    "create_batch_block",
    "create_block",
    "get_all_batch_blocks",
    "get_all_blocks",
    "get_batch_block",
    "get_batch_summary",
    "get_blockchain_overview",
    "get_blocks_for_event",
    "get_genesis_batch_block",
    "get_genesis_block",
    "get_latest_block",
    "init_batch_ledger",
    "init_blockchain",
    "restore_batch",
    "simulate_batch_tamper",
    "verify_batch_block",
    "verify_chain",
    "verify_event_integrity",
]
