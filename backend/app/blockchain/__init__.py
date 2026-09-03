"""
ULPF Local Blockchain Integrity & Chain-of-Custody Layer.
Provides tamper-evident cryptographic proof ledgers for security log preservation.
"""

from app.blockchain.blockchain import (
    GENESIS_HASH,
    calculate_block_hash,
    create_block,
    get_genesis_block,
)
from app.blockchain.ledger import (
    append_block,
    append_event_blocks_batch,
    get_all_blocks,
    get_blocks_for_event,
    get_blockchain_overview,
    get_latest_block,
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

__all__ = [
    "BlockchainBlock",
    "BlockchainOverview",
    "ChainVerificationResult",
    "EventIntegrityResult",
    "GENESIS_HASH",
    "append_block",
    "append_event_blocks_batch",
    "calculate_block_hash",
    "create_block",
    "get_all_blocks",
    "get_blocks_for_event",
    "get_blockchain_overview",
    "get_genesis_block",
    "get_latest_block",
    "init_blockchain",
    "verify_chain",
    "verify_event_integrity",
]
