import sys; sys.path.insert(0, "backend")
import duckdb
import pyarrow as pa
from datetime import datetime, timezone
import uuid

from app.storage.db import get_db, reset_db_connection, _init_db_schema
from app.storage.raw import hash_raw_log
from app.blockchain.ledger import (
    init_blockchain,
    get_latest_block,
    create_block,
    BlockchainBlock,
    get_blockchain_overview,
    append_event_blocks_batch,
)

c = duckdb.connect(":memory:")
_init_db_schema(c)
init_blockchain(c)

event_records = [(str(uuid.uuid4()), hash_raw_log(f"test event {i}")) for i in range(100)]
latest = get_latest_block(c)
curr_index = latest.block_index
curr_prev_hash = latest.block_hash
ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

new_blocks = []
rows_to_insert = []
for event_id, event_hash in event_records:
    curr_index += 1
    block = create_block(
        block_index=curr_index,
        event_id=event_id,
        event_hash=event_hash,
        previous_hash=curr_prev_hash,
        action="LOG_STORED",
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

bc_tbl = pa.Table.from_pydict({
    "block_index": [r[0] for r in rows_to_insert],
    "timestamp": [r[1] for r in rows_to_insert],
    "event_id": [r[2] for r in rows_to_insert],
    "action": [r[3] for r in rows_to_insert],
    "event_hash": [r[4] for r in rows_to_insert],
    "previous_hash": [r[5] for r in rows_to_insert],
    "block_hash": [r[6] for r in rows_to_insert],
})
c.register("_tmp_bc", bc_tbl)
c.execute("INSERT INTO blockchain_ledger SELECT * FROM _tmp_bc;")
c.unregister("_tmp_bc")

ov = get_blockchain_overview(conn=c)
print(f"blockchain_ledger: status={ov.chain_status}, total_blocks={ov.total_blocks}")
assert ov.chain_status == "VALID", f"Expected VALID, got {ov.chain_status}"
assert ov.total_blocks == 101, f"Expected 101 blocks, got {ov.total_blocks}"
print("SUCCESS: blockchain_ledger is 100% VALID with PyArrow batching!")
