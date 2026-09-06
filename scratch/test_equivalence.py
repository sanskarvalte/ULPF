import sys; sys.path.insert(0, "backend")
import duckdb
import pyarrow as pa
from datetime import datetime, timezone
import uuid

from app.storage.db import get_db, reset_db_connection, _init_db_schema
from app.storage.raw import hash_raw_log, verify_chain, get_latest_hash
from app.blockchain.ledger import (
    init_blockchain,
    get_latest_block,
    create_block,
    BlockchainBlock,
    get_blockchain_overview,
)

c = duckdb.connect(":memory:")
_init_db_schema(c)
init_blockchain(c)

raw_records = [
    (hash_raw_log(f"log line {i}"), f"log line {i}", "test_eq.log")
    for i in range(100)
]
now = datetime.now(timezone.utc)
source_file = "test_eq.log"
prev_hash, last_seq = get_latest_hash(source_file, conn=c)

rows_to_insert = []
for r_id, r_text, s_file in raw_records:
    last_seq += 1
    canonical_id = hash_raw_log(r_text)
    rows_to_insert.append((canonical_id, r_text, now, s_file, prev_hash, last_seq))
    prev_hash = canonical_id

raw_tbl = pa.Table.from_pydict({
    "raw_event_id": [r[0] for r in rows_to_insert],
    "raw_text": [r[1] for r in rows_to_insert],
    "received_at": [r[2] for r in rows_to_insert],
    "source_file": [r[3] for r in rows_to_insert],
    "previous_hash": [r[4] for r in rows_to_insert],
    "seq_num": [r[5] for r in rows_to_insert],
})

c.register("_tmp_raw", raw_tbl)
c.execute("""
    INSERT OR IGNORE INTO raw_events (raw_event_id, raw_text, received_at, source_file, previous_hash, seq_num)
    SELECT * FROM _tmp_raw;
""")
c.unregister("_tmp_raw")

is_valid, checked, violations = verify_chain("test_eq.log", conn=c)
print(f"raw_events chain verification: valid={is_valid}, count={checked}, violations={violations}")
assert is_valid, "Raw events chain must be valid"
print("SUCCESS: raw_events hash chain is 100% valid with PyArrow batching!")
