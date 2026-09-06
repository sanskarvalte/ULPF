import sys; sys.path.insert(0, "backend")
import time, uuid
import duckdb
import pyarrow as pa
from datetime import datetime, timezone

c = duckdb.connect(":memory:")
c.execute("""
CREATE TABLE raw_events (
    raw_event_id VARCHAR PRIMARY KEY,
    raw_text TEXT NOT NULL,
    received_at TIMESTAMP NOT NULL,
    source_file VARCHAR,
    previous_hash VARCHAR,
    seq_num BIGINT
);
""")

c.execute("""
CREATE TABLE blockchain_ledger (
    block_index BIGINT PRIMARY KEY,
    timestamp VARCHAR NOT NULL,
    event_id VARCHAR NOT NULL,
    action VARCHAR NOT NULL,
    event_hash VARCHAR NOT NULL,
    previous_hash VARCHAR NOT NULL,
    block_hash VARCHAR NOT NULL
);
""")

N = 2000
now = datetime.now(timezone.utc)
raw_rows = [(f"id_{i}", f"log line {i} " * 5, now, "test.log", f"hash_{i-1}", i) for i in range(N)]
bc_rows = [(i, now.isoformat(), f"ev_{i}", "LOG_STORED", f"ehash_{i}", f"phash_{i}", f"bhash_{i}") for i in range(N)]

# Method 1: executemany
t0 = time.perf_counter()
c.executemany("INSERT INTO raw_events VALUES (?, ?, ?, ?, ?, ?)", raw_rows)
t_executemany = time.perf_counter() - t0

c.execute("DELETE FROM raw_events")

# Method 2: PyArrow
t0 = time.perf_counter()
tbl = pa.Table.from_pydict({
    "raw_event_id": [r[0] for r in raw_rows],
    "raw_text": [r[1] for r in raw_rows],
    "received_at": [r[2] for r in raw_rows],
    "source_file": [r[3] for r in raw_rows],
    "previous_hash": [r[4] for r in raw_rows],
    "seq_num": [r[5] for r in raw_rows],
})
c.register("_tbl", tbl)
c.execute("INSERT OR IGNORE INTO raw_events SELECT * FROM _tbl")
c.unregister("_tbl")
t_arrow = time.perf_counter() - t0

# Method 3: PyArrow for blockchain_ledger
t0 = time.perf_counter()
bc_tbl = pa.Table.from_pydict({
    "block_index": [r[0] for r in bc_rows],
    "timestamp": [r[1] for r in bc_rows],
    "event_id": [r[2] for r in bc_rows],
    "action": [r[3] for r in bc_rows],
    "event_hash": [r[4] for r in bc_rows],
    "previous_hash": [r[5] for r in bc_rows],
    "block_hash": [r[6] for r in bc_rows],
})
c.register("_bc_tbl", bc_tbl)
c.execute("INSERT INTO blockchain_ledger SELECT * FROM _bc_tbl")
c.unregister("_bc_tbl")
t_bc_arrow = time.perf_counter() - t0

print(f"2,000 rows executemany:        {t_executemany*1000:.2f} ms")
print(f"2,000 rows raw PyArrow:        {t_arrow*1000:.2f} ms")
print(f"2,000 rows blockchain PyArrow: {t_bc_arrow*1000:.2f} ms")
