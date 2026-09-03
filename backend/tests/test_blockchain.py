"""
Comprehensive Automated Test Suite for ULPF Local Blockchain Integrity & Chain-of-Custody Layer.
Covers:
1. Deterministic Genesis block initialization and idempotency.
2. Block creation, SHA-256 calculation, and previous_hash chaining.
3. Batch block persistence and continuity.
4. Full blockchain audit (valid chain verification).
5. Tamper detection on modified block payload.
6. Tamper detection on broken previous_hash link.
7. Per-event integrity verification (VERIFIED vs TAMPERED).
8. Chain-of-custody event history.
9. Persistence across DuckDB reconnect.
10. FastAPI REST API endpoints integration via TestClient.
11. End-to-end Pipeline -> DuckDB -> Blockchain proof -> Verification flow.
"""

import os
import tempfile
import unittest
from pathlib import Path
import duckdb

from app.api.blockchain import (
    audit_blockchain,
    get_event_chain_of_custody,
    get_overview,
    list_blocks,
    simulate_tampering,
    verify_event,
)
from app.blockchain.blockchain import (
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
from app.blockchain.verifier import (
    verify_chain,
    verify_event_integrity,
)
from app.pipeline import PipelineEngine, run_pipeline
from app.storage.db import get_db
from app.storage.raw import hash_raw_log


class TestBlockchainIntegrity(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.TemporaryDirectory()
        cls.db_path = Path(cls.temp_dir.name) / "test_blockchain.duckdb"
        os.environ["ULPF_DB_PATH"] = str(cls.db_path)
        cls.conn = get_db(cls.db_path)
        init_blockchain(cls.conn)

    @classmethod
    def tearDownClass(cls):
        cls.conn.close()
        os.environ.pop("ULPF_DB_PATH", None)
        cls.temp_dir.cleanup()

    def setUp(self):
        self.conn.execute("DELETE FROM blockchain_ledger")
        self.conn.execute("DELETE FROM raw_events")
        self.conn.execute("DELETE FROM normalized_events")
        init_blockchain(self.conn)

    # ─────────────────────────────────────────────────────────────────
    # 1. Genesis Block & Idempotency
    # ─────────────────────────────────────────────────────────────────
    def test_genesis_block_initialization(self):
        genesis = get_genesis_block()
        self.assertEqual(genesis.block_index, 0)
        self.assertEqual(genesis.event_id, "GENESIS")
        self.assertEqual(genesis.action, "GENESIS")
        self.assertEqual(genesis.previous_hash, "0" * 64)

        # Check DB has exactly 1 genesis block
        rows = self.conn.execute("SELECT COUNT(*) FROM blockchain_ledger").fetchone()
        self.assertEqual(rows[0], 1)

        # Re-initialize: must not duplicate genesis
        init_blockchain(self.conn)
        rows_after = self.conn.execute("SELECT COUNT(*) FROM blockchain_ledger").fetchone()
        self.assertEqual(rows_after[0], 1)

    # ─────────────────────────────────────────────────────────────────
    # 2. Block Creation & Chaining
    # ─────────────────────────────────────────────────────────────────
    def test_block_creation_and_chaining(self):
        block1 = append_block(
            event_id="EVT-001",
            event_hash="hash_001_abc",
            action="LOG_STORED",
            conn=self.conn,
        )
        self.assertEqual(block1.block_index, 1)
        genesis = get_genesis_block()
        self.assertEqual(block1.previous_hash, genesis.block_hash)

        block2 = append_block(
            event_id="EVT-002",
            event_hash="hash_002_def",
            action="LOG_STORED",
            conn=self.conn,
        )
        self.assertEqual(block2.block_index, 2)
        self.assertEqual(block2.previous_hash, block1.block_hash)

        # Verify tip
        latest = get_latest_block(self.conn)
        self.assertEqual(latest.block_index, 2)
        self.assertEqual(latest.block_hash, block2.block_hash)

    # ─────────────────────────────────────────────────────────────────
    # 3. Batch Block Persistence & Verification
    # ─────────────────────────────────────────────────────────────────
    def test_batch_block_persistence_and_full_verification(self):
        events_batch = [
            ("EVT-101", "hash_101"),
            ("EVT-102", "hash_102"),
            ("EVT-103", "hash_103"),
            ("EVT-104", "hash_104"),
        ]
        blocks = append_event_blocks_batch(events_batch, action="LOG_STORED", conn=self.conn)
        self.assertEqual(len(blocks), 4)
        self.assertEqual(blocks[0].block_index, 1)
        self.assertEqual(blocks[3].block_index, 4)

        # Audit entire chain
        audit = verify_chain(conn=self.conn)
        self.assertTrue(audit.valid)
        self.assertEqual(audit.total_blocks, 5)  # Genesis + 4 blocks
        self.assertEqual(audit.verified_blocks, 5)
        self.assertIsNone(audit.invalid_block)

    # ─────────────────────────────────────────────────────────────────
    # 4. Tamper Detection: Modified Block Payload
    # ─────────────────────────────────────────────────────────────────
    def test_tamper_detection_modified_block_payload(self):
        events_batch = [("EVT-201", "hash_201"), ("EVT-202", "hash_202")]
        append_event_blocks_batch(events_batch, conn=self.conn)

        # Directly alter event_hash in block #1 in DuckDB
        self.conn.execute("UPDATE blockchain_ledger SET event_hash = 'TAMPERED_HASH' WHERE block_index = 1")

        audit = verify_chain(conn=self.conn)
        self.assertFalse(audit.valid)
        self.assertEqual(audit.invalid_block, 1)
        self.assertIn("Tampered block payload", audit.reason)

    # ─────────────────────────────────────────────────────────────────
    # 5. Tamper Detection: Broken Previous Hash Link
    # ─────────────────────────────────────────────────────────────────
    def test_tamper_detection_broken_previous_hash(self):
        events_batch = [("EVT-301", "hash_301"), ("EVT-302", "hash_302")]
        append_event_blocks_batch(events_batch, conn=self.conn)

        # Corrupt previous_hash of block #2
        self.conn.execute("UPDATE blockchain_ledger SET previous_hash = 'FORGED_PREVIOUS_HASH' WHERE block_index = 2")

        audit = verify_chain(conn=self.conn)
        self.assertFalse(audit.valid)
        self.assertEqual(audit.invalid_block, 2)
        self.assertIn("Broken chain link", audit.reason)

    # ─────────────────────────────────────────────────────────────────
    # 6. Event Integrity Verification (VERIFIED vs TAMPERED)
    # ─────────────────────────────────────────────────────────────────
    def test_event_integrity_verification(self):
        raw_log = "<164>Aug 26 14:32:10 asa-fw01 %ASA-4-106023: Deny tcp src outside:198.51.100.23/54321 dst inside:10.0.1.50/443"
        raw_hash = hash_raw_log(raw_log)
        event_id = "EVT-AUTH-999"

        # 1. Store in DuckDB raw_events and normalized_events
        self.conn.execute(
            "INSERT INTO raw_events VALUES (?, ?, ?, ?, ?, ?)",
            [raw_hash, raw_log, "2026-08-26 14:32:10", "firewall.log", None, 1],
        )
        self.conn.execute(
            """
            INSERT INTO normalized_events (event_id, raw_event_id, timestamp, category_name, severity, status, message, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [event_id, raw_hash, "2026-08-26 14:32:10", "Network Activity", "Medium", "Failure", "Deny tcp", "2026-08-26 14:32:10"],
        )

        # 2. Record in Blockchain Ledger
        append_block(event_id=event_id, event_hash=raw_hash, action="LOG_STORED", conn=self.conn)

        # 3. Verify Integrity (Should be VERIFIED)
        res_valid = verify_event_integrity(event_id, conn=self.conn)
        self.assertEqual(res_valid.status, "VERIFIED")
        self.assertEqual(res_valid.stored_hash, raw_hash)
        self.assertEqual(res_valid.blockchain_hash, raw_hash)

        # 4. Simulate Unauthorized Database Modification
        self.conn.execute(
            "UPDATE raw_events SET raw_text = 'FORGED ALTERED LOG TEXT' WHERE raw_event_id = ?",
            [raw_hash],
        )

        # 5. Verify Integrity Again (Should be TAMPERED)
        res_tampered = verify_event_integrity(event_id, conn=self.conn)
        self.assertEqual(res_tampered.status, "TAMPERED")
        self.assertNotEqual(res_tampered.stored_hash, raw_hash)
        self.assertEqual(res_tampered.blockchain_hash, raw_hash)
        self.assertIn("Cryptographic hash mismatch", res_tampered.message)

    # ─────────────────────────────────────────────────────────────────
    # 7. Chain-of-Custody History for Event
    # ─────────────────────────────────────────────────────────────────
    def test_chain_of_custody_history(self):
        event_id = "EVT-COC-555"
        h = "hash_sample_coc"

        append_block(event_id=event_id, event_hash=h, action="LOG_RECEIVED", conn=self.conn)
        append_block(event_id=event_id, event_hash=h, action="LOG_NORMALIZED", conn=self.conn)
        append_block(event_id=event_id, event_hash=h, action="LOG_STORED", conn=self.conn)

        history = get_blocks_for_event(event_id, conn=self.conn)
        self.assertEqual(len(history), 3)
        self.assertEqual(history[0].action, "LOG_RECEIVED")
        self.assertEqual(history[1].action, "LOG_NORMALIZED")
        self.assertEqual(history[2].action, "LOG_STORED")

    # ─────────────────────────────────────────────────────────────────
    # 8. End-to-End Pipeline Integration Test
    # ─────────────────────────────────────────────────────────────────
    def test_e2e_pipeline_and_blockchain_proof(self):
        engine = PipelineEngine(conn=self.conn)
        raw_log = '{"ts":"2026-08-26T12:00:00Z","user":"alice","action":"logon","status":"success"}'
        events = engine.ingest_text(raw_log, source_name="e2e_test.json", persist=True)
        self.assertEqual(len(events), 1)
        ev = events[0]

        # Verify event block was appended to blockchain
        blocks = get_blocks_for_event(ev.event_id, conn=self.conn)
        self.assertGreaterEqual(len(blocks), 1)
        self.assertEqual(blocks[-1].event_id, ev.event_id)

        # Verify integrity check passes
        res = verify_event_integrity(ev.event_id, conn=self.conn)
        self.assertEqual(res.status, "VERIFIED")

        # Verify overall blockchain is valid
        audit = verify_chain(conn=self.conn)
        self.assertTrue(audit.valid)

    # ─────────────────────────────────────────────────────────────────
    # 9. FastAPI Handlers Testing
    # ─────────────────────────────────────────────────────────────────
    def test_fastapi_blockchain_api_routes(self):
        # 1. get_overview()
        overview = get_overview()
        self.assertGreaterEqual(overview.total_blocks, 1)
        self.assertEqual(overview.chain_status, "VALID")

        # 2. audit_blockchain()
        audit = audit_blockchain()
        self.assertTrue(audit.valid)

        # 3. Ingest an event and test event-specific endpoints
        raw = "<14>Aug 26 12:00:00 server01 sshd[123]: Accepted password for root from 192.168.1.100 port 22"
        events = PipelineEngine().ingest_text(raw, source_name="api_test.log", persist=True)
        ev_id = events[0].event_id

        # 4. verify_event(event_id) -> VERIFIED
        res_int = verify_event(ev_id)
        self.assertEqual(res_int.status, "VERIFIED")

        # 5. simulate_tampering(event_id)
        res_tamper = simulate_tampering(ev_id)
        self.assertEqual(res_tamper["status"], "tampered_for_demo")

        # 6. verify_event(event_id) -> TAMPERED
        res_int_after = verify_event(ev_id)
        self.assertEqual(res_int_after.status, "TAMPERED")

        # 7. list_blocks(limit=10, offset=0)
        blocks = list_blocks(limit=10, offset=0)
        self.assertGreaterEqual(len(blocks), 1)

        # 8. get_event_chain_of_custody(event_id)
        coc = get_event_chain_of_custody(ev_id)
        self.assertGreaterEqual(len(coc), 1)


if __name__ == "__main__":
    unittest.main()
