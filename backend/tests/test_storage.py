"""
Unit tests for DuckDB Storage & Lossless Traceability in ULPF.
"""

import tempfile
import unittest
from pathlib import Path

from app.models.event_schema import UnifiedEvent
from app.storage.db import get_db
from app.storage.normalized import (
    export_to_parquet,
    get_all_events,
    get_event_by_id,
    get_stats,
    save_normalized_event,
)
from app.storage.raw import get_raw_event, hash_raw_log


class TestStorage(unittest.TestCase):

    def test_storage_and_traceability(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.duckdb"
            conn = get_db(db_path)

            raw = "2026-08-26 12:00:00 [ERROR] Firewall drop packet from 10.0.0.99"
            event = UnifiedEvent(
                src_ip="10.0.0.99",
                severity="High",
                severity_id=4,
                message="Firewall drop packet",
                raw_event=raw,
            )

            eid, rid = save_normalized_event(event, raw_text=raw, source_file="test.log", conn=conn)
            self.assertEqual(rid, hash_raw_log(raw))

            # Retrieve with forensic join
            joined = get_event_by_id(eid, conn=conn)
            self.assertIsNotNone(joined)
            self.assertEqual(joined["src_ip"], "10.0.0.99")
            self.assertEqual(joined["raw_text"], raw)
            self.assertEqual(joined["raw_event_id"], rid)

            # Stats check
            stats = get_stats(conn=conn)
            self.assertEqual(stats["total_normalized_events"], 1)
            self.assertEqual(stats["total_raw_events"], 1)

            # Parquet export check
            parquet_file = Path(tmpdir) / "out.parquet"
            export_to_parquet(parquet_file, conn=conn)
            self.assertTrue(parquet_file.exists())
            self.assertGreater(parquet_file.stat().st_size, 0)


if __name__ == "__main__":
    unittest.main()
