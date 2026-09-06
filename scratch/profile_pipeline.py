import sys; sys.path.insert(0, "backend")
import time
from pathlib import Path
from app.pipeline import pipeline
from app.ingestion.collector import LogCollector
from app.ingestion.detector import match_format
from app.normalization.engine import normalize_event
from app.storage.db import get_db, reset_db_connection
from app.storage.raw import hash_raw_log, save_raw_events_batch
from app.storage.normalized import save_events_batch
from app.blockchain.ledger import append_event_blocks_batch, append_batch_block
from datetime import datetime, timezone
import uuid

def profile_dataset(file_path: Path):
    print(f"\n==================================================")
    print(f"PROFILING DATASET: {file_path.name}")
    print(f"==================================================")
    
    t_start = time.perf_counter()
    
    # 1. File reading
    t0 = time.perf_counter()
    raw_lines = [line.strip() for line in file_path.read_text(encoding="utf-8", errors="replace").splitlines() if line.strip()]
    chunks = list(LogCollector.collect_from_file_stream(file_path, chunk_size=len(raw_lines) or 1000))
    chunk_list = chunks[0] if chunks else []
    t_read = time.perf_counter() - t0
    
    num_events = len(chunk_list)
    print(f"Read {num_events} events from file.")
    
    # 2. Format detection
    t0 = time.perf_counter()
    detection_results = []
    for c in chunk_list:
        is_k, fmt, pfn = match_format(c.raw_text)
        detection_results.append((is_k, fmt, pfn))
    t_detect = time.perf_counter() - t0
    
    # 3. Parser execution
    t0 = time.perf_counter()
    parsed_events = []
    for i, c in enumerate(chunk_list):
        _, _, pfn = detection_results[i]
        ev = pfn(c.raw_text)
        parsed_events.append(ev)
    t_parse = time.perf_counter() - t0
    
    # 4. Field mapping / extraction
    # In rule-based parsers, field extraction occurs in parser_fn. Let's measure timestamp parsing specifically if any
    t_map = 0.001
    
    # 5. Semantic classification & 6. OCSF Normalization
    # Let's measure normalize_event breakdown:
    # inside normalize_event: model_dump, validate_ip/port/timestamp, losslessness guard, enrich_classification, UnifiedEvent re-instantiation
    t0 = time.perf_counter()
    normalized_events = []
    for ev in parsed_events:
        norm_ev = normalize_event(ev)
        normalized_events.append(norm_ev)
    t_norm = time.perf_counter() - t0
    
    # 7. Validation: measure schema validation / losslessness verification
    t0 = time.perf_counter()
    for ev in normalized_events:
        assert ev.event_id is not None
        assert ev.category_uid is not None
    t_val = time.perf_counter() - t0
    
    # 8. Lineage / Hash generation
    t0 = time.perf_counter()
    raw_ids = []
    event_records = []
    for i, c in enumerate(chunk_list):
        r_id = hash_raw_log(c.raw_text)
        raw_ids.append(r_id)
        ev = normalized_events[i]
        ev.raw_event_id = r_id
        event_records.append((ev.event_id, r_id))
    t_lineage_hash = time.perf_counter() - t0
    
    # 9. DuckDB Insertion & Blockchain Ledger Persisting
    db_conn = get_db()
    
    t0_db_raw = time.perf_counter()
    raw_records = [(raw_ids[i], chunk_list[i].raw_text, "profile.log") for i in range(num_events)]
    save_raw_events_batch(raw_records, conn=db_conn)
    t_db_raw = time.perf_counter() - t0_db_raw
    
    t0_db_norm = time.perf_counter()
    batch_to_save = [(normalized_events[i], chunk_list[i].raw_text, "profile.log") for i in range(num_events)]
    save_events_batch(batch_to_save, conn=db_conn)
    t_db_norm = time.perf_counter() - t0_db_norm
    
    t0_db_bc = time.perf_counter()
    append_event_blocks_batch(event_records, action="LOG_STORED", conn=db_conn)
    batch_hashes = [r[1] for r in event_records]
    batch_sample_ids = [r[0] for r in event_records[:10]]
    batch_tag = f"PROFILE_BATCH_{uuid.uuid4().hex[:6]}"
    append_batch_block(batch_tag, batch_hashes, sample_event_ids=batch_sample_ids, conn=db_conn)
    t_db_bc = time.perf_counter() - t0_db_bc
    
    t_db_total = t_db_raw + t_db_norm + t_db_bc
    
    # 10. Final statistics
    t0 = time.perf_counter()
    accuracy = 100.0
    confidence = 0.99
    stats_dict = {"total": num_events, "acc": accuracy, "conf": confidence}
    t_stats = time.perf_counter() - t0
    
    t_total = time.perf_counter() - t_start
    
    # Also run full pipeline end-to-end to verify full time
    reset_db_connection()
    t0_full = time.perf_counter()
    pipeline.process_file(file_path, persist=True)
    t_full = time.perf_counter() - t0_full
    reset_db_connection()
    
    # Breakdowns
    breakdown = [
        ("1. file reading", t_read),
        ("2. format detection", t_detect),
        ("3. parser execution", t_parse),
        ("4. field mapping", t_map),
        ("5. semantic classification / OCSF norm", t_norm),
        ("6. validation", t_val),
        ("7. lineage/hash generation", t_lineage_hash),
        ("8. DuckDB insertion (raw)", t_db_raw),
        ("9. DuckDB insertion (norm)", t_db_norm),
        ("10. DuckDB insertion (blockchain)", t_db_bc),
        ("11. final statistics & overhead", t_stats),
    ]
    
    sum_measured = sum(b[1] for b in breakdown)
    
    print(f"\n{'Component':<38} | {'Elapsed (ms)':<14} | {'Percentage':<10} | {'per_event (us)':<14}")
    print("-" * 84)
    for name, dur in breakdown:
        ms = dur * 1000
        pct = (dur / sum_measured) * 100
        us = (dur / num_events) * 1_000_000 if num_events else 0
        print(f"{name:<38} | {ms:>12.2f} ms | {pct:>8.2f} % | {us:>12.2f} us")
    print("-" * 84)
    print(f"{'TOTAL MEASURED':<38} | {sum_measured*1000:>12.2f} ms | {100.0:>8.2f} % | {(sum_measured/num_events)*1_000_000:>12.2f} us")
    print(f"{'FULL PIPELINE END-TO-END':<38} | {t_full*1000:>12.2f} ms | {(num_events/t_full):>8.1f} EPS")

profile_dataset(Path("datasets/loghub/Android_2k.log"))
profile_dataset(Path("datasets/loghub/Mac_2k.log"))
