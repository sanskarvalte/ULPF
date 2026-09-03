# ULPF — Universal Log Pre-processing Framework
**National Technical Research Organisation (NTRO) Evaluation**

ULPF ingests, detects, parses, normalizes, and enriches heterogeneous security logs (Syslog RFC 3164/5424, JSON, XML/Sysmon, CSV, CEF, LEEF, Android, and generic text) into the **Open Cybersecurity Schema Framework (OCSF)** standard. All records and untouched raw payloads are stored in local **DuckDB** for forensic traceability, high-throughput SQL analytics, one-click **Parquet export**, and offline **Isolation Forest ML Anomaly Detection**.

> **100% Offline & Air-Gapped**: Runs entirely on localhost with zero external cloud or database dependencies.

---

## 🏛️ 8-Node Target Pipeline Architecture

```
                     ┌────────────────────────┐
                     │   1. Log Collector     │
                     └───────────┬────────────┘
                                 │
                                 ▼
                     ┌────────────────────────┐
                     │     2. Raw Storage     │ (Persists untouched raw_event + SHA-256 ID)
                     └───────────┬────────────┘
                                 │
                                 ▼
                     ┌────────────────────────┐
                     │   3. Format Matcher    │ (Runtime-mutable deterministic signatures)
                     └─────┬────────────┬─────┘
             Known = YES   │            │  Known = NO
                           │            │
                           ▼            ▼
        ┌─────────────────────┐   ┌───────────────────────────┐
        │4. Rule-Based Parsers│   │ 5. Ollama AI Assistant    │ (Non-blocking, Fingerprint Hash,
        │ (Syslog, JSON, XML, │   │    (llama3.2 temp=0 JSON) │  Emits 'unknown_pending_review')
        │  CSV, CEF, LEEF)    │   └─────────────┬─────────────┘
        └──────────┬──────────┘                 │
                   │                            ▼
                   │              ┌───────────────────────────┐
                   │              │      6. Human Review      │ (Approve / Reject per fingerprint)
                   │              └─────────────┬─────────────┘
                   │                            │ (On Approval)
                   │                            ▼
                   │              ┌───────────────────────────┐
                   │              │  7. Save as New Parser    │ (Persisted in DuckDB custom_parsers,
                   │              │     (Dynamic Matcher)     │  Registered in Node 3 & 4 on startup)
                   │              └─────────────┬─────────────┘
                   │                            │
                   └──────────────┬─────────────┘ (Both branches converge)
                                  │
                                  ▼
                     ┌────────────────────────┐
                     │     8. Normalizer      │ (Unified OCSF Schema + Losslessness Substring Guard)
                     └────────────┬───────────┘
                                  │
                                  ▼
                     ┌────────────────────────┐
                     │   Output Fanout Sinks  │ (DuckDB SQL, Parquet, JSON, Isolation Forest ML)
                     └────────────────────────┘
```

### Node Descriptions

1. **Log Collector**: Single generic entry point accepting raw log lines, multi-line streams, and files with source metadata.
2. **Raw Storage**: Unconditionally persists untouched `raw_event` text and computes a SHA-256 ID into DuckDB `raw_events` before any parsing attempt.
3. **Format Matcher**: Executes cheap, deterministic regex/prefix signatures against a runtime-mutable registry. **Zero LLM calls** in this stage.
4. **Rule-Based Parsers (Yes Branch)**: Ultra-fast deterministic parsers (<1ms) for Syslog, JSON, XML, CSV, CEF, LEEF, and Android that never touch Ollama.
5. **Ollama AI Assistant (No Branch)**: Structural template fingerprinting with local `llama3.2` (`temperature: 0`). Non-blocking emission as `unknown_pending_review` while enqueuing suggestions to Node 6.
6. **Human Review**: REST API and UI to inspect pending format suggestions by structural fingerprint and review Ollama's suggested mapping and confidence.
7. **Save as New Parser**: On approval, persists to DuckDB `custom_parsers`, dynamically compiles and registers the new parser into active memory, and reloads automatically across restarts so future logs skip AI.
8. **Unified Normalizer**: Single convergence point for both branches. Normalizes OCSF taxonomy, maps severity/status, and enforces a **Losslessness Substring Guard** that rejects any fabricated values not present in `raw_event`.

---

## 🚀 Quick Start (Local Offline Execution)

### 1. Activate Environment
```bash
source .venv/bin/activate
# Or install offline from bundled wheels if on a new machine:
# pip install --no-index --find-links=offline_packages -r requirements.txt
```

### 2. Launch Web UI & REST API Server
```bash
PYTHONPATH=backend uvicorn app.main:app --app-dir backend --host 127.0.0.1 --port 8000 --reload
```

- **Interactive Dashboard & Log Explorer**: [http://127.0.0.1:8000](http://127.0.0.1:8000)
- **Interactive OpenAPI Docs (Swagger)**: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)
- **Human Review API**: [http://127.0.0.1:8000/docs#/Human%20Review%20%26%20Dynamic%20Parsers](http://127.0.0.1:8000/docs#/Human%20Review%20%26%20Dynamic%20Parsers)

---

## 👥 Operating the Human Review Queue (Node 6 & 7)

### List Pending AI Format Suggestions
```bash
curl -s http://127.0.0.1:8000/reviews/pending | jq
```

### Approve a Format Suggestion & Save as Dynamic Parser
```bash
curl -X POST http://127.0.0.1:8000/reviews/<FINGERPRINT>/approve \
  -H "Content-Type: application/json" \
  -d '{
    "format_name": "custom_app_auth",
    "approved_by": "security_lead"
  }'
```
*Once approved, all future logs matching this format shape are routed to the **Yes branch** and skip Ollama entirely.*

### List All Approved Custom Parsers
```bash
curl -s http://127.0.0.1:8000/reviews/parsers | jq
```

---

## ⛓️ BLOCKCHAIN-BASED LOG INTEGRITY

ULPF stores the actual raw and normalized security logs in local DuckDB. A local blockchain-based integrity ledger stores cryptographic hashes and audit metadata for those events. Each block is linked to the previous block using cryptographic hashes. During verification, ULPF recalculates the stored event's SHA-256 hash and compares it with the blockchain proof, allowing modification of security evidence to be detected.

### Target Integrity Architecture

```
                 SECURITY LOG
                      │
                      ▼
                 ULPF ENGINE
                      │
        ┌─────────────┴─────────────┐
        ▼                           ▼
     Parsing                   Detection
        │
        ▼
   Normalization
        │
        ▼
       OCSF
        │
        ▼
     Validation
        │
        ▼
     SHA-256 (hash_raw_log)
        │
     ┌──┴───────────────┐
     ▼                  ▼
  DuckDB           Blockchain
(actual data)      (proof/ledger)
     │                  │
     └────────┬─────────┘
              ▼
       Integrity Verification
              │
        ┌─────┴─────┐
        ▼           ▼
     VERIFIED     TAMPERED
```

### Key Principles of the Blockchain Layer

1. **Separation of Concerns**:
   - **DuckDB**: Stores actual raw logs (`raw_events`), normalized events (`normalized_events`), and OCSF attributes.
   - **Blockchain Ledger**: Stores **only** cryptographic hashes, event IDs, timestamps, actions (`LOG_STORED`, `LOG_RECEIVED`), previous block hashes, and current block hashes in the `blockchain_ledger` table.
   - **SHA-256**: The digital fingerprint used to compare evidence.
2. **Deterministic SHA-256 Block Chaining**:
   - Each block is linked via `previous_hash` to the preceding block's `block_hash`.
   - Block hash calculation: `SHA-256(block_index | timestamp | event_id | action | event_hash | previous_hash)`.
   - Invariant, deterministic Genesis block (#0) anchors the ledger.
3. **Chain of Custody**:
   - Records lifecycle actions (`LOG_RECEIVED`, `LOG_NORMALIZED`, `LOG_STORED`) providing a tamper-evident timeline for forensics.
4. **100% Offline & Air-Gapped**:
   - Zero cryptocurrency, zero proof-of-work mining, zero external cloud nodes. Operates entirely locally with DuckDB and Python standard libraries.

### Blockchain Verification & Demonstration

#### 1. Audit Full Blockchain Ledger Continuity
```bash
curl -s http://127.0.0.1:8000/api/blockchain/verify | jq
```
*Validates Genesis anchor, recalculates every block hash, and checks continuity across the entire chain.*

#### 2. Verify an Individual Event Cryptographic Integrity
```bash
curl -s http://127.0.0.1:8000/api/blockchain/integrity/<EVENT_ID> | jq
```
*Recalculates the stored log's SHA-256 hash in DuckDB and compares it to the immutable blockchain proof.*

#### 3. Demonstrate Tamper Detection (Cybersecurity Evaluation)
```bash
# Step A: Simulate unauthorized DuckDB modification
curl -X POST http://127.0.0.1:8000/api/blockchain/simulate-tamper/<EVENT_ID> | jq

# Step B: Re-verify integrity (Instantly flags TAMPERED)
curl -s http://127.0.0.1:8000/api/blockchain/integrity/<EVENT_ID> | jq
```

---

## 🧪 Running Unit & Integration Tests

```bash
# Run complete test suite (79 tests across all 8 nodes and blockchain layer)
PYTHONPATH=backend .venv/bin/python3 -m unittest discover -s backend/tests

# Run dedicated Blockchain integrity test suite (9 tests)
PYTHONPATH=backend .venv/bin/python3 -m unittest backend/tests/test_blockchain.py

# Run dedicated Cisco ASA firewall test suite (12 tests)
PYTHONPATH=backend .venv/bin/python3 -m unittest backend/tests/test_cisco_asa.py
```
