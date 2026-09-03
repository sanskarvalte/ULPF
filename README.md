# ULPF — Universal Log Pre-processing Framework
**National Technical Research Organisation (NTRO) Evaluation**

ULPF ingests, detects, parses, normalizes, and enriches heterogeneous security logs (Syslog RFC 3164/5424, JSON, XML/Sysmon, CSV, CEF, LEEF, and generic text) into the **Open Cybersecurity Schema Framework (OCSF)** standard. All records and untouched raw payloads are stored in local **DuckDB** for forensic traceability, high-throughput SQL analytics, one-click **Parquet export**, and offline **Isolation Forest ML Anomaly Detection**.

> **100% Offline & Air-Gapped**: Runs entirely on localhost with zero external cloud or database dependencies.

---

## 🏗️ Architecture Layout

```
ULPF/
├── backend/
│   ├── app/
│   │   ├── main.py             # FastAPI App & CLI Runner
│   │   ├── api/                # Modular API routers (ingest, sources, mappings, events, analytics)
│   │   ├── ingestion/          # Heuristic format detector & dynamic parser registry
│   │   ├── parsers/            # Base, JSON, Syslog, CEF, LEEF, CSV, XML, Generic & Drain mining
│   │   ├── normalization/      # Taxonomy tables, field dictionaries & normalization engine
│   │   ├── mapping/            # OCSF JSON schema adapter & pre-configured vendor rules
│   │   ├── ai/                 # Local Isolation Forest anomaly detection & AI schema suggester
│   │   ├── validation/         # Schema compliance, IP/Port format & SHA-256 integrity checks
│   │   ├── storage/            # DuckDB raw deduplication, normalized queries & Parquet export
│   │   └── models/             # UnifiedEvent Pydantic schema model
│   └── tests/                  # Unit and integration test suite
├── frontend/
│   ├── index.html              # Multi-view offline Web Dashboard (ES modules)
│   └── src/
│       ├── pages/              # Dashboard, LogExplorer, SourceOnboarding, MappingReview, EventDetails
│       └── components/         # Navbar, metrics grid, traceability modals
├── integrations/               # Fluent-Bit, Drain3, OSSEM, and OCSF configuration definitions
├── mappings/                   # Pre-configured YAML rules (Windows, Sysmon, Linux, Zeek)
├── datasets/                   # Sample log datasets & LogHub benchmark guidelines
├── docker/                     # Dockerfile & container entrypoint script
├── docs/                       # Architecture document, air-gapped runbook, and evaluation presentation
├── docker-compose.yml
├── requirements.txt
└── offline_packages/           # Bundled offline wheels for air-gapped installation
```

---

## 🚀 Quick Start (Local Offline Execution)

### 1. Activate Environment
```bash
source .venv/bin/activate
# Or install offline from bundled wheels if on a new machine:
# pip install --no-index --find-links=offline_packages -r requirements.txt
```

### 2. Ingest Logs via CLI
```bash
# Ingest single file or directory using the ulpf CLI:
ulpf process sample.log
ulpf process datasets/sample/install.log
ulpf process datasets/loghub/Mac_2k.log

# View database statistics:
ulpf stats

# List recent normalized events:
ulpf list

# Export normalized logs to ZSTD Parquet or JSON:
ulpf export exports/normalized_events.parquet
ulpf export exports/normalized_events.json
```

### 3. Launch Web UI & REST API Server
```bash
PYTHONPATH=backend uvicorn app.main:app --app-dir backend --host 127.0.0.1 --port 8000
```

- **Interactive Dashboard & Log Explorer**: [http://127.0.0.1:8000](http://127.0.0.1:8000)
- **Interactive OpenAPI Docs (Swagger)**: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)
- **Isolation Forest ML Anomalies**: [http://127.0.0.1:8000/anomalies](http://127.0.0.1:8000/anomalies)

---

## 🧪 Running Unit Tests

```bash
cd backend
../.venv/bin/python -m unittest discover -s tests
```

---

## 📑 NTRO Evaluation Deliverables

- **Architecture Document (Max 2 Pages)**: [`docs/architecture.md`](docs/architecture.md)
- **Air-Gapped Deployment Runbook**: [`docs/airgapped.md`](docs/airgapped.md)
- **Technical Presentation (5 Slides) & Demo Script (2 Mins)**: [`docs/evaluation.md`](docs/evaluation.md)
- **Container Configuration**: [`docker-compose.yml`](docker-compose.yml) and [`docker/Dockerfile`](docker/Dockerfile)
