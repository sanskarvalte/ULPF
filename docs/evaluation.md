# NTRO Evaluation Deliverables Guide

---

## 1. Technical Presentation (Max 5 Slides)

### Slide 1: Title & Executive Summary
- **Title**: Universal Log Pre-processing Framework (ULPF)
- **Subtitle**: Vendor-Agnostic, Lossless Pre-processing & Normalization for Next-Gen SIEM & Defense Analytics
- **Organization**: National Technical Research Organisation (NTRO) Evaluation
- **Key Points**:
  - Solves log fragmentation across heterogeneous hardware/software perimeters.
  - Aligns with OCSF (Open Cybersecurity Schema Framework) standard.
  - 100% offline & air-gapped ready with embedded DuckDB and local ML.

### Slide 2: End-to-End Modular Architecture
- **Diagram**: Ingestion Layer → Normalization Engine → DuckDB Storage → AI/ML Analytics → Visual UI.
- **Highlights**:
  - Multi-format ingestion: Syslog (RFC 3164/5424), JSON, XML/Sysmon, CSV, CEF, LEEF.
  - Heuristic auto-detector eliminates manual parser selection overhead.
  - Plug-and-play YAML mapping rules (`mappings/windows`, `mappings/sysmon`, `mappings/zeek`).

### Slide 3: Lossless Normalization & Forensic Traceability
- **Lossless Guarantee**: Every raw payload is hashed via SHA-256 and stored in `raw_events`.
- **Bidirectional Traceability**: Unique `event_id` directly joins with original unparsed text via `raw_event_id`.
- **OCSF Taxonomy**: Standardized numeric UIDs for Categories, Classes, Activities, and Severities.

### Slide 4: Storage, Big Data & AI/ML Anomaly Detection
- **Storage Performance**: In-process DuckDB columnar execution (sub-millisecond SQL queries).
- **SIEM / Data Lake Hand-off**: Native ZSTD-compressed Apache Parquet, JSON, and CSV export.
- **Machine Learning Engine**: Local Isolation Forest model scoring time-window deviations and error surges in real-time.

### Slide 5: Key Deliverables, Benchmarks & Operational Impact
- **Zero Internet/Cloud Dependency**: Pre-bundled wheels, zero-CDN local dashboard.
- **Container Portability**: Dockerfile & single-command `docker-compose.yml`.
- **Results**: >90% reduction in custom parser authoring effort; unified visibility across multi-vendor perimeters.

---

## 2. Demo Video Script (Max 2 Minutes)

| Timestamp | Screen Action | Narration Script |
|---|---|---|
| **0:00 - 0:25** | Open Terminal & launch `uvicorn app.main:app` and navigate to `http://127.0.0.1:8000`. | *"Welcome to the Universal Log Pre-processing Framework. ULPF is an air-gapped, vendor-agnostic pipeline designed for high-throughput perimeter log normalization."* |
| **0:25 - 0:50** | Click on **"Source Onboarding"** tab, paste a multi-format log string (or upload `server.json` / `security.cef`) and click **"Ingest & Normalize"**. | *"ULPF's heuristic detector instantly identifies the log format—whether Syslog, JSON, CEF, or XML—and maps heterogeneous attributes to standard OCSF fields with zero manual tuning."* |
| **0:50 - 1:20** | Navigate to **"Log Explorer"** and click **"Trace"** on an event to open the modal. | *"Here we demonstrate complete forensic traceability. On the left is the structured OCSF record, and on the right is the untouched raw payload verified by SHA-256 hash."* |
| **1:20 - 1:45** | Switch to **"Dashboard"** and highlight the **AI/ML Anomaly Detection** card. | *"Our local Isolation Forest ML engine runs directly on DuckDB SQL aggregations, flagging abnormal surges in failed authentication and perimeter errors without any external API calls."* |
| **1:45 - 2:00** | Click **"Parquet"** export button to download the file. | *"With one click, normalized logs are exported as compressed Parquet files ready for direct ingest into SIEMs and Big Data lakes. ULPF is fully packaged in Docker and 100% offline ready."* |
