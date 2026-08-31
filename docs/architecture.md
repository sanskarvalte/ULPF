# Universal Log Pre-processing Framework (ULPF)
## System Architecture Document (NTRO Evaluation)

### 1. Executive Summary & Problem Scope
Modern enterprise and defense perimeters generate massive volumes of heterogeneous logs from firewalls, operating systems, identity managers, and network appliances (Syslog, JSON, XML, CSV, CEF, LEEF, and unstructured text). The **Universal Log Pre-processing Framework (ULPF)** provides a high-throughput, vendor-agnostic, and 100% offline-deployable pipeline that ingests, parses, normalizes, and enriches logs into the **Open Cybersecurity Schema Framework (OCSF)** standard while strictly preserving raw event data for forensic compliance.

```
+-----------------------------------------------------------------------------------+
|                           INGESTION & DETECTION LAYER                             |
|  [Syslog RFC3164/5424] [JSON] [CEF / ArcSight] [LEEF / QRadar] [XML/Sysmon] [CSV] |
|                                       │                                           |
|                  Heuristic Format Detector & Dynamic Registry                     |
+---------------------------------------┬-------------------------------------------+
                                        │
                                        ▼
+-----------------------------------------------------------------------------------+
|                        NORMALIZATION & TAXONOMY ENGINE                            |
|             OCSF Classification (Category, Class, Activity, Severity, Type)        |
|             OSSEM Dictionary Mapping • AI Automated Schema Suggester              |
|             Drain Template Mining (<*> parameterization for unstructured logs)    |
+---------------------------------------┬-------------------------------------------+
                                        │
                                        ▼
+-----------------------------------------------------------------------------------+
|                         STORAGE & TRACEABILITY LAYER                              |
|   raw_events (SHA-256 deduplication) ◄────[Trace Link]────► normalized_events     |
|   Embedded Local DuckDB Engine (SQL OLAP Aggregations & ZSTD Parquet Export)      |
+---------------------------------------┬-------------------------------------------+
                                        │
                     ┌──────────────────┴──────────────────┐
                     ▼                                     ▼
+------------------------------------+   +------------------------------------+
|     AI/ML SECURITY ANALYTICS       |   |     MODULAR PRESENTATION LAYER     |
|  Local Isolation Forest ML Engine  |   |  FastAPI REST API & Interactive UI |
|  Time-window burst & spike score   |   |  Dashboard • Explorer • Onboarding |
+------------------------------------+   +------------------------------------+
```

---

### 2. Core Architectural Pillars

#### A. Lossless Ingestion & Forensic Traceability
- **Raw Log Storage (`raw_events`)**: Every ingested log payload is hashed via **SHA-256** and stored untouched in an append-only DuckDB table.
- **Traceability Link (`raw_event_id`)**: Every normalized record retains a cryptographic pointer back to the raw source, enabling security analysts to audit exact original text alongside structured fields.

#### B. Unified OCSF Taxonomy & Extensible Parsers
- **Standardized Schema**: Maps vendor-specific keys to standard OCSF fields (`category_uid`, `class_uid`, `activity_id`, `severity_id`, `src_endpoint`, `dst_endpoint`, `actor`, `connection_info`).
- **Plug-and-Play Onboarding**: Adding support for a new log source requires only registering its format or dropping a YAML rule in `mappings/`.

#### C. Local Machine Learning & Anomaly Detection
- **Isolation Forest In-Memory Model**: Automatically computes dynamic baseline feature vectors (total event volume, high-severity ratios, authentication failure rates) across time windows and flags statistical intrusion spikes without external cloud APIs.

#### D. Big Data & SIEM Integration
- **DuckDB & Parquet**: Zero-copy SQL queries directly on disk; one-click export to **ZSTD-compressed Apache Parquet** for ingestion into Splunk, Microsoft Sentinel, Elasticsearch, Apache Iceberg, or Snowflake.

#### E. 100% Air-Gapped & Offline Packaging
- **Zero External CDNs / Cloud Dependencies**: Pure self-contained HTML/CSS/JS frontend; all Python dependencies packaged as offline `.whl` files in `offline_packages/`.
