# LogHub Benchmark Datasets for ULPF Evaluation

LogHub provides a collection of system log datasets for AI/ML log parsing and anomaly detection research.

### Compatible Datasets for ULPF Testing:
- **HDFS**: Hadoop Distributed File System log dataset (2,000 to 11M log lines).
- **BGL**: Blue Gene/L Supercomputer log dataset.
- **Linux / Syslog**: Ubuntu auth and system logs.
- **Windows**: Windows Event Log system & security logs.
- **Zookeeper**: Distributed coordination logs.

### Testing LogHub datasets with ULPF:
```bash
# Place your downloaded loghub file (e.g. Linux_2k.log) into this directory and run:
PYTHONPATH=backend python backend/app/main.py datasets/loghub/Linux_2k.log
```
