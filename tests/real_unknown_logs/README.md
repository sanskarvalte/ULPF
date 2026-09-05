# ULPF Test Log Corpus — 20 Distinct Formats

Each file uses a genuinely different structure, vendor style, or encoding —
not variations of the same format — to stress-test format-detection,
fingerprinting, and normalization coverage.

| # | File | Format Type | Category | What It Tests |
|---|------|-------------|----------|----------------|
| 01 | linux_syslog.log | RFC3164 Syslog | OS | Classic space-delimited syslog, mixed message types |
| 02 | windows_eventlog.xml | XML | OS | XML namespaces, attributes, nested EventData |
| 03 | aws_cloudtrail.json | JSON (nested array) | Cloud | Nested JSON objects, array of records |
| 04 | apache_access.log | Apache Combined Log | Web Server | Quoted fields, bracketed timestamp, status codes |
| 05 | cef_firewall.log | CEF | Security Appliance | CEF pipe-delimited header + key=value extension |
| 06 | leef_ibm.log | LEEF | Security Appliance | Tab-delimited LEEF extension fields |
| 07 | csv_export.csv | CSV | Generic | Simple comma-delimited with header row |
| 08 | cisco_asa.log | Cisco ASA Syslog | Firewall | Vendor-specific %ASA-N-NNNNNN message codes |
| 09 | fortinet_fortigate.log | Key=Value | Firewall | Fortinet's dense key=value single-line format |
| 10 | paloalto_traffic.csv | CSV (vendor-specific columns) | Firewall | Palo Alto's own CSV column ordering |
| 11 | snort_ids.log | Multi-line free text | IDS/IPS | Multi-line alert block — tests continuation-line merging |
| 12 | openvpn.log | Free text w/ embedded fields | VPN | "us=" microsecond field, TLS handshake messages |
| 13 | linux_authlog.log | Syslog (auth-specific) | OS/Auth | SSH brute-force pattern, PAM session messages |
| 14 | mysql_slowquery.log | Comment-prefixed block | Database | "#"-prefixed metadata lines + raw SQL statement |
| 15 | kubernetes_pod.jsonl | JSON Lines (structured) | Container | One JSON object per line, cloud-native style |
| 16 | dns_bind.log | BIND query log | Network Service | Free text with embedded IP:port, security denial line |
| 17 | iot_sensor.jsonl | JSON Lines (IoT) | IoT | Unix epoch timestamps, sensor telemetry, badge access event |
| 18 | haproxy_lb.log | Syslog + structured suffix | Load Balancer | Timing tuple (Tq/Tw/Tc/Tr/Tt), HTTP request tail |
| 19 | sonicwall_firewall.log | key=value with id= prefix | Firewall | SonicWall's own id=/sn=/pri= schema |
| 20 | zookeeper.log | Log4j-style free text | Application | [myid:N] bracketed thread context, ERROR/WARN/INFO levels |

## Suggested Test Priorities

- **Known-format path (should use direct parsers):** 01, 03, 04, 07, 15
- **Semi-structured/vendor key-value (should fingerprint reliably):** 05, 06, 09, 19
- **Genuinely irregular/unknown-format path (Drain3 + fallback):** 11, 12, 14, 20
- **Multi-line continuation test:** 11 (Snort alert block spans 4 lines)
- **Severity-keyword test:** 02 (failure), 08 (deny/disallow), 09 (alert), 11 (priority), 13 (failed), 18 (503/SC), 19 (port scan), 20 (ERROR/WARN)
- **Self-declared vendor/product test:** 08 (Cisco ASA), 09 (FortiGate), 19 (SonicWall)
- **Timestamp format variety:** epoch (17), microsecond offset (12), bracketed (04), ISO (03, 15), BIND-style (16)

## Note on Realism

These are synthetic but structurally accurate representations of each
format's real-world shape (field ordering, delimiters, vendor conventions).
IP addresses use RFC 5737/3849 documentation ranges (192.0.2.0/24,
198.51.100.0/24, 203.0.113.0/24) — none are real hosts.
