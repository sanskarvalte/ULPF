"""
Unit and Regression Tests for Cisco ASA Firewall Syslog Parser.
Validates all 5 confirmed defects:
1. Line-boundary / unclosed quote handling (prevents data absorption).
2. Timestamp parsing across all 6 observed standard/non-standard variants.
3. IP, Port, Hostname, Protocol, and Activity extraction across all ASA message formats (106100, 305011, 302013, 302014, 106006, 106016, 106023, IPv6, hostnames).
4. Deterministic severity level mapping (derived solely from ASA level digit).
5. Tolerance for session- infix and missing colon.
6. 89-line comprehensive sample log validation (89 lines -> 89 distinct events, 100% timestamps).
"""

import unittest
from datetime import datetime, timezone

from app.ingestion.collector import LogCollector
from app.pipeline import run_pipeline
from app.parsers.syslog_parser import parse_syslog_log, _parse_cisco_asa


class TestCiscoAsaParser(unittest.TestCase):

    def setUp(self):
        self.collector = LogCollector()

    # ─────────────────────────────────────────────────────────────────
    # 1. Line-Boundary & Stray Quote Handling (Defect 1)
    # ─────────────────────────────────────────────────────────────────
    def test_defect1_trailing_quote_line_boundary(self):
        """
        Verify that a stray/unclosed double-quote character at the end of a line
        (...by access-group "PERMIT_IN" [0x0, 0x0]") does NOT absorb subsequent lines.
        """
        raw_stream = (
            'Apr 15 2013 09:36:50: %ASA-4-106023: Deny tcp src outside:198.51.100.23/54321 dst inside:10.0.1.50/443 by access-group "PERMIT_IN" [0x0, 0x0]"\n'
            'Apr 15 2013 09:36:51: %ASA-6-302013: Built outbound TCP connection 12345 for outside:198.51.100.10/443 (198.51.100.10/443) to inside:10.0.1.50/54321 (10.0.1.50/54321)\n'
            'Apr 15 2013 09:36:52: %ASA-6-302014: Teardown TCP connection 12345 for outside:198.51.100.10/443 to inside:10.0.1.50/54321 duration 0:00:30 bytes 1500 TCP FINs\n'
            'Apr 15 2013 09:36:53: %ASA-5-106100: access-list cached permitted tcp inside/10.0.1.5(54321) -> dmz/192.168.1.10(80) hit-cnt 1 first hit [0x0, 0x0]\n'
        )
        res = run_pipeline(raw_stream, filename="cisco_trailing_quote.log", save_to_db=False)
        events = res["events"]
        self.assertEqual(len(events), 4, f"Expected 4 distinct events, got {len(events)}")
        self.assertEqual(events[0].status_code, "%ASA-4-106023")
        self.assertEqual(events[1].status_code, "%ASA-6-302013")
        self.assertEqual(events[2].status_code, "%ASA-6-302014")
        self.assertEqual(events[3].status_code, "%ASA-5-106100")

    # ─────────────────────────────────────────────────────────────────
    # 2. Timestamp Parsing Variants (Defect 2)
    # ─────────────────────────────────────────────────────────────────
    def test_defect2_timestamp_variants(self):
        """
        Verify all 6 observed timestamp variants parse correctly to UTC datetimes.
        """
        variants = [
            # Variant 1: No separator between seconds and colon
            ("Apr 15 2013 09:36:50: %ASA-4-106023: Deny tcp src outside:198.51.100.23/54321 dst inside:10.0.1.50/443",
             datetime(2013, 4, 15, 9, 36, 50, tzinfo=timezone.utc)),
            # Variant 2: Timezone abbreviation before colon
            ("Apr 15 2014 09:34:34 EDT: %ASA-6-302013: Built outbound TCP connection 100 for outside:1.1.1.1/80 to inside:2.2.2.2/1000",
             datetime(2014, 4, 15, 9, 34, 34, tzinfo=timezone.utc)),
            # Variant 3: Arbitrary hostname before colon
            ("Apr 24 2013 16:00:28 INT-FW01 : %ASA-6-305011: Built dynamic TCP translation from inside:10.0.1.5/54321 to outside:198.51.100.5/12345",
             datetime(2013, 4, 24, 16, 0, 28, tzinfo=timezone.utc)),
            # Variant 4: Placeholder token before colon
            ("Dec 11 2018 08:01:24 <IP>: %ASA-4-106023: Deny tcp src outside:1.1.1.1/100 dst inside:2.2.2.2/200",
             datetime(2018, 12, 11, 8, 1, 24, tzinfo=timezone.utc)),
            # Variant 5: Blank/empty hostname with extra space
            ("Aug 15 2012 23:30:09 : %ASA-6-302014: Teardown TCP connection 100 for outside:1.1.1.1/80 to inside:2.2.2.2/1000",
             datetime(2012, 8, 15, 23, 30, 9, tzinfo=timezone.utc)),
            # Variant 6: Leading PRI tag
            ("<13>Apr 26 2022 10:24:37: %ASA-session-5-106100: access-list acl_in permitted tcp inside/10.0.1.1(100) -> outside/8.8.8.8(53) hit-cnt 1",
             datetime(2022, 4, 26, 10, 24, 37, tzinfo=timezone.utc)),
        ]

        for raw_line, expected_dt in variants:
            ev = parse_syslog_log(raw_line)
            self.assertIsNotNone(ev.timestamp, f"Timestamp was None for: {raw_line}")
            self.assertEqual(ev.timestamp, expected_dt, f"Timestamp mismatch for {raw_line}: got {ev.timestamp}, expected {expected_dt}")
            self.assertEqual(ev.vendor, "Cisco")
            self.assertEqual(ev.product, "ASA")

    # ─────────────────────────────────────────────────────────────────
    # 3. Message Types & IP/Port/Hostname Extractions (Defect 3)
    # ─────────────────────────────────────────────────────────────────
    def test_defect3_event_106100_access_list(self):
        """Test event 106100 with IPv4, IPv6, and Hostname endpoints."""
        # 1. Standard IPv4 access-list permitted
        raw1 = "Apr 15 2013 09:36:50: %ASA-5-106100: access-list acl_in permitted tcp inside/10.0.1.5(54321) -> dmz/192.168.1.10(80) hit-cnt 1 first hit [0x0, 0x0]"
        ev1 = parse_syslog_log(raw1)
        self.assertEqual(ev1.src_ip, "10.0.1.5")
        self.assertEqual(ev1.src_port, 54321)
        self.assertEqual(ev1.dst_ip, "192.168.1.10")
        self.assertEqual(ev1.dst_port, 80)
        self.assertEqual(ev1.protocol, "tcp")
        self.assertEqual(ev1.activity_name, "Permit")
        self.assertEqual(ev1.status, "Success")
        self.assertEqual(ev1.unmapped.get("acl_name"), "acl_in")

        # 2. IPv6 access-list est-allowed
        raw2 = "Apr 15 2013 09:36:51: %ASA-5-106100: access-list PERMIT_IN est-allowed tcp outside/fe80::2205:baff:fe9d:f637(51234) -> inside/fe80::1(443) hit-cnt 1"
        ev2 = parse_syslog_log(raw2)
        self.assertEqual(ev2.src_ip, "fe80::2205:baff:fe9d:f637")
        self.assertEqual(ev2.src_port, 51234)
        self.assertEqual(ev2.dst_ip, "fe80::1")
        self.assertEqual(ev2.dst_port, 443)
        self.assertEqual(ev2.activity_name, "Permit")
        self.assertEqual(ev2.status, "Success")

        # 3. Hostname endpoint (dmz:OCSP_Server/5678 -> identity:10.0.13.13/80)
        raw3 = "Apr 15 2013 09:36:52: %ASA-5-106100: access-list acl_dmz permitted tcp dmz/OCSP_Server(5678) -> identity/10.0.13.13(80) hit-cnt 1"
        ev3 = parse_syslog_log(raw3)
        self.assertEqual(ev3.src_hostname, "OCSP_Server")
        self.assertEqual(ev3.src_port, 5678)
        self.assertEqual(ev3.dst_ip, "10.0.13.13")
        self.assertEqual(ev3.dst_port, 80)

        # 4. Denied access-list
        raw4 = "Apr 15 2013 09:36:53: %ASA-4-106100: access-list acl_out denied udp outside/203.0.113.50(1234) -> inside/10.0.1.100(53) hit-cnt 5"
        ev4 = parse_syslog_log(raw4)
        self.assertIn(ev4.activity_name, ("Refuse", "Deny"))
        self.assertEqual(ev4.status, "Failure")
        self.assertEqual(ev4.status_id, 2)
        self.assertEqual(ev4.src_ip, "203.0.113.50")
        self.assertEqual(ev4.dst_ip, "10.0.1.100")

    def test_defect3_event_305011_dynamic_translation(self):
        """Test event 305011 Built dynamic translation."""
        raw = "Apr 24 2013 16:00:28: %ASA-6-305011: Built dynamic TCP translation from inside:10.0.1.5/54321 to outside:198.51.100.5/12345"
        ev = parse_syslog_log(raw)
        self.assertEqual(ev.src_ip, "10.0.1.5")
        self.assertEqual(ev.src_port, 54321)
        self.assertEqual(ev.dst_ip, "198.51.100.5")
        self.assertEqual(ev.dst_port, 12345)
        self.assertEqual(ev.protocol, "tcp")
        self.assertEqual(ev.activity_name, "Translate")
        self.assertEqual(ev.status, "Success")

    def test_defect3_event_302013_built_connection(self):
        """Test event 302013 Built connection."""
        raw = "Apr 15 2014 09:34:34 EDT: %ASA-6-302013: Built outbound TCP connection 998877 for outside:198.51.100.10/443 (198.51.100.10/443) to inside:10.0.1.50/54321 (10.0.1.50/54321)"
        ev = parse_syslog_log(raw)
        self.assertEqual(ev.src_ip, "198.51.100.10")
        self.assertEqual(ev.src_port, 443)
        self.assertEqual(ev.dst_ip, "10.0.1.50")
        self.assertEqual(ev.dst_port, 54321)
        self.assertEqual(ev.protocol, "tcp")
        self.assertEqual(ev.status, "Success")
        self.assertEqual(ev.unmapped.get("connection_id"), "998877")

    def test_defect3_event_302014_teardown_connection(self):
        """Test event 302014 Teardown connection with bytes and duration."""
        raw = "Aug 15 2012 23:30:09 : %ASA-6-302014: Teardown TCP connection 998877 for outside:198.51.100.10/443 to inside:10.0.1.50/54321 duration 0:01:30 bytes 4520 TCP FINs"
        ev = parse_syslog_log(raw)
        self.assertEqual(ev.src_ip, "198.51.100.10")
        self.assertEqual(ev.src_port, 443)
        self.assertEqual(ev.dst_ip, "10.0.1.50")
        self.assertEqual(ev.dst_port, 54321)
        self.assertEqual(ev.activity_name, "Teardown")
        self.assertEqual(ev.status, "Success")
        self.assertEqual(ev.traffic_bytes, 4520)
        self.assertEqual(ev.unmapped.get("duration"), "0:01:30")

    def test_defect3_event_106006_deny_inbound_udp(self):
        """Test event 106006 Deny inbound UDP."""
        raw = "Apr 15 2013 09:36:50: %ASA-2-106006: Deny inbound UDP from 198.51.100.25/5353 to 10.0.1.50/5353 on interface outside"
        ev = parse_syslog_log(raw)
        self.assertEqual(ev.src_ip, "198.51.100.25")
        self.assertEqual(ev.src_port, 5353)
        self.assertEqual(ev.dst_ip, "10.0.1.50")
        self.assertEqual(ev.dst_port, 5353)
        self.assertEqual(ev.protocol, "udp")
        self.assertIn(ev.activity_name, ("Refuse", "Deny"))
        self.assertEqual(ev.status, "Failure")

    def test_defect3_event_106016_deny_ip_spoof(self):
        """Test event 106016 Deny IP spoof capturing destination IP."""
        raw = "Apr 15 2013 09:36:50: %ASA-2-106016: Deny IP spoof from (10.0.1.50) to 198.51.100.20 on interface inside"
        ev = parse_syslog_log(raw)
        self.assertEqual(ev.dst_ip, "198.51.100.20")
        self.assertIn(ev.activity_name, ("Refuse", "Deny"))
        self.assertEqual(ev.status, "Failure")

    def test_defect3_event_106023_deny_proto_src_dst(self):
        """Test event 106023 Deny tcp/udp src ... dst ..."""
        raw = 'Apr 15 2013 09:36:50: %ASA-4-106023: Deny tcp src outside:198.51.100.23/54321 dst inside:10.0.1.50/443 by access-group "outside_in" [0x0, 0x0]'
        ev = parse_syslog_log(raw)
        self.assertEqual(ev.src_ip, "198.51.100.23")
        self.assertEqual(ev.src_port, 54321)
        self.assertEqual(ev.dst_ip, "10.0.1.50")
        self.assertEqual(ev.dst_port, 443)
        self.assertEqual(ev.protocol, "tcp")
        self.assertIn(ev.activity_name, ("Refuse", "Deny"))
        self.assertEqual(ev.status, "Failure")

    # ─────────────────────────────────────────────────────────────────
    # 4. Deterministic Severity Mapping (Defect 4)
    # ─────────────────────────────────────────────────────────────────
    def test_defect4_deterministic_severity_mapping(self):
        """
        Assert identical, deterministic severity output across multiple lines with the same %ASA-<level>-<code>.
        Level 1/2 -> Critical (5), Level 3 -> High (4), Level 4 -> Medium (3), Level 5/6/7 -> Informational (1).
        """
        test_lines = [
            ("Apr 15 2013 09:36:50: %ASA-1-106001: Inbound TCP connection reset", "Critical", 5),
            ("Apr 15 2013 09:36:50: %ASA-2-106006: Deny inbound UDP from 1.1.1.1/53 to 2.2.2.2/53", "Critical", 5),
            ("Apr 15 2013 09:36:50: %ASA-3-305005: No translation group found for tcp src", "High", 4),
            ("Apr 15 2013 09:36:50: %ASA-4-106023: Deny tcp src outside:198.51.100.23/54321 dst inside:10.0.1.50/443", "Medium", 3),
            ("Apr 15 2013 09:36:50: %ASA-4-106023: Deny udp src outside:198.51.100.23/1234 dst inside:10.0.1.50/123", "Medium", 3),
            ("Apr 15 2013 09:36:50: %ASA-5-106100: access-list acl_in permitted tcp inside/10.0.1.5(54321) -> dmz/192.168.1.10(80) hit-cnt 1", "Informational", 1),
            ("Apr 15 2013 09:36:50: %ASA-6-302013: Built outbound TCP connection 123 for 1.1.1.1/80 to 2.2.2.2/100", "Informational", 1),
        ]

        for raw_line, exp_sev_name, exp_sev_id in test_lines:
            ev = parse_syslog_log(raw_line)
            self.assertEqual(ev.severity, exp_sev_name, f"Severity name mismatch for {raw_line}: got {ev.severity}")
            self.assertEqual(ev.severity_id, exp_sev_id, f"Severity id mismatch for {raw_line}: got {ev.severity_id}")

    # ─────────────────────────────────────────────────────────────────
    # 5. Tolerance for session- Infix & Missing Colon (Defect 5)
    # ─────────────────────────────────────────────────────────────────
    def test_defect5_session_infix_and_missing_colon(self):
        """
        Verify that %ASA-session-5-106100: and %ASA-6-302016 (missing colon) resolve vendor='Cisco',
        product='ASA', category_name='Network Activity', class_name='Network Activity'.
        """
        # Session infix
        raw_session = "<13>Apr 26 2022 10:24:37: %ASA-session-5-106100: access-list acl_in permitted tcp inside/10.0.1.1(100) -> outside/8.8.8.8(53) hit-cnt 1"
        ev_sess = parse_syslog_log(raw_session)
        self.assertEqual(ev_sess.vendor, "Cisco")
        self.assertEqual(ev_sess.product, "ASA")
        self.assertEqual(ev_sess.category_name, "Network Activity")
        self.assertEqual(ev_sess.class_name, "Network Activity")
        self.assertEqual(ev_sess.status_code, "%ASA-5-106100")
        self.assertEqual(ev_sess.src_ip, "10.0.1.1")
        self.assertEqual(ev_sess.dst_ip, "8.8.8.8")

        # Missing colon after code
        raw_nocolon = "Aug 15 2012 23:30:09 : %ASA-6-302016 Teardown UDP connection 888 for inside:10.0.1.5/53 to outside:8.8.8.8/53 duration 0:00:10 bytes 128"
        ev_nc = parse_syslog_log(raw_nocolon)
        self.assertEqual(ev_nc.vendor, "Cisco")
        self.assertEqual(ev_nc.product, "ASA")
        self.assertEqual(ev_nc.category_name, "Network Activity")
        self.assertEqual(ev_nc.class_name, "Network Activity")
        self.assertEqual(ev_nc.status_code, "%ASA-6-302016")
        self.assertEqual(ev_nc.src_ip, "10.0.1.5")
        self.assertEqual(ev_nc.dst_ip, "8.8.8.8")

    # ─────────────────────────────────────────────────────────────────
    # 6. Comprehensive 89-Line Golden Log Suite
    # ─────────────────────────────────────────────────────────────────
    def test_89_lines_full_sample_log(self):
        """
        Validate full 89-line Cisco ASA log stream:
        Confirm 89/89 lines produce 89 distinct normalized events with 0 lines dropped,
        100% timestamp parse rate, and 100% Cisco ASA vendor/product classification.
        """
        lines_89 = []
        for i in range(1, 90):
            sec = (i * 7) % 60
            # Mix all formats, variants, trailing quotes, hostnames, and event codes
            if i % 8 == 1:
                # Event 106023 with potential trailing quote
                q = '"' if i == 17 else ''
                line = f'Apr 15 2013 09:36:{sec:02d}: %ASA-4-106023: Deny tcp src outside:198.51.100.{i}/5432{i%10} dst inside:10.0.1.{i}/443 by access-group "PERMIT_IN" [0x0, 0x0]{q}'
            elif i % 8 == 2:
                # Event 106100 with hostnames and ports
                line = f'Apr 15 2014 09:34:{sec:02d} EDT: %ASA-5-106100: access-list cached permitted tcp dmz/OCSP_Server({5000+i}) -> identity/10.0.13.{i}(80) hit-cnt 1 first hit [0x0, 0x0]'
            elif i % 8 == 3:
                # Event 106100 with IPv6
                line = f'Apr 24 2013 16:00:{sec:02d} INT-FW01 : %ASA-5-106100: access-list PERMIT_IN est-allowed tcp outside/fe80::2205:baff:fe9d:{i:x}({51000+i}) -> inside/fe80::{i}(443) hit-cnt 1'
            elif i % 8 == 4:
                # Event 305011 Built translation
                line = f'Dec 11 2018 08:01:{sec:02d} <IP>: %ASA-6-305011: Built dynamic TCP translation from inside:10.0.1.{i}/{54000+i} to outside:198.51.100.{i}/{12000+i}'
            elif i % 8 == 5:
                # Event 302013 Built connection
                line = f'Aug 15 2012 23:30:{sec:02d} : %ASA-6-302013: Built outbound TCP connection {10000+i} for outside:198.51.100.{i}/443 (198.51.100.{i}/443) to inside:10.0.1.{i}/{54000+i} (10.0.1.{i}/{54000+i})'
            elif i % 8 == 6:
                # Event 302014 Teardown connection (with missing colon variant)
                colon = '' if i % 2 == 0 else ':'
                line = f'Aug 15 2012 23:30:{sec:02d} : %ASA-6-302014{colon} Teardown TCP connection {10000+i} for outside:198.51.100.{i}/443 to inside:10.0.1.{i}/{54000+i} duration 0:01:30 bytes {4000+i} TCP FINs'
            elif i % 8 == 7:
                # Event 106006 Deny inbound UDP
                line = f'<13>Apr 26 2022 10:24:{sec:02d}: %ASA-2-106006: Deny inbound UDP from 198.51.100.{i}/5353 to 10.0.1.{i}/5353 on interface outside'
            else:
                # Event 106016 Deny IP spoof
                line = f'Apr 15 2013 09:36:{sec:02d}: %ASA-2-106016: Deny IP spoof from (10.0.1.{i}) to 198.51.100.{i} on interface inside'
            lines_89.append(line)

        self.assertEqual(len(lines_89), 89)
        raw_log_payload = "\n".join(lines_89)

        # Ingest via pipeline
        res = run_pipeline(raw_log_payload, filename="cisco_asa_89.log", save_to_db=False)
        events = res["events"]

        self.assertEqual(len(events), 89, f"Expected 89 events, got {len(events)}")

        # Validate completeness and accuracy across all 89 events
        for idx, ev in enumerate(events):
            self.assertEqual(ev.vendor, "Cisco", f"Line {idx+1}: vendor was {ev.vendor}")
            self.assertEqual(ev.product, "ASA", f"Line {idx+1}: product was {ev.product}")
            self.assertEqual(ev.category_name, "Network Activity", f"Line {idx+1}: category was {ev.category_name}")
            self.assertEqual(ev.class_name, "Network Activity", f"Line {idx+1}: class was {ev.class_name}")
            self.assertIsNotNone(ev.timestamp, f"Line {idx+1}: timestamp was None")
            self.assertIsNotNone(ev.status_code, f"Line {idx+1}: status_code was None")
            self.assertIsNotNone(ev.severity, f"Line {idx+1}: severity was None")
            self.assertIn(ev.status, ("Success", "Failure"), f"Line {idx+1}: status was {ev.status}")
            # Ensure at least one endpoint (IP or Hostname) is populated
            has_endpoint = bool(ev.src_ip or ev.dst_ip or ev.src_hostname or ev.dst_hostname)
            self.assertTrue(has_endpoint, f"Line {idx+1}: No endpoint extracted from {ev.message}")


if __name__ == "__main__":
    unittest.main()
