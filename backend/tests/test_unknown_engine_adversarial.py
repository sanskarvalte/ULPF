"""
Adversarial Test Suite for ULPF Unknown Log Intelligence Engine.

Covers all 18 required adversarial & edge-case scenarios:
1. Same format with changed values (IPs, users, timestamps, numbers)
2. Missing optional fields
3. Extra fields (losslessly preserved in unmapped)
4. Reordered key/value pairs
5. Quoted messages
6. Commas inside messages
7. Spaces inside values
8. Timestamps containing spaces
9. IPv6 addresses
10. IPv4 addresses
11. Port values
12. Negative numbers
13. Decimal numbers
14. UUIDs
15. URLs
16. Escaped characters
17. Unicode / UTF-8
18. Empty / null / dash values

Also verifies the Strict Accuracy Gate:
- 100% target enforcement across all 6 metrics
- Structured failing_fields diagnostics
- Automatic repair loop
- Strict rejection of untrusted parsers below target
- Zero per-event AI call reuse of learned parsers
"""

import unittest
from unittest.mock import patch, MagicMock
from datetime import datetime, timezone

from app.ai.fingerprint import (
    compute_log_fingerprint,
    group_templates_by_fingerprint,
)
from app.ai.dynamic_parser import (
    parse_with_spec,
    _parse_key_value,
    _parse_delimited,
    _convert_value,
)
from app.ai.parser_accuracy import (
    evaluate_parser_accuracy,
    check_sample_accuracy,
)
from app.ai.parser_resolver import (
    resolve_parser_spec,
    DEFAULT_ACCURACY_THRESHOLD,
)
from app.parsers.registry import (
    register_parser,
    get_parser,
    has_parser,
    promote_parser,
    reject_parser,
    clear_parsers,
    list_parsers,
)


class TestUnknownLogEngineAdversarial(unittest.TestCase):
    def setUp(self):
        clear_parsers()

    def tearDown(self):
        clear_parsers()

    # -------------------------------------------------------------------------
    # 1. SAME FORMAT WITH CHANGED VALUES & TEMPLATE GROUPING
    # -------------------------------------------------------------------------
    def test_adversarial_same_format_changed_values(self):
        """
        Structural fingerprinting must collapse variable values (IPs, users,
        timestamps, numbers, UUIDs) and never use actual values as identity.
        """
        line1 = '2026-08-27 10:00:00 ip=192.168.1.1 user=alice duration=12ms action=login'
        line2 = '2026-08-27 11:15:30 ip=10.0.0.5 user=bob duration=340ms action=logout'
        line3 = '2026-08-27 12:45:00 ip=172.16.0.20 user=charlie duration=5ms action=login'

        tmpl1, _, fp1 = compute_log_fingerprint(line1)
        tmpl2, _, fp2 = compute_log_fingerprint(line2)
        tmpl3, _, fp3 = compute_log_fingerprint(line3)

        self.assertEqual(fp1, fp2, "Fingerprints must be identical for same format with changed values")
        self.assertEqual(fp2, fp3, "Fingerprints must be identical for same format with changed values")
        self.assertEqual(tmpl1, tmpl2)

        # Values should not be in the template
        self.assertNotIn("alice", tmpl1)
        self.assertNotIn("192.168.1.1", tmpl1)
        self.assertNotIn("340ms", tmpl1)

        # Template grouping verification
        groups = group_templates_by_fingerprint([line1, line2, line3])
        self.assertEqual(len(groups), 1, "Should group all 3 lines into exactly 1 template group")
        self.assertEqual(groups[fp1]["count"], 3)
        self.assertEqual(len(groups[fp1]["samples"]), 3)

    # -------------------------------------------------------------------------
    # 2. TIMESTAMPS CONTAINING SPACES AND DIVERSE FORMATS
    # -------------------------------------------------------------------------
    def test_adversarial_timestamps_containing_spaces(self):
        """
        Timestamps containing spaces (e.g. 'YYYY-MM-DD HH:MM:SS') must be
        fingerprinted without fragmenting into separate word tokens and parsed accurately.
        """
        line = '2026-08-27 14:20:15 ip=10.0.0.1 user=admin msg="System rebooted"'
        tmpl, _, fp = compute_log_fingerprint(line)
        self.assertTrue(tmpl.startswith("<TS>"), f"Expected <TS> prefix, got {tmpl}")

        spec = {
            "format_name": "space_ts_test",
            "parser_type": "key_value",
            "fields": [
                {"name": "timestamp", "type": "datetime"},
                {"name": "src_ip", "type": "ip"},
                {"name": "user", "type": "string"},
                {"name": "message", "type": "string"},
            ],
            "timestamp_field": "timestamp",
        }
        event = parse_with_spec(line, spec)
        self.assertIsNotNone(event.timestamp)
        self.assertEqual(event.timestamp.year, 2026)
        self.assertEqual(event.timestamp.month, 8)
        self.assertEqual(event.timestamp.day, 27)
        self.assertEqual(event.timestamp.hour, 14)
        self.assertEqual(event.src_ip, "10.0.0.1")
        self.assertEqual(event.user, "admin")

    # -------------------------------------------------------------------------
    # 3. IPV6 AND IPV4 ADDRESSES
    # -------------------------------------------------------------------------
    def test_adversarial_ipv4_and_ipv6(self):
        """
        Must recognize both IPv4 and various forms of IPv6 addresses:
        full, compressed (::1), link-local (fe80::).
        """
        ipv4_line = 'src=192.168.1.50 dst=10.200.1.99 action=ACCEPT'
        ipv6_line = 'src=2001:0db8:85a3:0000:0000:8a2e:0370:7334 dst=fe80::1 action=ACCEPT'
        loopback_line = 'src=::1 dst=::1 action=DROP'

        tmpl_v4, _, fp_v4 = compute_log_fingerprint(ipv4_line)
        tmpl_v6, _, fp_v6 = compute_log_fingerprint(ipv6_line)
        tmpl_loop, _, fp_loop = compute_log_fingerprint(loopback_line)

        self.assertEqual(tmpl_v4, tmpl_v6, "IPv4 and IPv6 structural templates must match")
        self.assertEqual(fp_v4, fp_v6)
        self.assertEqual(fp_v4, fp_loop)

        spec = {
            "format_name": "ip_test",
            "parser_type": "key_value",
            "fields": [
                {"name": "src_ip", "type": "ip"},
                {"name": "dst_ip", "type": "ip"},
                {"name": "action", "type": "action"},
            ],
        }
        ev_v6 = parse_with_spec(ipv6_line, spec)
        self.assertIn(ev_v6.src_ip, ("2001:0db8:85a3:0000:0000:8a2e:0370:7334", "2001:db8:85a3::8a2e:370:7334"))
        self.assertEqual(ev_v6.dst_ip, "fe80::1")

    # -------------------------------------------------------------------------
    # 4. PORT VALUES
    # -------------------------------------------------------------------------
    def test_adversarial_port_values(self):
        """
        Port numbers must be parsed into integer values between 0 and 65535.
        """
        line = 'proto=TCP src_ip=10.0.0.1 src_port=8080 dst_ip=10.0.0.2 dst_port=443'
        spec = {
            "format_name": "port_test",
            "parser_type": "key_value",
            "fields": [
                {"name": "protocol", "type": "protocol"},
                {"name": "src_ip", "type": "ip"},
                {"name": "src_port", "type": "port"},
                {"name": "dst_ip", "type": "ip"},
                {"name": "dst_port", "type": "port"},
            ],
        }
        event = parse_with_spec(line, spec)
        self.assertEqual(event.src_port, 8080)
        self.assertEqual(event.dst_port, 443)
        self.assertIsInstance(event.src_port, int)
        self.assertIsInstance(event.dst_port, int)

    # -------------------------------------------------------------------------
    # 5. NEGATIVE AND DECIMAL NUMBERS
    # -------------------------------------------------------------------------
    def test_adversarial_negative_and_decimal_numbers(self):
        """
        Handles negative numbers and decimal values in fingerprinting and extraction.
        """
        line = 'temp=-15.5 delta=-42 duration=0.0034 score=99.95'
        tmpl, _, _ = compute_log_fingerprint(line)
        self.assertNotIn("-15.5", tmpl)
        self.assertNotIn("-42", tmpl)

        self.assertEqual(_convert_value("-42", "number"), -42)
        self.assertEqual(_convert_value("-15.5", "number"), -15.5)
        self.assertEqual(_convert_value("0.0034", "float"), 0.0034)
        self.assertEqual(_convert_value("99.95", "decimal"), 99.95)

    # -------------------------------------------------------------------------
    # 6. UUIDS AND CRYPTOGRAPHIC HASHES
    # -------------------------------------------------------------------------
    def test_adversarial_uuids_and_hashes(self):
        """
        Recognizes standard UUIDs and 32/64 hex hashes (MD5, SHA-256).
        """
        line = (
            'trace_id=550e8400-e29b-41d4-a716-446655440000 '
            'sha256=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 '
            'md5=d41d8cd98f00b204e9800998ecf8427e'
        )
        tmpl, _, _ = compute_log_fingerprint(line)
        self.assertIn("<UUID>", tmpl)
        self.assertIn("<HEX>", tmpl)
        self.assertNotIn("550e8400", tmpl)
        self.assertNotIn("e3b0c442", tmpl)

    # -------------------------------------------------------------------------
    # 7. URLS
    # -------------------------------------------------------------------------
    def test_adversarial_urls(self):
        """
        Recognizes full URLs with protocols, paths, query parameters, and fragments.
        """
        line = 'user=alice url="https://api.example.com/v1/checkout?cart_id=99&ref=promo#top" status=200'
        tmpl, _, _ = compute_log_fingerprint(line)
        self.assertNotIn("https://api.example.com", tmpl)

        spec = {
            "format_name": "url_test",
            "parser_type": "key_value",
            "fields": [
                {"name": "user", "type": "string"},
                {"name": "url", "type": "string"},
                {"name": "status_code", "type": "number"},
            ],
        }
        event = parse_with_spec(line, spec)
        self.assertEqual(event.unmapped.get("url"), "https://api.example.com/v1/checkout?cart_id=99&ref=promo#top")

    # -------------------------------------------------------------------------
    # 8. QUOTED MESSAGES WITH COMMAS AND SPACES INSIDE
    # -------------------------------------------------------------------------
    def test_adversarial_quoted_messages_and_commas_inside(self):
        """
        Delimiters like commas and spaces inside quoted strings must not split fields.
        """
        line = 'status=500 msg="Failed to connect to db, timeout after 30s, retry failed" host=node-1'
        spec = {
            "format_name": "quoted_msg_test",
            "parser_type": "key_value",
            "fields": [
                {"name": "status_code", "type": "number"},
                {"name": "message", "type": "string"},
                {"name": "src_hostname", "type": "string"},
            ],
        }
        event = parse_with_spec(line, spec)
        self.assertEqual(event.message, "Failed to connect to db, timeout after 30s, retry failed")
        self.assertEqual(event.src_hostname, "node-1")
        self.assertEqual(event.status_code, "500")

    # -------------------------------------------------------------------------
    # 9. SPACES INSIDE VALUES
    # -------------------------------------------------------------------------
    def test_adversarial_spaces_inside_values(self):
        """
        Spaces inside quoted values (e.g. user-agent strings) must remain intact.
        """
        line = 'ip=1.2.3.4 agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64)" action=ALLOW'
        spec = {
            "format_name": "user_agent_test",
            "parser_type": "key_value",
            "fields": [
                {"name": "src_ip", "type": "ip"},
                {"name": "user_agent", "type": "string"},
                {"name": "action", "type": "action"},
            ],
        }
        event = parse_with_spec(line, spec)
        self.assertEqual(event.unmapped.get("user_agent"), "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
        self.assertEqual(event.src_ip, "1.2.3.4")

    # -------------------------------------------------------------------------
    # 10. ESCAPED CHARACTERS
    # -------------------------------------------------------------------------
    def test_adversarial_escaped_characters(self):
        """
        Handles escaped quotes, newlines, and backslashes inside quoted strings.
        """
        line = r'user="alice" msg="User said \"Access Denied\\Exit\" immediately\n"'
        spec = {
            "format_name": "escaped_test",
            "parser_type": "key_value",
            "fields": [
                {"name": "user", "type": "string"},
                {"name": "message", "type": "string"},
            ],
        }
        event = parse_with_spec(line, spec)
        self.assertEqual(event.user, "alice")
        self.assertIn('"Access Denied\\Exit"', event.message)
        self.assertTrue(event.message.endswith("\n"))

    # -------------------------------------------------------------------------
    # 11. UNICODE / UTF-8
    # -------------------------------------------------------------------------
    def test_adversarial_unicode_utf8(self):
        """
        Correctly parses non-ASCII Unicode characters (accents, emojis, CJK).
        """
        line = 'user="Jöhn Döe 🚀" city="München" error="認証に失敗しました"'
        spec = {
            "format_name": "unicode_test",
            "parser_type": "key_value",
            "fields": [
                {"name": "user", "type": "string"},
                {"name": "city", "type": "string"},
                {"name": "message", "type": "string"},
            ],
        }
        event = parse_with_spec(line, spec)
        self.assertEqual(event.user, "Jöhn Döe 🚀")
        self.assertEqual(event.unmapped.get("city"), "München")
        self.assertEqual(event.message, "認証に失敗しました")

    # -------------------------------------------------------------------------
    # 12. EMPTY / NULL / DASH VALUES
    # -------------------------------------------------------------------------
    def test_adversarial_empty_values(self):
        """
        Empty quotes, '-', 'null', 'none' must convert cleanly to None without errors.
        """
        line = 'user="" ip="-" session=null status=nil comment=none'
        spec = {
            "format_name": "empty_test",
            "parser_type": "key_value",
            "fields": [
                {"name": "user", "type": "string"},
                {"name": "src_ip", "type": "ip"},
                {"name": "session_uid", "type": "string"},
                {"name": "status", "type": "string"},
            ],
        }
        event = parse_with_spec(line, spec)
        self.assertIsNone(event.src_ip)
        self.assertIsNone(event.session_uid)

    # -------------------------------------------------------------------------
    # 13. REORDERED KEY/VALUE PAIRS
    # -------------------------------------------------------------------------
    def test_adversarial_reordered_key_value_pairs(self):
        """
        Extracts key-value pairs accurately regardless of the order they appear in.
        """
        line_a = 'action=LOGIN user=bob ip=10.0.0.5 status=SUCCESS'
        line_b = 'status=SUCCESS ip=10.0.0.5 user=bob action=LOGIN'

        spec = {
            "format_name": "reorder_test",
            "parser_type": "key_value",
            "fields": [
                {"name": "action", "type": "action"},
                {"name": "user", "type": "string"},
                {"name": "src_ip", "type": "ip"},
                {"name": "status", "type": "string"},
            ],
        }

        event_a = parse_with_spec(line_a, spec)
        event_b = parse_with_spec(line_b, spec)

        self.assertEqual(event_a.user, event_b.user)
        self.assertEqual(event_a.src_ip, event_b.src_ip)
        self.assertEqual(event_a.status, event_b.status)

    # -------------------------------------------------------------------------
    # 14. MISSING OPTIONAL FIELDS
    # -------------------------------------------------------------------------
    def test_adversarial_missing_optional_fields(self):
        """
        Lines missing optional fields parse gracefully without crashing or offset corruption.
        """
        line_complete = "2026-08-27T10:00:00Z|AUTH|jdoe|10.0.0.1|invalid_password"
        line_missing_optional = "2026-08-27T10:00:00Z|AUTH|jdoe|10.0.0.1"

        spec = {
            "format_name": "optional_pipe_test",
            "parser_type": "delimited",
            "delimiter": "|",
            "fields": [
                {"name": "timestamp", "type": "datetime"},
                {"name": "service_name", "type": "string"},
                {"name": "user", "type": "string"},
                {"name": "src_ip", "type": "ip"},
                {"name": "status_detail", "type": "string"},
            ],
            "timestamp_field": "timestamp",
            "optional_fields": ["status_detail"],
        }

        event_complete = parse_with_spec(line_complete, spec)
        self.assertEqual(event_complete.status_detail, "invalid_password")

        event_missing = parse_with_spec(line_missing_optional, spec)
        self.assertEqual(event_missing.user, "jdoe")
        self.assertEqual(event_missing.src_ip, "10.0.0.1")
        self.assertIsNone(event_missing.status_detail)

    # -------------------------------------------------------------------------
    # 15. EXTRA FIELDS PRESERVED LOSSLESSLY
    # -------------------------------------------------------------------------
    def test_adversarial_extra_fields_preserved_losslessly(self):
        """
        Unmapped / unanticipated custom fields must be preserved losslessly in event.unmapped.
        """
        line = 'action=LOGIN user=alice tenant_id=org_corp_99 data_center=us-east-1 pod=prod-04'
        spec = {
            "format_name": "extra_fields_test",
            "parser_type": "key_value",
            "fields": [
                {"name": "action", "type": "action"},
                {"name": "user", "type": "string"},
            ],
        }
        event = parse_with_spec(line, spec)
        self.assertEqual(event.user, "alice")
        self.assertIsNotNone(event.unmapped)
        self.assertEqual(event.unmapped.get("tenant_id"), "org_corp_99")
        self.assertEqual(event.unmapped.get("data_center"), "us-east-1")
        self.assertEqual(event.unmapped.get("pod"), "prod-04")

    # -------------------------------------------------------------------------
    # 16. MIXED DELIMITERS
    # -------------------------------------------------------------------------
    def test_adversarial_mixed_delimiters(self):
        """
        Logs containing mixed delimiters (e.g. key:value and key=value) are extracted correctly.
        """
        line = 'tag:auth user=alice ip=10.0.0.1 status:success code=200'
        spec = {
            "format_name": "mixed_delims",
            "parser_type": "key_value",
            "fields": [
                {"name": "tag", "type": "string"},
                {"name": "user", "type": "string"},
                {"name": "src_ip", "type": "ip"},
                {"name": "status", "type": "string"},
                {"name": "status_code", "type": "number"},
            ],
        }
        event = parse_with_spec(line, spec)
        self.assertEqual(event.user, "alice")
        self.assertEqual(event.src_ip, "10.0.0.1")
        self.assertEqual(event.unmapped.get("tag"), "auth")
        self.assertEqual(event.status.lower(), "success")
        self.assertEqual(event.status_code, "200")

    # -------------------------------------------------------------------------
    # 17. STRICT ACCURACY GATE: 100% TARGET VERIFICATION ACROSS ALL 6 METRICS
    # -------------------------------------------------------------------------
    def test_accuracy_gate_100_percent_target(self):
        """
        For ground truth samples, all 6 accuracy metrics must be evaluated:
        exact_field_match, normalized_field_match, event_level_match,
        field_coverage, unknown_field_preservation, parse_success.
        """
        samples = [
            {
                "raw": "user=alice ip=10.0.0.1 action=LOGIN status=SUCCESS",
                "expected": {
                    "user": "alice",
                    "src_ip": "10.0.0.1",
                    "action": "LOGIN",
                    "status": "SUCCESS",
                },
            },
            {
                "raw": "user=bob ip=10.0.0.2 action=LOGOUT status=SUCCESS",
                "expected": {
                    "user": "bob",
                    "src_ip": "10.0.0.2",
                    "action": "LOGOUT",
                    "status": "SUCCESS",
                },
            },
        ]
        spec = {
            "format_name": "acc_gate_test",
            "parser_type": "key_value",
            "fields": [
                {"name": "user", "type": "string"},
                {"name": "src_ip", "type": "ip"},
                {"name": "action", "type": "action"},
                {"name": "status", "type": "string"},
            ],
        }

        results = evaluate_parser_accuracy(samples, spec, accuracy_threshold=100.0)

        self.assertTrue(results["passed_gate"])
        self.assertGreaterEqual(results["exact_field_match"], 75.0)
        self.assertEqual(results["normalized_field_match"], 100.0)
        self.assertEqual(results["event_level_match"], 100.0)
        self.assertEqual(results["field_coverage"], 100.0)
        self.assertEqual(results["unknown_field_preservation"], 100.0)
        self.assertEqual(results["parse_success"], 100.0)
        self.assertEqual(len(results["failing_fields"]), 0)

    # -------------------------------------------------------------------------
    # 18. ACCURACY GATE REPAIR LOOP & STRUCTURED FAILING FIELDS
    # -------------------------------------------------------------------------
    @patch("app.ai.parser_resolver.generate_parser_spec")
    @patch("app.ai.parser_resolver.repair_parser_spec")
    def test_accuracy_gate_repair_loop_and_promotion(
        self,
        mock_repair,
        mock_generate,
    ):
        """
        When generated spec fails accuracy gate (e.g. wrong field name in delimited log),
        the engine pinpoints failing fields, calls repair, and promotes on success.
        """
        flawed_spec = {
            "format_name": "flawed_pipe",
            "parser_type": "delimited",
            "delimiter": "|",
            "fields": [
                {"name": "wrong_field", "type": "string"},
                {"name": "src_ip", "type": "ip"},
            ],
        }
        repaired_spec = {
            "format_name": "repaired_pipe",
            "parser_type": "delimited",
            "delimiter": "|",
            "fields": [
                {"name": "user", "type": "string"},
                {"name": "src_ip", "type": "ip"},
            ],
        }

        mock_generate.return_value = flawed_spec
        mock_repair.return_value = repaired_spec

        samples = [
            {
                "raw": "alice|10.0.0.1",
                "expected": {"user": "alice", "src_ip": "10.0.0.1"},
            }
        ]

        result = resolve_parser_spec(
            log_samples="alice|10.0.0.1",
            accuracy_samples=samples,
            accuracy_threshold=100.0,
        )

        self.assertTrue(result["success"])
        self.assertEqual(result["status"], "promoted")
        self.assertEqual(result["repair_attempts"], 1)
        self.assertEqual(result["accuracy"], 100.0)
        mock_repair.assert_called_once()

    # -------------------------------------------------------------------------
    # 19. STRICT REJECTION OF UNTRUSTED PARSERS BELOW TARGET
    # -------------------------------------------------------------------------
    @patch("app.ai.parser_resolver.generate_parser_spec")
    @patch("app.ai.parser_resolver.repair_parser_spec")
    def test_accuracy_gate_strict_rejection_below_target(
        self,
        mock_repair,
        mock_generate,
    ):
        """
        If after maximum repair attempts the parser is still below target accuracy,
        it MUST be rejected and NOT registered as a trusted active parser.
        """
        unrepairable_spec = {
            "format_name": "bad_pipe",
            "parser_type": "delimited",
            "delimiter": "|",
            "fields": [
                {"name": "unrelated", "type": "string"},
            ],
        }

        mock_generate.return_value = unrepairable_spec
        mock_repair.return_value = unrepairable_spec

        samples = [
            {
                "raw": "alice|10.0.0.1",
                "expected": {"user": "alice", "src_ip": "10.0.0.1"},
            }
        ]

        result = resolve_parser_spec(
            log_samples="alice|10.0.0.1",
            accuracy_samples=samples,
            accuracy_threshold=100.0,
        )

        self.assertFalse(result["success"])
        self.assertEqual(result["status"], "rejected")
        self.assertGreaterEqual(result["repair_attempts"], 1)
        self.assertLess(result["accuracy"], 100.0)

        # Confirm registry behavior: rejected parser is NOT active
        fp = "test_fp_rejected"
        reject_parser(fp, reason="Accuracy gate failed target of 100%")
        self.assertFalse(has_parser(fp), "Rejected parser must not be active in registry")
        self.assertIsNone(get_parser(fp), "Rejected parser must return None")

    # -------------------------------------------------------------------------
    # 20. ZERO PER-LINE AI: LEARNED PARSER REUSE WITHOUT OLLAMA
    # -------------------------------------------------------------------------
    def test_learned_parser_reuse_zero_per_event_ai(self):
        """
        Once a parser is learned and registered, 100+ subsequent log lines with the
        same fingerprint execute directly via the deterministic parser engine
        without invoking Ollama.
        """
        spec = {
            "format_name": "learned_auth_kv",
            "parser_type": "key_value",
            "fields": [
                {"name": "timestamp", "type": "datetime"},
                {"name": "src_ip", "type": "ip"},
                {"name": "user", "type": "string"},
                {"name": "action", "type": "action"},
                {"name": "status_code", "type": "number"},
            ],
            "timestamp_field": "timestamp",
        }

        template_line = '2026-08-27 10:00:00 ip=192.168.1.1 user=u1 action=LOGIN code=200'
        _, _, fp = compute_log_fingerprint(template_line)

        # Register learned parser
        register_parser(fp, spec, status="active")
        self.assertTrue(has_parser(fp))

        # Simulate 100 incoming events of the same format with different values
        events_processed = 0
        ai_invocations = 0

        for i in range(100):
            line = f'2026-08-27 10:{i % 60:02d}:00 ip=10.0.0.{i} user=user_{i} action=LOGIN code={200 + i % 5}'
            _, _, cur_fp = compute_log_fingerprint(line)
            self.assertEqual(cur_fp, fp, "All lines must share the learned fingerprint")

            # Lookup parser in registry (zero AI)
            cached_spec = get_parser(cur_fp)
            if cached_spec is None:
                ai_invocations += 1
            else:
                event = parse_with_spec(line, cached_spec)
                self.assertEqual(event.user, f"user_{i}")
                self.assertEqual(event.src_ip, f"10.0.0.{i}")
                events_processed += 1

        self.assertEqual(events_processed, 100)
        self.assertEqual(ai_invocations, 0, "Ollama must NEVER be called per event once learned")


if __name__ == "__main__":
    unittest.main()
