"""
Unit tests for ULPF Validation Subsystem (app/validation/validator.py).
"""

from __future__ import annotations

import unittest
from datetime import datetime, timezone

from app.validation.validator import (
    validate_ip,
    validate_port,
    validate_severity,
    validate_status,
    validate_timestamp,
)


class TestValidationSubsystem(unittest.TestCase):
    def test_validate_ip(self):
        # Valid IPv4
        self.assertEqual(validate_ip("192.168.1.1"), "192.168.1.1")
        self.assertEqual(validate_ip("10.0.0.1"), "10.0.0.1")
        self.assertEqual(validate_ip("172.16.254.1"), "172.16.254.1")

        # Valid IPv6
        self.assertEqual(validate_ip("2001:db8::1"), "2001:db8::1")
        self.assertEqual(validate_ip("::1"), "::1")

        # Invalid IP addresses
        self.assertIsNone(validate_ip("999.999.999.999"))
        self.assertIsNone(validate_ip("192.168.1"))
        self.assertIsNone(validate_ip("abc.def.ghi.jkl"))
        self.assertIsNone(validate_ip("unknown"))
        self.assertIsNone(validate_ip(None))
        self.assertIsNone(validate_ip(12345))

    def test_validate_port(self):
        # Valid ports
        self.assertEqual(validate_port(80), 80)
        self.assertEqual(validate_port(443), 443)
        self.assertEqual(validate_port("8080"), 8080)
        self.assertEqual(validate_port(65535), 65535)
        self.assertEqual(validate_port(1), 1)

        # Invalid ports
        self.assertIsNone(validate_port(0))
        self.assertIsNone(validate_port(-1))
        self.assertIsNone(validate_port(65536))
        self.assertIsNone(validate_port("invalid"))
        self.assertIsNone(validate_port(None))

    def test_validate_timestamp(self):
        # Valid datetime object
        dt = datetime(2026, 8, 26, 12, 0, 0, tzinfo=timezone.utc)
        self.assertEqual(validate_timestamp(dt), dt)

        # Valid ISO strings
        res = validate_timestamp("2026-08-26T12:00:00Z")
        self.assertIsNotNone(res)
        self.assertEqual(res.year, 2026)

        # Invalid timestamps
        self.assertIsNone(validate_timestamp("not a timestamp"))
        self.assertIsNone(validate_timestamp(None))

    def test_validate_severity(self):
        # Standard OCSF names
        self.assertEqual(validate_severity("High", None), ("High", 4))
        self.assertEqual(validate_severity("critical", None), ("Critical", 5))
        self.assertEqual(validate_severity("info", None), ("Informational", 1))

        # Numeric severity IDs
        self.assertEqual(validate_severity(None, 4), ("High", 4))
        self.assertEqual(validate_severity(None, 1), ("Informational", 1))
        self.assertEqual(validate_severity(None, 0), ("Unknown", 0))

        # Invalid severity
        self.assertEqual(validate_severity(None, None), (None, None))
        self.assertEqual(validate_severity(None, 99), (None, None))

    def test_validate_status(self):
        # Standard OCSF status names
        self.assertEqual(validate_status("Success", None), ("Success", 1))
        self.assertEqual(validate_status("failure", None), ("Failure", 2))
        self.assertEqual(validate_status("other", None), ("Other", 99))

        # Numeric status IDs
        self.assertEqual(validate_status(None, 1), ("Success", 1))
        self.assertEqual(validate_status(None, 2), ("Failure", 2))

        # Invalid status
        self.assertEqual(validate_status(None, None), (None, None))
        self.assertEqual(validate_status(None, 42), (None, None))


if __name__ == "__main__":
    unittest.main()
