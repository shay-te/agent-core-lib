"""Tests for :func:`agent_core_lib.pii._pii_strict_phone.find_strict_phone`.

Validates that the ``phonenumbers``-backed detector finds real numbers
and refuses the false-positive class the loose regex would catch
(order ids, timestamps).
"""
from __future__ import annotations

import unittest

from agent_core_lib.pii._pii_strict_phone import find_strict_phone


class TestStrictPhoneDetector(unittest.TestCase):
    def test_us_e164_match(self):
        findings = find_strict_phone('call +1 212 555 1234 today')
        self.assertEqual(
            [f.pattern_name for f in findings],
            ['phone_strict'],
        )

    def test_uk_e164_match(self):
        findings = find_strict_phone('reach +44 20 7946 0958 now')
        self.assertEqual([f.pattern_name for f in findings], ['phone_strict'])

    def test_de_e164_match(self):
        findings = find_strict_phone('reach +49 30 12345678 today')
        self.assertEqual([f.pattern_name for f in findings], ['phone_strict'])

    def test_national_form_with_default_region(self):
        findings = find_strict_phone('call 212-555-1234 today', default_region='US')
        self.assertEqual([f.pattern_name for f in findings], ['phone_strict'])

    def test_order_id_is_not_phone(self):
        findings = find_strict_phone('order 1234567890123456 shipped')
        self.assertEqual(findings, [])

    def test_unix_timestamp_is_not_phone(self):
        findings = find_strict_phone('logged at 1640995200 epoch')
        self.assertEqual(findings, [])

    def test_redacted_preview_never_carries_full_number(self):
        findings = find_strict_phone('reach +1 212 555 1234 now')
        self.assertEqual(len(findings), 1)
        self.assertNotIn('555 1234', findings[0].redacted_preview)
        self.assertIn('REDACTED', findings[0].redacted_preview)

    def test_empty_text_returns_empty(self):
        self.assertEqual(find_strict_phone(''), [])
        self.assertEqual(find_strict_phone(None), [])  # type: ignore[arg-type]


if __name__ == '__main__':
    unittest.main()
