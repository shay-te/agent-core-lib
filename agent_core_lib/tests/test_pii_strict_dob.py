"""Tests for :func:`agent_core_lib.pii._pii_strict_dob.find_strict_dob`.

Validates that the dateparser-backed detector fires on plausible DOBs
without a keyword and refuses dates that aren't plausible birthdays.
"""
from __future__ import annotations

import unittest
from datetime import date

from agent_core_lib.pii._pii_strict_dob import find_strict_dob


class TestStrictDobDetector(unittest.TestCase):
    def test_iso_format_plausible_dob_fires(self):
        findings = find_strict_dob('subject 1990-05-15 on record')
        self.assertEqual([f.pattern_name for f in findings], ['dob_strict'])

    def test_us_format_plausible_dob_fires(self):
        findings = find_strict_dob('born 05/15/1990 in NYC')
        self.assertEqual([f.pattern_name for f in findings], ['dob_strict'])

    def test_eu_format_plausible_dob_fires(self):
        findings = find_strict_dob('subject 15/05/1990 active')
        self.assertEqual([f.pattern_name for f in findings], ['dob_strict'])

    def test_future_date_not_dob(self):
        future = date.today().year + 5
        findings = find_strict_dob(f'event {future}-01-01 scheduled')
        self.assertEqual(findings, [])

    def test_pre_1900_date_not_dob(self):
        findings = find_strict_dob('historic 1850-01-01 entry')
        self.assertEqual(findings, [])

    def test_unparseable_date_shape_returns_empty(self):
        findings = find_strict_dob('version 1.2.3-rc.4 released')
        self.assertEqual(findings, [])

    def test_empty_text_returns_empty(self):
        self.assertEqual(find_strict_dob(''), [])
        self.assertEqual(find_strict_dob(None), [])  # type: ignore[arg-type]

    def test_redacted_preview_never_carries_full_date(self):
        findings = find_strict_dob('subject 1990-05-15 noted')
        self.assertEqual(len(findings), 1)
        self.assertNotIn('1990-05-15', findings[0].redacted_preview)
        self.assertIn('REDACTED', findings[0].redacted_preview)

    def test_invalid_date_shape_skipped_by_dateparser(self):
        # The shape regex matches but ``dateparser`` returns ``None`` —
        # the candidate is silently dropped. Exercises the ``parsed
        # is None`` branch.
        findings = find_strict_dob('field 00/00/2020 noted')
        self.assertEqual(findings, [])


if __name__ == '__main__':
    unittest.main()
