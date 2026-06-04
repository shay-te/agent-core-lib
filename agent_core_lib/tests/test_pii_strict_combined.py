"""Tests for :func:`agent_core_lib.pii.pii_patterns.find_pii_strict`.

Combines :func:`find_pii_patterns` (regex) + the library-backed
detectors (``phonenumbers`` + ``dateparser``) + optional spaCy NER.
"""
from __future__ import annotations

import unittest

from agent_core_lib.pii.pii_patterns import find_pii_strict


class TestFindPiiStrict(unittest.TestCase):
    def test_regex_and_strict_detectors_combined(self):
        text = (
            'jane@example.com reach +1 212 555 1234 '
            'born 05/15/1990 ssn 123-45-6789'
        )
        findings = find_pii_strict(text)
        names = {f.pattern_name for f in findings}
        # Regex-based detectors fire.
        self.assertIn('email', names)
        self.assertIn('ssn', names)
        # Library-backed strict detectors fire too.
        self.assertIn('phone_strict', names)
        self.assertIn('dob_strict', names)

    def test_empty_text_returns_empty(self):
        self.assertEqual(find_pii_strict(''), [])

    def test_clean_text_returns_empty(self):
        # No PII shapes — regex + strict detectors all miss.
        self.assertEqual(
            find_pii_strict('the request completed successfully'),
            [],
        )

    def test_include_ner_off_by_default(self):
        # spaCy NER would flag "Jane Smith" as person_name. With the
        # default include_ner=False, no person_name finding appears.
        findings = find_pii_strict('Jane Smith joined the team')
        names = {f.pattern_name for f in findings}
        self.assertNotIn('person_name', names)

    def test_include_ner_true_pulls_in_spacy_findings(self):
        # When the caller opts in and spaCy is installed, ``person_name``
        # appears in the combined output. Skips cleanly when spaCy
        # isn't available so the test still passes in lean envs.
        try:
            import spacy
            spacy.load('en_core_web_sm')
        except (ImportError, OSError):
            self.skipTest('spaCy + en_core_web_sm not installed')
        findings = find_pii_strict('Jane Smith joined the team', include_ner=True)
        names = {f.pattern_name for f in findings}
        self.assertIn('person_name', names)


if __name__ == '__main__':
    unittest.main()
