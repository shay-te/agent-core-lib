"""Bulletproof corpus for the long-tail healthcare codes patterns."""
from __future__ import annotations

import unittest

from agent_core_lib.pii.pii_patterns import find_pii_patterns


_PATTERN_NAMES = frozenset({
    'clia',
    'icd10_code',
    'ndc_drug_code',
})

_POSITIVES = (
    'CLIA 12D1234567 on file',
    'NDC 12345-678-90 prescribed',
    'diagnosis ICD-10 A01.0 confirmed',
)
_NEGATIVES = (
    'random patient text',
    'order 123-456-78 shipped',
)


class TestHealthcareCodesBulletproof(unittest.TestCase):
    def test_positive_corpus(self):
        failures = [
            text for text in _POSITIVES
            if not any(
                f.pattern_name in _PATTERN_NAMES
                for f in find_pii_patterns(text)
            )
        ]
        self.assertEqual(failures, [], f'missed: {failures}')

    def test_negative_corpus(self):
        firings = [
            text for text in _NEGATIVES
            if any(
                f.pattern_name in _PATTERN_NAMES
                for f in find_pii_patterns(text)
            )
        ]
        self.assertEqual(firings, [], f'false-positive: {firings}')


if __name__ == '__main__':
    unittest.main()
