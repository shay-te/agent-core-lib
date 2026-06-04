"""Bulletproof corpus for the long-tail vehicle long tail patterns."""
from __future__ import annotations

import unittest

from agent_core_lib.pii.pii_patterns import find_pii_patterns


_PATTERN_NAMES = frozenset({
    'ca_license_plate',
    'eu_license_plate',
    'uk_license_plate',
})

_POSITIVES = (
    'UK plate AB12 CDE today',
    'EU plate ABC-1234-DE verified',
    'Canadian plate ABCD 1234 registered',
)
_NEGATIVES = (
    'random SKU AB12 here',
    'just narrative',
)


class TestVehicleLongTailBulletproof(unittest.TestCase):
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
