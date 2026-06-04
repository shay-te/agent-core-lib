"""Bulletproof corpus for the long-tail postal long tail patterns."""
from __future__ import annotations

import unittest

from agent_core_lib.pii.pii_patterns import find_pii_patterns


_PATTERN_NAMES = frozenset({
    'hk_postcode',
    'kr_postcode',
    'nz_postcode',
    'ru_postcode',
    'sg_postcode',
    'th_postcode',
    'tw_postcode',
    'za_postcode',
})

_POSITIVES = (
    'postcode 0001 Pretoria',
    'NZ postcode 6011 Wellington',
    'индекс 101000 Moscow',
    '우편번호 04524 Seoul',
    'postcode 10200 Bangkok',
    'TW-100 Taipei',
    'HK postcode 999077 international',
    'Singapore postcode 018989 confirmed',
)
_NEGATIVES = (
    'order 1234 shipped',
    'narrative without postcode',
)


class TestPostalLongTailBulletproof(unittest.TestCase):
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
