"""Bulletproof corpus for the long-tail government ids long tail patterns."""
from __future__ import annotations

import unittest

from agent_core_lib.pii.pii_patterns import find_pii_patterns


_PATTERN_NAMES = frozenset({
    'bd_nid',
    'eg_national_id',
    'gh_ghana_card',
    'id_ktp',
    'ke_id',
    'ng_nin',
    'ph_tin',
    'pk_cnic',
    'sa_nin',
    'vn_national_id',
})

_POSITIVES = (
    'national ID 29001011234567 verified',
    'CNIC 12345-1234567-1 on file',
    'NID 1234567890 verified',
    'CCCD 012345678901 confirmed',
    'KTP 3201234567890123 issued',
    'TIN 123-456-789-000 on file',
    'NIN 1234567890 verified',
    'NIN 12345678901 confirmed',
    'Kenya ID 12345678 verified',
    'GHA-123456789-0 confirmed',
)
_NEGATIVES = (
    'random 12 digit string 123456789012 nothing',
    'just text',
)


class TestGovernmentIdsLongTailBulletproof(unittest.TestCase):
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
