"""Bulletproof corpus for the long-tail social long tail patterns."""
from __future__ import annotations

import unittest

from agent_core_lib.pii.pii_patterns import find_pii_patterns


_PATTERN_NAMES = frozenset({
    'bluesky_handle',
    'signal_handle',
    'slack_user_id',
    'snapchat_handle',
    'whatsapp_number',
})

_POSITIVES = (
    'snapchat @jane_doe pinged',
    'reach https://wa.me/+12125551234 today',
    'signal +12125551234 active',
    'mention <@U01ABCDEFGH> in the thread',
    '@jane-doe.bsky.social posted',
)
_NEGATIVES = (
    'no handle in this text',
    'just narrative',
)


class TestSocialLongTailBulletproof(unittest.TestCase):
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
