"""Bulletproof corpus for the long-tail session tokens long tail patterns."""
from __future__ import annotations

import unittest

from agent_core_lib.pii.pii_patterns import find_pii_patterns


_PATTERN_NAMES = frozenset({
    'csrf_token',
    'jsession_id',
    'oauth_bearer',
    'php_session_id',
})

_POSITIVES = (
    'Authorization: Bearer abc123def456ghi789 ok',
    'cookie PHPSESSID=abcdef1234567890abcdef set',
    'Cookie: JSESSIONID=ABCDEF1234567890 received',
    'X-CSRF-TOKEN: abc123def456ghi789jkl0mno verified',
)
_NEGATIVES = (
    'no session token here',
    'plain text',
)


class TestSessionTokensLongTailBulletproof(unittest.TestCase):
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
