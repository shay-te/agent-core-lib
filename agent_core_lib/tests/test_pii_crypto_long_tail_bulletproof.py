"""Bulletproof corpus for the long-tail crypto long tail patterns."""
from __future__ import annotations

import unittest

from agent_core_lib.pii.pii_patterns import find_pii_patterns


_PATTERN_NAMES = frozenset({
    'cardano_address',
    'cosmos_address',
    'polkadot_address',
    'ripple_address',
    'tron_address',
})

_POSITIVES = (
    'sent USDT to TLyqzVGLV1srkB7dToTAEqgDSfPtXRJZYH today',
    'cardano addr1qx2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzer3jcu5d8ps7zex2k2xt3uqxgjqnnj0vs2qd47s received',
    'dot 12xtAYsRUrmbniiWQqJtECiBQrMn8AypQcXhnQAc6RB6XkLW transferred',
    'send to cosmos1k0jntykt7e4g3y88ltc60czgjuqdy4c9ag7eas now',
    'XRP rEb8TK3gBgk5auZkwc6sHnwrGVJH8DuaLh confirmed',
)
_NEGATIVES = (
    'order ABC123 shipped today',
    'plain text with no wallet at all',
)


class TestCryptoLongTailBulletproof(unittest.TestCase):
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
