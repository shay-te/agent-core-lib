"""Bulletproof corpus for the ``il_id`` PII pattern.

Israeli teudat zehut (national ID): 9 digits where the last position
is a Luhn-like check digit. The shape collides with US passport
numbers and bare 9-digit IDs, so the keyword anchor (``תז``,
``teudat zehut``, ``israeli id``) is what distinguishes it; the
check-digit validator (``_il_id_check_digit_valid`` in
``pii_patterns``) then filters out the impossible check digits.

Three corpora per workspace rule:
  * ``_POSITIVES`` — shape-and-check-digit valid + keyword-anchored.
  * ``_NEGATIVES`` — wrong shape / wrong check digit (validator rejects).
  * ``_JSON_PAYLOADS`` — embedded in dict / list payload shapes the
    chat tool result might carry.
"""
from __future__ import annotations

import unittest

from agent_core_lib.helpers.pii_patterns import find_pii_patterns
from agent_core_lib.helpers.pii_scrub import find_pii_in_payload


# Shape-and-check-digit valid teudat zehut numbers (check-digit math
# matches the issuer's algorithm). Each is keyword-anchored so it
# doesn't collide with the bare-9-digit class.
_POSITIVES = (
    'teudat zehut 123456782 on file',
    'israeli id 111111118 verified',
    'תז 123456782',
    # at end of line
    'reported: israeli id 016049371',
    # mixed case
    'Teudat Zehut 017283938 confirmed',
    # with colon separator
    'teudat zehut: 044444412',
    # inside parens
    'subject (israeli id 051851814) updated',
    # the dashed form some Israeli forms print
    '123-456-782',
)


# Shape-only (would match without the validator) but check-digit
# wrong — the validator must drop them.
_NEGATIVES = (
    # check digit off by one
    'teudat zehut 123456789',
    'israeli id 111111111',
    # all-9s (validator rejects)
    'teudat zehut 999999999',
    # too short for the legacy padded form
    'teudat zehut 12',
    # too long
    'teudat zehut 1234567890',
    # narrative without any teudat zehut
    'we shipped 100 orders today',
    # phone-shaped (10 digits)
    '+972 50 1234567',
)


_JSON_PAYLOADS = (
    {'teudat_zehut': 'teudat zehut 123456782'},
    {'profile': {'il_id': 'israeli id 111111118'}},
    [{'id': 1, 'tz': 'תז 016049371'}],
    {'log': 'subject teudat zehut 017283938 confirmed'},
    {'records': [{'tz': 'israeli id 044444412'}]},
)


class TestIlIdBulletproofCorpus(unittest.TestCase):
    def test_il_id_positive_corpus(self):
        failures = [
            text for text in _POSITIVES
            if 'il_id' not in {f.pattern_name for f in find_pii_patterns(text)}
        ]
        self.assertEqual(failures, [], f'missed {len(failures)}: {failures}')

    def test_il_id_negative_corpus(self):
        failures = [
            text for text in _NEGATIVES
            if 'il_id' in {f.pattern_name for f in find_pii_patterns(text)}
        ]
        self.assertEqual(
            failures, [],
            f'false-positive on {len(failures)}: {failures}',
        )

    def test_il_id_in_json_payload(self):
        failures = [
            payload for payload in _JSON_PAYLOADS
            if 'il_id' not in {f.pattern_name for f in find_pii_in_payload(payload)}
        ]
        self.assertEqual(failures, [], f'missed in JSON: {failures}')


if __name__ == '__main__':
    unittest.main()
