"""Bulletproof corpus for the keyword-anchored ``us_drivers_license`` pattern.

Replaces the previous shape-only ``\\b[A-Z]\\d{7}\\b|\\b\\d{8}\\b``
which collided with every 8-digit order id. The new pattern requires
a ``DL`` / ``drivers license`` / ``license #`` keyword nearby and
unions the per-state published formats — borrowed from scrubadub's
``DriversLicenceDetector`` table and cross-checked against the
state DMV publications.

Three corpora:
  * ``_POSITIVES`` — per-state shapes, all keyword-anchored.
  * ``_NEGATIVES`` — shapes that previously fired but should now
    miss (bare 8-digit ids, license-keyword without a real DL shape,
    keyword + wrong format).
  * ``_JSON_PAYLOADS`` — dict / list embeddings.
"""
from __future__ import annotations

import unittest

from agent_core_lib.pii.pii_patterns import find_pii_patterns
from agent_core_lib.pii.pii_scrub import find_pii_in_payload


_POSITIVES = (
    # CA: letter + 7 digits
    'DL B1234567 confirmed',
    "California driver's license B1234567 issued",
    # FL: letter + 7 digits
    'DL F2345678 verified',
    # TX: 8 digits
    'drivers license 12345678 on file',
    # NY: 9 digits
    'NY drivers license 123456789 valid',
    # OH: 2 letters + 6 digits
    'license # AB123456 on file',
    # PA / GA: 7-9 digits with keyword
    'license: 1234567 issued',
    'License# 123456789',
    # case variations
    'dl b1234567',
    'Drivers License 12345678 issued',
    # with colon
    'license #: B1234567',
    # inside parens
    '(DL B1234567)',
)


_NEGATIVES = (
    # bare 8-digit order id (previously fired)
    'id 12345678 active',
    'order 12345678 shipped',
    # ISBN-shaped 13 digits
    'isbn 1234567890123',
    # license keyword but wrong shape (too short / too long)
    'DL X',
    'DL 12',
    # narrative without any DL
    'we shipped 100 orders today',
    # SSN-shaped (XXX-XX-XXXX) is not a DL even with the keyword nearby
    'DL holder 123-45-6789 noted',
)


_JSON_PAYLOADS = (
    {'dl': 'DL B1234567 confirmed'},
    {'profile': {'license': 'drivers license 12345678 on file'}},
    [{'id': 1, 'doc': 'license # AB123456'}],
    {'log': 'subject DL B1234567 verified'},
)


class TestUsDriversLicenseBulletproofCorpus(unittest.TestCase):
    def test_us_drivers_license_positive_corpus(self):
        failures = [
            text for text in _POSITIVES
            if 'us_drivers_license' not in
            {f.pattern_name for f in find_pii_patterns(text)}
        ]
        self.assertEqual(failures, [], f'missed {len(failures)}: {failures}')

    def test_us_drivers_license_negative_corpus(self):
        failures = [
            text for text in _NEGATIVES
            if 'us_drivers_license' in
            {f.pattern_name for f in find_pii_patterns(text)}
        ]
        self.assertEqual(
            failures, [],
            f'false-positive on {len(failures)}: {failures}',
        )

    def test_us_drivers_license_in_json_payload(self):
        failures = [
            payload for payload in _JSON_PAYLOADS
            if 'us_drivers_license' not in
            {f.pattern_name for f in find_pii_in_payload(payload)}
        ]
        self.assertEqual(failures, [], f'missed in JSON: {failures}')


if __name__ == '__main__':
    unittest.main()
