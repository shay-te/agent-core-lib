"""Bulletproof corpus for the ``phone`` PII pattern.

Test inputs borrowed from:

  * Presidio's ``test_phone_recognizer.py`` (which wraps Google's
    ``phonenumbers`` library; we mine its positive test set for our
    looser regex).
  * scrubadub's phone tests.
  * ITU-T E.164 examples + national formats from libphonenumber.

The ``phone`` regex is intentionally loose (matches many shapes
including order-id-shaped digit runs); the bulletproof test exists to
lock the positives and document the false-positive boundary.
"""
from __future__ import annotations

import unittest

from agent_core_lib.helpers.pii_patterns import find_pii_patterns
from agent_core_lib.helpers.pii_scrub import find_pii_in_payload


_POSITIVES = (
    # E.164 international
    '+1 212 555 1234',
    '+1-212-555-1234',
    '+1.212.555.1234',
    '+44 7700 900123',
    '+44 20 7946 0958',
    '+49 30 12345678',
    '+33 1 23 45 67 89',
    '+91 98765 43210',
    '+81 3-1234-5678',
    '+972 2 123 4567',
    # US national
    '(212) 555-1234',
    '212-555-1234',
    '212.555.1234',
    '212 555 1234',
    '2125551234',
    # UK national
    '0207 946 0958',
    '07700 900 123',
    # Toll-free
    '1-800-555-1234',
    # extension
    '+1 212 555 1234 ext. 99',
    # narrative
    'call me at +1 212 555 1234 tomorrow',
    'phone: (212) 555-1234',
)


_NEGATIVES = (
    # too short
    '123 45',
    '+1 1',
    # alphabetic ID
    'abc-def-ghij',
    # bare year
    '2024',
    # bare currency
    '$1,234.56',
    # bare time
    '12:34',
    # narrative without digit run
    'call me later please',
    # IPv4 (dots between short numbers)
    '10.0.0.1',
    # 4-digit pin
    'PIN 4321',
    # ratio
    '7:3',
)


_JSON_PAYLOADS = (
    {'phone': '+1 212 555 1234'},
    {'contact': {'mobile': '+1-212-555-1234'}},
    [{'id': 1, 'phone': '(212) 555-1234'}],
    {'log': 'callback on 212-555-1234'},
    {'profile': {'contact': {'phones': ['+1 212 555 1234']}}},
    {'comment': 'reached at +44 7700 900123 today'},
    {'tags': ['urgent', '+1 212 555 1234']},
    {'free_text': 'leave message at 212-555-1234'},
    {'nested': {'list': [{'phone': '+91 98765 43210'}]}},
    {'data': {'raw': '+33 1 23 45 67 89'}},
)


# ---- verbatim third-party corpora ---------------------------------------
# Phone is the family with the highest cross-library agreement — every
# tested literal from Presidio / scrubadub / CommonRegex matches our
# loose phone regex. The cost of that breadth is documented false
# positives (long order ids, hyphenated dates) that the Recommendation
# block in pii_patterns.py tracks closing via the ``phonenumbers``
# library as a follow-up.

# Presidio: presidio-analyzer/tests/test_recognizers/test_phone_recognizer.py.
_PHONE_PRESIDIO_POSITIVES = (
    'My US number is (415) 555-0132, and my international one is +1 415 555 0132',
    'My Israeli number is 09-7625400',
    '_: (415)555-0132',
    'United States: (415)555-0132',
    'US: 415-555-0132',
    '_: +55 11 98456 5666',
    'Brazil: +55 11 98456 5666',
    'BR: +55 11 98456 5666',
    'My Japanese number is 090-1234-5678',
    'My CN number is 13812345678',
    'My US number is (415) 555-0132, and my international one is415-555-0132',
    'My US number is (415) 555-0132, and my international one is 91-415-555-0132',
    'My US number is (415) 555-0132, and my international one is +91 4155 550132',
    'My US number is (415) 555-0132, and my international one is +91 4155550132',
    'My US number is (415) 555-0132, and my international one is +44 (20) 7123 4567',
    'My US number is (415) 555-0132, and my international one is +55 11 98456 5666',
    'My US number is (415) 555-0132, and my international one is +49 30 1234567',
    'My US number is (415) 555-0132, and my international one is +39 06 678 4343',
    'My US number is (415) 555-0132, and my international one is +30 21 0 1234567',
    'My US number is (415) 555-0132, and my international one is +33 1 42 68 53 00',
)

# scrubadub: tests/test_detector_phone_numbers.py.
_PHONE_SCRUBADUB_POSITIVES = (
    '1-312-515-2239',
    '+1-312-515-2239',
    '1 (312) 515-2239',
    '312-515-2239',
    '(312) 515-2239',
    '(312)515-2239',
    '312-515-2239 x12',
    '312-515-2239 ext. 12',
    '312-515-2239 ext.12',
    '+47 21 30 85 99',
    '+45 69 19 88 56',
    '+46 852 503 499',
    '+31 619 837 236',
    '+86 135 3727 4136',
    '+61267881324',
    'Call me on my cell 312.714.8142 or in my office 773.415.7432',
)

# CommonRegex: test.py.
_PHONE_COMMONREGEX_POSITIVES = (
    '12345678900',
    '1234567890',
    '+1 234 567 8900',
    '234-567-8900',
    '1-234-567-8900',
    '1.234.567.8900',
    '(123) 456 7890',
    '+41 22 730 5989',
    '(+41) 22 730 5989',
    '+442345678900',
    # phones-with-extensions sub-corpus
    '(523)222-8888 ext 527',
    '(523)222-8888x623',
    '(523)222-8888 x623',
    '(523)222-8888 x 623',
    '(523)222-8888EXT623',
    '523-222-8888EXT623',
    '(523) 222-8888 x 623',
)


class TestPhoneBulletproofCorpus(unittest.TestCase):
    def test_phone_positive_corpus(self):
        failures = [
            text for text in _POSITIVES
            if 'phone' not in {f.pattern_name for f in find_pii_patterns(text)}
        ]
        self.assertEqual(failures, [], f'missed {len(failures)}: {failures}')

    def test_phone_negative_corpus(self):
        failures = [
            text for text in _NEGATIVES
            if 'phone' in {f.pattern_name for f in find_pii_patterns(text)}
        ]
        self.assertEqual(failures, [], f'false-positive on {len(failures)}: {failures}')

    def test_phone_presidio_positive_corpus(self):
        failures = [
            text for text in _PHONE_PRESIDIO_POSITIVES
            if 'phone' not in {f.pattern_name for f in find_pii_patterns(text)}
        ]
        self.assertEqual(failures, [], f'Presidio missed: {failures}')

    def test_phone_scrubadub_positive_corpus(self):
        failures = [
            text for text in _PHONE_SCRUBADUB_POSITIVES
            if 'phone' not in {f.pattern_name for f in find_pii_patterns(text)}
        ]
        self.assertEqual(failures, [], f'scrubadub missed: {failures}')

    def test_phone_commonregex_positive_corpus(self):
        failures = [
            text for text in _PHONE_COMMONREGEX_POSITIVES
            if 'phone' not in {f.pattern_name for f in find_pii_patterns(text)}
        ]
        self.assertEqual(failures, [], f'CommonRegex missed: {failures}')

    def test_phone_in_json_payload(self):
        failures = [
            payload for payload in _JSON_PAYLOADS
            if 'phone' not in {f.pattern_name for f in find_pii_in_payload(payload)}
        ]
        self.assertEqual(failures, [], f'missed in JSON: {failures}')


if __name__ == '__main__':
    unittest.main()
