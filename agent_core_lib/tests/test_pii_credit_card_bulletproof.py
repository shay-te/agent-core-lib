"""Bulletproof corpus for the ``credit_card`` PII pattern.

Test inputs borrowed from:

  * Presidio's ``test_credit_card_recognizer.py``: PAN samples for
    Visa-16, Visa-13, Mastercard, Amex-15, Discover, JCB, Diners.
  * scrubadub's ``test_credit_card.py``.
  * The standard PCI-DSS test PAN list (4111-, 5500-, 3400- etc.).
  * Stripe's documented test card numbers.

Three corpora per workspace rule (one TestCase per file).
"""
from __future__ import annotations

import unittest

from agent_core_lib.helpers.pii_patterns import find_pii_patterns
from agent_core_lib.helpers.pii_scrub import find_pii_in_payload


_POSITIVES = (
    # Visa 16-digit, various separators (PCI test PANs)
    '4111111111111111',
    '4111 1111 1111 1111',
    '4111-1111-1111-1111',
    # Mastercard
    '5500000000000004',
    '5500 0000 0000 0004',
    '5555 5555 5555 4444',  # Stripe test
    # Amex 15-digit (Presidio borrowed)
    '378282246310005',
    '3782 822463 10005',
    '3400 0000 0000 009',
    # Discover
    '6011000000000004',
    '6011 0000 0000 0004',
    # JCB
    '3528000000000007',
    # Diners 14
    '30000000000004',
    '3000 000000 0004',
    # Visa 13 (legacy)
    '4222222222222',
    # mixed-separator (space + dash)
    '4111-1111 1111 1111',
    # embedded in text
    'card 4111 1111 1111 1111 expires 12/26',
    'pay with 5500000000000004 today',
    'PAN: 378282246310005 issued',
    # leading + trailing punctuation
    '(4111 1111 1111 1111)',
    'cards: 4111-1111-1111-1111;',
    # next to other PII
    '4111111111111111 expires 12/26 ssn 123-45-6789',
    # 19-digit (Maestro)
    '6759649826438453123',
)


_NEGATIVES = (
    # too short (12 digits)
    '123456789012',
    # too long (20 digits)
    '12345678901234567890',
    # all-letters
    'CARD-ABCDABCDABCDABCD',
    # contains letters
    '4111-1111-1111-XXXX',
    # only 1-2 groups, not enough digits
    '4111',
    '4111 1111',
    # phone-like 10 digits
    '212-555-1234',
    # words around digits
    'thirteen fourteen fifteen',
    # plain narrative
    'we processed 100 orders today',
    # ISO date with dashes — too few digits
    '2024-03-15',
    # version string
    'v1.2.3-rc.4',
)


# ---- verbatim third-party corpora ---------------------------------------
# Each list below is copied directly from the upstream library's test
# file. The Presidio NEGATIVES are the most interesting — they're
# Luhn-INVALID card numbers that Presidio rejects via checksum and we
# (currently) accept. They are locked as documented over-matches so the
# day we add a Luhn validator (tracked in pii_patterns.py's
# "Recommendation" block, item 1) the asserts flip.

# Presidio: presidio-analyzer/tests/test_recognizers/test_credit_card_recognizer.py
_CC_PRESIDIO_POSITIVES = (
    '4012888888881881 4012-8888-8888-1881 4012 8888 8888 1881',
    '122000000000003',
    'my credit card: 122000000000003',
    '371449635398431',
    '5555555555554444',
    '5019717010103742',
    '30569309025904',
    '6011000400000000',
    '3528000700000000',
    '6759649826438453',
    '4111111111111111',
    '4917300800000000',
    '4484070000000000',
)
# Presidio rejects these via Luhn — they are shape-valid but checksum-
# invalid PAN candidates. Our shape-only regex fires; locked as the
# baseline so a future Luhn validator flips them.
_CC_PRESIDIO_LUHN_REJECTS_WE_FIRE = (
    '1748503543012',
    '4012-8888-8888-1882',
    'my credit card number is 4012-8888-8888-1882',
    '36168002586008',
    'my credit card number is 36168002586008',
)

# scrubadub: tests/test_detector_credit_card.py.
_CC_SCRUBADUB_POSITIVES = (
    'My credit card is 378282246310005.',
    'My credit card is 371449635398431.',
    'My credit card is 378734493671000.',
    'My credit card is 30569309025904.',
    'My credit card is 38520000023237.',
    'My credit card is 6011111111111117.',
    'My credit card is 6011000990139424.',
    'My credit card is 3530111333300000.',
    'My credit card is 3566002020360505.',
    'My credit card is 5555555555554444.',
    'My credit card is 5105105105105100.',
    'My credit card is 4111111111111111.',
    'My credit card is 4012888888881881.',
)

# CommonRegex: test.py (madisonmay/CommonRegex).
_CC_COMMONREGEX_POSITIVES = (
    '0000-0000-0000-0000',
    '0123456789012345',
    '0000 0000 0000 0000',
    '012345678901234',
)


_JSON_PAYLOADS = (
    {'card_number': '4111 1111 1111 1111'},
    {'payment': {'pan': '5500000000000004'}},
    [{'order_id': 1, 'card': '4111111111111111'}],
    {'logs': ['attempt with 4111 1111 1111 1111 declined']},
    {'nested': {'list': [{'card': '378282246310005'}]}},
    {'comment': 'customer card 4111-1111-1111-1111 on file'},
    {'transactions': [{'card': '4111111111111111'}, {'card': '5500000000000004'}]},
    {'description': 'paid 4111 1111 1111 1111 + tip'},
    {'data': {'raw': '4111111111111111'}},
    {'free_text': 'I see card 4111 1111 1111 1111 here'},
)


class TestCreditCardBulletproofCorpus(unittest.TestCase):
    def test_credit_card_positive_corpus(self):
        failures = []
        for text in _POSITIVES:
            found = [f.pattern_name for f in find_pii_patterns(text)]
            if 'credit_card' not in found:
                failures.append(text)
        self.assertEqual(failures, [], f'missed {len(failures)}: {failures}')

    def test_credit_card_negative_corpus(self):
        failures = []
        for text in _NEGATIVES:
            found = [f.pattern_name for f in find_pii_patterns(text)]
            if 'credit_card' in found:
                failures.append(text)
        self.assertEqual(
            failures, [],
            f'false-positive on {len(failures)}: {failures}',
        )

    def test_credit_card_presidio_positive_corpus(self):
        failures = []
        for text in _CC_PRESIDIO_POSITIVES:
            if 'credit_card' not in [f.pattern_name for f in find_pii_patterns(text)]:
                failures.append(text)
        self.assertEqual(failures, [], f'Presidio missed: {failures}')

    def test_credit_card_presidio_luhn_rejects_are_documented_overmatches(self):
        # Presidio rejects these via Luhn checksum. We currently fire on
        # all of them (shape-only regex, no checksum). Lock the
        # over-match so a future Luhn validator is a visible change.
        failures = []
        for text in _CC_PRESIDIO_LUHN_REJECTS_WE_FIRE:
            if 'credit_card' not in [f.pattern_name for f in find_pii_patterns(text)]:
                failures.append(text)
        self.assertEqual(
            failures, [],
            f'documented Luhn over-match no longer fires for {failures} '
            f'— if a Luhn validator was added, update the lock and the '
            f'Recommendation table in pii_patterns.py.',
        )

    def test_credit_card_scrubadub_positive_corpus(self):
        failures = []
        for text in _CC_SCRUBADUB_POSITIVES:
            if 'credit_card' not in [f.pattern_name for f in find_pii_patterns(text)]:
                failures.append(text)
        self.assertEqual(failures, [], f'scrubadub missed: {failures}')

    def test_credit_card_commonregex_positive_corpus(self):
        failures = []
        for text in _CC_COMMONREGEX_POSITIVES:
            if 'credit_card' not in [f.pattern_name for f in find_pii_patterns(text)]:
                failures.append(text)
        self.assertEqual(failures, [], f'CommonRegex missed: {failures}')

    def test_credit_card_in_json_payload(self):
        failures = []
        for payload in _JSON_PAYLOADS:
            found = [f.pattern_name for f in find_pii_in_payload(payload)]
            if 'credit_card' not in found:
                failures.append(payload)
        self.assertEqual(
            failures, [],
            f'missed in {len(failures)} JSON payload(s): {failures}',
        )


if __name__ == '__main__':
    unittest.main()
