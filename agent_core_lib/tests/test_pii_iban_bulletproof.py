"""Bulletproof corpus for the ``iban`` PII pattern.

Test inputs borrowed from:

  * Presidio's ``test_iban_recognizer.py`` (country-specific samples).
  * SEPA published IBAN reference vectors.
  * scrubadub's IBAN tests.
"""
from __future__ import annotations

import unittest

from agent_core_lib.helpers.pii_patterns import find_pii_patterns
from agent_core_lib.helpers.pii_scrub import find_pii_in_payload


_POSITIVES = (
    # UK
    'GB82WEST12345698765432',
    'GB29NWBK60161331926819',
    # DE (Germany)
    'DE89370400440532013000',
    'DE91100000000123456789',
    # FR (France)
    'FR1420041010050500013M02606',
    # NL (Netherlands)
    'NL91ABNA0417164300',
    # ES (Spain)
    'ES7921000813610123456789',
    # IT (Italy)
    'IT60X0542811101000000123456',
    # CH (Switzerland)
    'CH9300762011623852957',
    # AT (Austria)
    'AT611904300234573201',
    # BE (Belgium)
    'BE68539007547034',
    # NO (Norway)
    'NO9386011117947',
    # SE (Sweden)
    'SE4550000000058398257466',
    # DK (Denmark)
    'DK5000400440116243',
    # FI (Finland)
    'FI2112345600000785',
    # IE (Ireland)
    'IE29AIBK93115212345678',
    # PT (Portugal)
    'PT50000201231234567890154',
    # GR (Greece)
    'GR1601101250000000012300695',
    # embedded
    'wire to IBAN GB82 WEST 1234 5698 7654 32 today',
    'transfer IBAN: DE89370400440532013000',
)


_NEGATIVES = (
    # too short
    'GB82WEST',
    # missing country prefix
    '82WEST12345698765432',
    # all digits no letters
    '12345678901234567890',
    # all letters no digits
    'ABCDEFGHIJKLMNOPQRSTUV',
    # 1-letter country
    'G82WEST12345698765432',
    # 3-letter country
    'GBR82WEST12345698765432',
    # wrong checksum-block (only 1 digit instead of 2)
    'GB8WEST12345698765432',
    # lowercase country letters (regex requires uppercase)
    'gb82west12345698765432',
    # narrative
    'we shipped 100 orders today',
)


_JSON_PAYLOADS = (
    {'iban': 'GB82WEST12345698765432'},
    {'bank': {'iban': 'DE89370400440532013000'}},
    [{'id': 1, 'iban': 'NL91ABNA0417164300'}],
    {'transfers': [{'iban': 'GB82WEST12345698765432'}]},
    {'log': 'wire via GB82WEST12345698765432 confirmed'},
    {'data': {'iban': 'FR1420041010050500013M02606'}},
    {'nested': {'deep': {'iban': 'CH9300762011623852957'}}},
    {'comment': 'invoice paid IBAN GB29NWBK60161331926819'},
    {'free_text': 'NL91ABNA0417164300 → confirmed'},
    {'tags': ['urgent', 'GB82WEST12345698765432']},
)


# ---- verbatim third-party corpora ---------------------------------------
# Presidio's IBAN recognizer ships ~100 country-specific test vectors;
# we mirror a representative cross-section (one per major country plus
# the printed-with-spaces variant) plus the "in a sentence" and "list
# of ibans" embedding shapes. The dash-separated form is a documented
# MISS — IBANs aren't typically published with dashes.

# Presidio: presidio-analyzer/tests/test_recognizers/test_iban_recognizer.py.
_IBAN_PRESIDIO_POSITIVES = (
    'DE89370400440532013000',
    'DE89 3704 0044 0532 0130 00',
    'NL91ABNA0417164300',
    'NL91 ABNA 0417 1643 00',
    'GB29NWBK60161331926819',
    'GB29 NWBK 6016 1331 9268 19',
    'FR1420041010050500013M02606',
    'FR14 2004 1010 0505 0001 3M02 606',
    'CH9300762011623852957',
    'CH93 0076 2011 6238 5295 7',
    'AL47212110090000000235698741',
    'AL47 2121 1009 0000 0002 3569 8741',
    'BE68539007547034',
    'IT60X0542811101000000123456',
    'IT60 X054 2811 1010 0000 0123 456',
    'ES9121000418450200051332',
    'ES91 2100 0418 4502 0005 1332',
    'PT50000201231234567890154',
    'IL620108000000099999999',
    'this is an iban VG96 VPVG 0000 0123 4567 8901 in a sentence',
    'list of ibans: AL47212110090000000235698741, AL47212110090000000235698741',
)
_IBAN_PRESIDIO_DASH_SEPARATOR_WE_MISS = (
    'Dash as iban separator: AL47-2121-1009-0000-0002-3569-8741',
)
# Inputs where the regex greedily extends into the following
# all-caps word (``X``, ``ALL CAPS``) and the resulting blob isn't
# mod-97-valid. The mod-97 validator correctly rejects the
# over-extended match — locked here so a future regex tightening
# (so the match stops at the IBAN boundary itself) flips them back
# into the regular positive corpus.
_IBAN_PRESIDIO_REGEX_OVEREXTENDS_VALIDATOR_REJECTS = (
    'this is an iban VG96 VPVG 0000 0123 4567 8901 X in a sentence',
    'AL47212110090000000235698741 ALL CAPS',
)


class TestIbanBulletproofCorpus(unittest.TestCase):
    def test_iban_positive_corpus(self):
        failures = [
            text for text in _POSITIVES
            if 'iban' not in {f.pattern_name for f in find_pii_patterns(text)}
        ]
        self.assertEqual(failures, [], f'missed {len(failures)}: {failures}')

    def test_iban_negative_corpus(self):
        failures = [
            text for text in _NEGATIVES
            if 'iban' in {f.pattern_name for f in find_pii_patterns(text)}
        ]
        self.assertEqual(failures, [], f'false-positive on {len(failures)}: {failures}')

    def test_iban_presidio_positive_corpus(self):
        failures = [
            text for text in _IBAN_PRESIDIO_POSITIVES
            if 'iban' not in {f.pattern_name for f in find_pii_patterns(text)}
        ]
        self.assertEqual(failures, [], f'Presidio missed: {failures}')

    def test_iban_regex_overextends_validator_rejects(self):
        # Locked behavior: when the regex eats a stray ``X`` or
        # ``ALL CAPS`` after the IBAN body, the resulting blob fails
        # mod-97 and the validator drops it. Documented here so a
        # future regex tightening that stops the greedy consumption
        # flips this back into a regular positive (and this lock
        # must be deleted at the same commit).
        firings = [
            text for text in _IBAN_PRESIDIO_REGEX_OVEREXTENDS_VALIDATOR_REJECTS
            if 'iban' in {f.pattern_name for f in find_pii_patterns(text)}
        ]
        self.assertEqual(
            firings, [],
            f'regex-overextended IBAN unexpectedly accepted by validator: '
            f'{firings}',
        )

    def test_iban_presidio_dash_separator_is_known_miss(self):
        firings = [
            text for text in _IBAN_PRESIDIO_DASH_SEPARATOR_WE_MISS
            if 'iban' in {f.pattern_name for f in find_pii_patterns(text)}
        ]
        self.assertEqual(
            firings, [],
            f'dash-separated IBAN now matching — was the regex relaxed? '
            f'{firings}. Verify it does not over-match generic dashed ids.',
        )

    def test_iban_in_json_payload(self):
        failures = [
            payload for payload in _JSON_PAYLOADS
            if 'iban' not in {f.pattern_name for f in find_pii_in_payload(payload)}
        ]
        self.assertEqual(failures, [], f'missed in JSON: {failures}')


if __name__ == '__main__':
    unittest.main()
