"""Bulletproof corpus for the ``ssn`` PII pattern.

Test inputs borrowed from:

  * Presidio's ``test_us_ssn_recognizer.py`` (positives + the
    Presidio-rejected area-numbers 000 / 666 / 9xx — documented as
    over-matches we'd close with a checksum follow-up).
  * scrubadub's ``test_social_security_number.py``.
  * SSA's published "ineligible" prefixes.
"""
from __future__ import annotations

import unittest

from agent_core_lib.pii.pii_patterns import find_pii_patterns
from agent_core_lib.pii.pii_scrub import find_pii_in_payload


_POSITIVES = (
    '123-45-6789',
    '111-22-3333',
    '001-01-0001',
    'SSN 123-45-6789 on file',
    'ssn: 123-45-6789',
    'SSN# 123-45-6789',
    'My SSN is 123-45-6789.',
    '(123-45-6789)',
    '123-45-6789;',
    'CC 4111 1111 1111 1111 SSN 123-45-6789',
    'employee 123-45-6789 filed taxes',
    # Mixed string: ``987-65-4321`` is rejected by the validator (ITIN
    # range), but ``123-45-6789`` still fires — one SSN match keeps the
    # string in the positive corpus.
    'forms processed: 123-45-6789, 987-65-4321',
    'social 123-45-6789 entered today',
    'SSN=123-45-6789',
    # at start
    '123-45-6789 was the reported number',
    # at end
    'reported number: 123-45-6789',
    # multiple in one line — same partial-validity reasoning as above
    '123-45-6789 and 987-65-4321 cross-referenced',
    # inside parens with context
    'tax id (123-45-6789) verified',
    # mixed-case context
    'Ssn 123-45-6789 noted',
)
# Bare ``987-65-4321`` (area in the 900-999 ITIN reservation range)
# previously fired as SSN; the validator now drops it. Locked here so
# a future relaxation of the validator is a visible test failure.
_VALIDATOR_REJECTS_ITIN_RANGE_BARE = (
    '987-65-4321',
)


_NEGATIVES = (
    # 9 digits no separators — looks like routing/passport
    '123456789',
    # wrong group sizes
    '12-345-6789',
    '1234-5-6789',
    '123-456-789',
    # spaces instead of dashes
    '123 45 6789',
    # too short
    '12-34-5678',
    # too long
    '1234-56-78901',
    # all letters
    'ABC-DE-FGHI',
    # phone-shape
    '(212) 555-1234',
    # date with same shape — only 2-digit middle
    '2024-03-15',
    # zip+4
    '90210-1234',
    # narrative without ssn-shape
    'the meeting is at 12:34 today',
    # ipv4 segments
    '192.168.1.1',
    # generic id with mixed punctuation
    'ORDER_123-45/6789',
)


# Presidio's recognizer REJECTS these via area-number rules; our
# pattern currently fires on them (documented as a follow-up for
# adding the Luhn-style validator chain). Lock the current behaviour
# so a future "add area-number exclusions" change updates this test
# alongside.
_DOCUMENTED_OVERMATCHES_OUR_REGEX_FIRES_PRESIDIO_REJECTS = (
    # area 000 (never issued)
    '000-12-3456',
    # area 666 (never issued)
    '666-12-3456',
    # area 900-999 (ITIN range, not SSN)
    '999-12-3456',
    # group 00
    '123-00-3456',
    # serial 0000
    '123-45-0000',
)


_JSON_PAYLOADS = (
    {'ssn': '123-45-6789'},
    {'employee': {'tax_id': '123-45-6789'}},
    [{'id': 1, 'ssn': '123-45-6789'}],
    {'note': 'SSN on file: 123-45-6789'},
    {'records': [{'ssn': '111-22-3333'}, {'ssn': '987-65-4321'}]},
    {'profile': {'identity': {'ssn': '123-45-6789'}}},
    {'free_text': 'reach hr; ssn 123-45-6789 is wrong'},
    {'audit_log': ['edited record ssn=123-45-6789 by admin']},
    {'tags': ['urgent', '123-45-6789', 'tax-2024']},
    {'comment': 'updated ssn (123-45-6789) at 09:00'},
)


# ---- verbatim third-party corpora ---------------------------------------
# SSN is the family where our regex differs most from the upstream
# references — Presidio matches dot- and space-separated SSNs and the
# all-digit 9-digit form; ours requires the canonical dashed form. The
# lists below lock the agreement / disagreement so a future relaxation
# is visible.

# Presidio: presidio-analyzer/tests/test_recognizers/test_us_ssn_recognizer.py.
_SSN_PRESIDIO_DASHED_FORM_WE_MATCH = (
    '078-05-1123',
)
# Presidio matches these alternative-separator forms; we don't — our
# regex pins to dash separators only, which is intentional (dot/space
# 3-2-4 numbers collide with phone fragments). Documented MISS.
_SSN_PRESIDIO_ALT_SEPARATORS_WE_MISS = (
    '078-051121 07805-1121',
    '078051121',
    '078.05.1123',
    '078 05 1123',
    'abc 078 05 1123 abc',
)
# Presidio rejects these (never-issued areas / group 00 / serial 0000);
# we ALSO reject them — but for the wrong reason (the bare 9-digit
# form doesn't match our dashed regex at all, so reservation isn't
# being enforced — the shape is). Lock the agreement.
_SSN_PRESIDIO_NEVER_ISSUED_WE_ALSO_REJECT = (
    '0780511201',
    '078051120',
    '000000000',
    '666000000',
    '078 00 1123',
    '693-09.4444',
)
# One Presidio negative we DO false-positive on: '078-05-0000'. The
# serial '0000' is reserved (SSA never issues it), but our regex is
# shape-only and fires. Locked as a documented over-match.
_SSN_PRESIDIO_NEGATIVE_WE_FIRE = (
    '078-05-0000',
)

# scrubadub: tests/test_detector_en_US_social_security_number.py.
_SSN_SCRUBADUB_DASHED_FORM_WE_MATCH = (
    'My social security number is 726-60-2033',
    'My social security number is 109-99-6000',
)
_SSN_SCRUBADUB_ALT_SEPARATORS_WE_MISS = (
    'My social security number is 109.99.6000',
    'My social security number is 109 99 6000',
)

# CommonRegex: test.py.
_SSN_COMMONREGEX_DASHED_FORM_WE_MATCH = (
    '523-04-1234',
)
_SSN_COMMONREGEX_SPACE_FORM_WE_MISS = (
    '523 23 4566',
)


class TestSsnBulletproofCorpus(unittest.TestCase):
    def test_ssn_positive_corpus(self):
        failures = [
            text for text in _POSITIVES
            if 'ssn' not in {f.pattern_name for f in find_pii_patterns(text)}
        ]
        self.assertEqual(failures, [], f'missed {len(failures)}: {failures}')

    def test_ssn_negative_corpus(self):
        failures = [
            text for text in _NEGATIVES
            if 'ssn' in {f.pattern_name for f in find_pii_patterns(text)}
        ]
        self.assertEqual(failures, [], f'false-positive on {len(failures)}: {failures}')

    def test_ssn_in_json_payload(self):
        failures = [
            payload for payload in _JSON_PAYLOADS
            if 'ssn' not in {f.pattern_name for f in find_pii_in_payload(payload)}
        ]
        self.assertEqual(failures, [], f'missed in JSON: {failures}')

    def test_ssn_presidio_dashed_form_matches(self):
        failures = [
            text for text in _SSN_PRESIDIO_DASHED_FORM_WE_MATCH
            if 'ssn' not in {f.pattern_name for f in find_pii_patterns(text)}
        ]
        self.assertEqual(failures, [], f'Presidio dashed positive missed: {failures}')

    def test_ssn_presidio_alt_separators_are_known_misses(self):
        # Lock the gap: dot- and space-separated SSNs slip through.
        # Closing this would mean accepting more phone-fragment false
        # positives, so the trade is documented rather than fixed.
        firings = [
            text for text in _SSN_PRESIDIO_ALT_SEPARATORS_WE_MISS
            if 'ssn' in {f.pattern_name for f in find_pii_patterns(text)}
        ]
        self.assertEqual(
            firings, [],
            f'alt-separator SSN now matching — {firings} — was the regex '
            f'relaxed? Phone false-positive risk increased; verify.',
        )

    def test_ssn_presidio_never_issued_we_also_reject(self):
        firings = [
            text for text in _SSN_PRESIDIO_NEVER_ISSUED_WE_ALSO_REJECT
            if 'ssn' in {f.pattern_name for f in find_pii_patterns(text)}
        ]
        self.assertEqual(firings, [], f'never-issued now matching: {firings}')

    def test_ssn_presidio_zero_serial_now_rejected(self):
        # Serial ``0000`` is reserved by the SSA. With the
        # area/group/serial validator landed in pii_patterns
        # (``_ssn_area_group_serial_valid``), these reserved-shape
        # strings no longer fire — the old over-match lock is flipped.
        firings = [
            text for text in _SSN_PRESIDIO_NEGATIVE_WE_FIRE
            if 'ssn' in {f.pattern_name for f in find_pii_patterns(text)}
        ]
        self.assertEqual(
            firings, [],
            f'ssn still fires on reserved-serial {firings} — the validator '
            f'regressed or the test corpus drifted.',
        )

    def test_ssn_scrubadub_dashed_form_matches(self):
        failures = [
            text for text in _SSN_SCRUBADUB_DASHED_FORM_WE_MATCH
            if 'ssn' not in {f.pattern_name for f in find_pii_patterns(text)}
        ]
        self.assertEqual(failures, [], f'scrubadub dashed positive missed: {failures}')

    def test_ssn_scrubadub_alt_separators_are_known_misses(self):
        firings = [
            text for text in _SSN_SCRUBADUB_ALT_SEPARATORS_WE_MISS
            if 'ssn' in {f.pattern_name for f in find_pii_patterns(text)}
        ]
        self.assertEqual(firings, [], f'alt-separator now matching: {firings}')

    def test_ssn_commonregex_dashed_matches(self):
        failures = [
            text for text in _SSN_COMMONREGEX_DASHED_FORM_WE_MATCH
            if 'ssn' not in {f.pattern_name for f in find_pii_patterns(text)}
        ]
        self.assertEqual(failures, [], f'CommonRegex dashed missed: {failures}')

    def test_ssn_commonregex_space_form_is_known_miss(self):
        firings = [
            text for text in _SSN_COMMONREGEX_SPACE_FORM_WE_MISS
            if 'ssn' in {f.pattern_name for f in find_pii_patterns(text)}
        ]
        self.assertEqual(firings, [], f'space-form now matching: {firings}')

    def test_bare_itin_range_ssn_no_longer_matches(self):
        # Bare 9xx-area SSN-shaped strings are now rejected by the
        # validator (area 900-999 = ITIN range, never a real SSN).
        firings = [
            text for text in _VALIDATOR_REJECTS_ITIN_RANGE_BARE
            if 'ssn' in {f.pattern_name for f in find_pii_patterns(text)}
        ]
        self.assertEqual(
            firings, [],
            f'bare ITIN-range SSN still firing: {firings}',
        )

    def test_reserved_area_group_serial_no_longer_match(self):
        # Previously a "documented over-match" canary. The
        # area/group/serial validator (``_ssn_area_group_serial_valid``
        # in pii_patterns) now rejects every reserved combination that
        # the SSA never issues — locked here so a future relaxation
        # of the validator is a visible test failure.
        firings = [
            text for text in
            _DOCUMENTED_OVERMATCHES_OUR_REGEX_FIRES_PRESIDIO_REJECTS
            if 'ssn' in {f.pattern_name for f in find_pii_patterns(text)}
        ]
        self.assertEqual(
            firings, [],
            f'reserved-area/group/serial still firing on {firings} — '
            f'the validator regressed or the test corpus drifted.',
        )


if __name__ == '__main__':
    unittest.main()
