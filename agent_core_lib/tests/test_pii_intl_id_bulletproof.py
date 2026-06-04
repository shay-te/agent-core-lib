"""Bulletproof corpora for the second- and third-wave international-ID
patterns (UNA-2727).

This file is the dedicated home for the per-country / per-jurisdiction
PII patterns that landed in the "Expansion pass" and "Third wave" of
UNA-2727. Each pattern gets:

  * A POSITIVE corpus — multiple realistic forms (printed canonical,
    keyword-prefixed, with/without separators, with surrounding prose,
    with locale-specific keywords where applicable). Every entry must
    fire as the named pattern.
  * A NEGATIVE corpus — strings that *look* like the pattern but
    aren't, OR strings the pattern intentionally doesn't match
    (over-match protection). Every entry must NOT fire as the named
    pattern.

The structure follows the existing ``test_pii_*_bulletproof.py``
files — one TestCase per pattern, ``positive_*`` / ``negative_*``
methods. Patterns covered:

  Second wave: es_passport, de_passport, es_nif, sg_fin, pl_pesel,
               uk_nhs, au_medicare.
  Third wave:  in_gstin, it_fiscal_code, es_nie, se_personnummer,
               in_voter, fi_personal_identity_code, us_npi, au_abn,
               au_acn, sg_uen, th_tnin, tr_national_id.

The reviewer's brief: "what ever can go out of the unsupported. let's
put a dedicated test for it with many challenging test data. just
make sure we can take as much as possible from it!" — every Presidio
test corpus we could harvest (`presidio-analyzer/tests/
test_<recognizer>_recognizer.py`) is mined here, plus realistic
variations the prior-art note (in ``pii_patterns.py``) catalogued.
"""
from __future__ import annotations

import unittest

from agent_core_lib.pii.pii_patterns import find_pii_patterns


def _names(text: str) -> list[str]:
    return [finding.pattern_name for finding in find_pii_patterns(text)]


def _fires(text: str, pattern_name: str) -> bool:
    return pattern_name in _names(text)


# ---------------------------------------------------------------------------
# es_passport — 3 letters + 6 digits, case-insensitive
# ---------------------------------------------------------------------------

class TestEsPassportBulletproof(unittest.TestCase):
    POSITIVES = (
        'AAA123456',
        'XYZ987654',
        'Mi pasaporte es AAA123456',
        'aaa123456',
        'AaA123456',
        'Spanish passport BBC456789 issued 2020',
        'pasaporte número MNO234567 vigente',
        'see passport ZZZ000000 in scan',
    )
    NEGATIVES = (
        '',
        'AAAA12345',          # 4 letters
        'AA1234567',          # 2 letters
        'AAA12345',           # 5 digits
        'AAA1234567',         # 7 digits
        '12AAA3456',          # letters not at start
        # NOT a passport — bare numbers / dates / random text
        '20200101',
        'random text without ids',
    )

    def test_positives_all_fire(self):
        misses = [t for t in self.POSITIVES if not _fires(t, 'es_passport')]
        self.assertEqual(misses, [], f'es_passport missed: {misses}')

    def test_negatives_do_not_fire(self):
        firings = [t for t in self.NEGATIVES if _fires(t, 'es_passport')]
        self.assertEqual(firings, [], f'es_passport false-positive: {firings}')


# ---------------------------------------------------------------------------
# de_passport — restricted-prefix + 8 alphanumeric, case-insensitive.
# Same regex covers DE ID card (Personalausweis).
# ---------------------------------------------------------------------------

class TestDePassportBulletproof(unittest.TestCase):
    POSITIVES = (
        # canonical Presidio passport corpus
        'C01234565',
        'F12345671',
        'L01X00T44',
        'CZ6311T03',
        'G00000002',
        'C01X00T41',
        'Reisepass C01234565 ausgestellt am 01.01.2020.',
        'Pass-Nr.: F12345671',
        # DE ID card (Personalausweis) shares the format
        'l01x00t44',                            # lowercase
        'Personalausweis: L01X00T44.',
        'T22000129', 'T00000000', 'T99999999',
        't22000129',                            # lowercase
        'Ausweis Nr. T22000129 gültig bis 2025.',
    )
    NEGATIVES = (
        '',
        # Forbidden prefix letters (A/B/D/E/I/O/Q/S/U)
        'A01234565',
        'B12345671',
        'D00000002',
        'E12345671',
        'I00000002',
        'O01234565',
        'Q12345671',
        'S00000002',
        'U01234565',
        # Wrong length
        'C0123456',                             # 8 chars (1 short)
        'C012345678',                           # 10 chars (1 long)
        # Generic 9-char alphanumeric without the prefix
        '123456789',
        'random text',
    )

    def test_positives_all_fire(self):
        misses = [t for t in self.POSITIVES if not _fires(t, 'de_passport')]
        self.assertEqual(misses, [], f'de_passport missed: {misses}')

    def test_negatives_do_not_fire(self):
        firings = [t for t in self.NEGATIVES if _fires(t, 'de_passport')]
        self.assertEqual(firings, [], f'de_passport false-positive: {firings}')


# ---------------------------------------------------------------------------
# es_nif — 7-8 digits + optional dash + check letter
# ---------------------------------------------------------------------------

class TestEsNifBulletproof(unittest.TestCase):
    POSITIVES = (
        '55555555K',
        '55555555-K',
        '1111111-G',
        '1111111G',
        '01111111G',
        'NIF 55555555K verificado',
        'DNI: 12345678Z',
        'Mi NIF es 87654321Y',
        'fiscal code 11111111A',
    )
    NEGATIVES = (
        '',
        '12345K',          # 5 digits + letter (too short)
        '123456789K',      # 9 digits + letter (too long)
        '12345678',        # no check letter
        'ABCDEFGHK',       # all letters
        'random text',
    )

    def test_positives_all_fire(self):
        misses = [t for t in self.POSITIVES if not _fires(t, 'es_nif')]
        self.assertEqual(misses, [], f'es_nif missed: {misses}')

    def test_negatives_do_not_fire(self):
        firings = [t for t in self.NEGATIVES if _fires(t, 'es_nif')]
        self.assertEqual(firings, [], f'es_nif false-positive: {firings}')


# ---------------------------------------------------------------------------
# sg_fin / sg_nric — S/T/F/G/M prefix + 7 digits + check letter
# ---------------------------------------------------------------------------

class TestSgFinBulletproof(unittest.TestCase):
    POSITIVES = (
        'S2740116C',
        'T1234567Z',
        'F2346401L',
        'G1122144L',
        'M4332674T',
        'NRIC S2740116C was processed',
        'NRIC: T1234567Z',
        'Singapore IC F2346401L on file',
    )
    NEGATIVES = (
        '',
        # Wrong prefix letter
        'A2740116C',
        'B1234567Z',
        'Z2346401L',
        # Wrong length
        'S274011C',        # 6 digits (too short)
        'S27401160C',      # 8 digits (too long)
        'S2740116',        # missing check letter
        # Not a FIN
        '2740116C',        # no prefix letter
        'random text',
    )

    def test_positives_all_fire(self):
        misses = [t for t in self.POSITIVES if not _fires(t, 'sg_fin')]
        self.assertEqual(misses, [], f'sg_fin missed: {misses}')

    def test_negatives_do_not_fire(self):
        firings = [t for t in self.NEGATIVES if _fires(t, 'sg_fin')]
        self.assertEqual(firings, [], f'sg_fin false-positive: {firings}')


# ---------------------------------------------------------------------------
# pl_pesel — 11 digits, keyword-anchored on PESEL
# ---------------------------------------------------------------------------

class TestPlPeselBulletproof(unittest.TestCase):
    POSITIVES = (
        'PESEL: 44051401458',
        'PESEL 44051401458',
        'pesel 02070803628',
        'PESEL=11111111116',
        'mój PESEL: 44051401458 jest aktualny',
    )
    NEGATIVES = (
        '',
        # Bare 11 digits — intentionally not matched (would over-match)
        '44051401458',
        '02070803628',
        # Wrong digit count
        'PESEL 4405140145',           # 10 digits
        'PESEL 440514014580',         # 12 digits
        # Different keyword
        'order id 44051401458',
        'TIN 44051401458',
    )

    def test_positives_all_fire(self):
        misses = [t for t in self.POSITIVES if not _fires(t, 'pl_pesel')]
        self.assertEqual(misses, [], f'pl_pesel missed: {misses}')

    def test_negatives_do_not_fire(self):
        firings = [t for t in self.NEGATIVES if _fires(t, 'pl_pesel')]
        self.assertEqual(firings, [], f'pl_pesel false-positive: {firings}')


# ---------------------------------------------------------------------------
# uk_nhs — 3-3-4 grouped 10 digits, keyword-anchored on NHS
# ---------------------------------------------------------------------------

class TestUkNhsBulletproof(unittest.TestCase):
    POSITIVES = (
        'NHS 401-023-2137 on file',
        'NHS: 221 395 1837',
        'nhs#401-023-2137',
        'NHS number 401 023 2137 verified',
        'see NHS 4010232137 for details',
    )
    NEGATIVES = (
        '',
        # Bare 3-3-4 — same shape as US phone, intentionally not flagged
        '401-023-2137',
        '221 395 1837',
        # Wrong digit count
        'NHS 401-023-213',           # 9 digits
        'NHS 401-023-21370',         # 11 digits
        # Different keyword
        'call 401-023-2137 between 9-5',
        'order 4010232137 shipped',
    )

    def test_positives_all_fire(self):
        misses = [t for t in self.POSITIVES if not _fires(t, 'uk_nhs')]
        self.assertEqual(misses, [], f'uk_nhs missed: {misses}')

    def test_negatives_do_not_fire(self):
        firings = [t for t in self.NEGATIVES if _fires(t, 'uk_nhs')]
        self.assertEqual(firings, [], f'uk_nhs false-positive: {firings}')


# ---------------------------------------------------------------------------
# au_medicare — 4-5-1 space-grouped 10 digits
# ---------------------------------------------------------------------------

class TestAuMedicareBulletproof(unittest.TestCase):
    POSITIVES = (
        '2123 45670 1',
        'Medicare 2123 45670 1 confirmed',
        'see medicare 5123 45670 1 in record',
        'card 9999 99999 9',
    )
    NEGATIVES = (
        '',
        # Bare 10 digits — Presidio uses a checksum; we deliberately
        # don't flag the bare form to avoid over-matching phones.
        '2123456701',
        # Different groupings
        '21234 56701',                # 5-5
        '21 234 567 01',              # 2-3-3-2
        '2123 4567 01',               # 4-4-2
        '212 345 670 1',              # 3-3-3-1
        # Wrong total digit count
        '2123 45670',                 # 9 digits
        '2123 45670 12',              # 11 digits
    )

    def test_positives_all_fire(self):
        misses = [t for t in self.POSITIVES if not _fires(t, 'au_medicare')]
        self.assertEqual(misses, [], f'au_medicare missed: {misses}')

    def test_negatives_do_not_fire(self):
        firings = [t for t in self.NEGATIVES if _fires(t, 'au_medicare')]
        self.assertEqual(firings, [], f'au_medicare false-positive: {firings}')


# ---------------------------------------------------------------------------
# in_gstin — 15-char fully-deterministic GSTIN layout
# ---------------------------------------------------------------------------

class TestInGstinBulletproof(unittest.TestCase):
    POSITIVES = (
        '27ABCDE1234F1Z5',
        '07PQRST6789K1Z2',
        '01ABCDE1234F1Z5',
        '37ABCDE1234F1Z5',
        'My GSTIN number is 27ABCDE1234F1Z5 for business registration',
        'GST registration: 07PQRST6789K1Z2',
        'Tax identification GSTIN: 01ABCDE1234F1Z5',
        'GSTINs: 27ABCDE1234F1Z5 and 07PQRST6789K1Z2',
        'The company GSTIN is 27ABCDE1234F1Z5 for tax purposes',
    )
    NEGATIVES = (
        '',
        # Just the PAN-portion (first 10 chars)
        'ABCDE1234F',
        'PQRST6789K',
        # Wrong separators (GSTIN has no dashes/spaces inside)
        '27-ABCDE-1234-F1-Z5',
        '27 ABCDE 1234 F1 Z5',
        # Wrong total length
        '27ABCDE1234F1Z',                  # 14 chars
        '27ABCDE1234F1Z55',                # 16 chars (will fire as substring if not bounded)
        # Wrong position-by-position layout
        'ABCDE12345F1Z51',                 # letters first
    )

    def test_positives_all_fire(self):
        misses = [t for t in self.POSITIVES if not _fires(t, 'in_gstin')]
        self.assertEqual(misses, [], f'in_gstin missed: {misses}')

    def test_negatives_do_not_fire(self):
        firings = [t for t in self.NEGATIVES if _fires(t, 'in_gstin')]
        self.assertEqual(firings, [], f'in_gstin false-positive: {firings}')


# ---------------------------------------------------------------------------
# it_fiscal_code — 16-char fully-deterministic Codice Fiscale layout
# ---------------------------------------------------------------------------

class TestItFiscalCodeBulletproof(unittest.TestCase):
    POSITIVES = (
        'AAAAAA00B11C333Y',
        'AAAAAA00B11C333N',
        'AAAAAA00B11C333Y and AAAAAA00B11C333N',
        'Codice Fiscale: AAAAAA00B11C333Y',
        'CF MNCFRZ80A01H501Z',
    )
    NEGATIVES = (
        '',
        # Wrong length
        'AAAAAA00B11C333',             # 15 chars
        'AAAAAA00B11C333YY',           # 17 chars
        # Wrong position-by-position layout
        '00AAAAAA00B11C33',            # starts with digits
        'AAAAAA00B11C333',             # missing trailing check letter
    )

    def test_positives_all_fire(self):
        misses = [t for t in self.POSITIVES if not _fires(t, 'it_fiscal_code')]
        self.assertEqual(misses, [], f'it_fiscal_code missed: {misses}')

    def test_negatives_do_not_fire(self):
        firings = [t for t in self.NEGATIVES if _fires(t, 'it_fiscal_code')]
        self.assertEqual(firings, [], f'it_fiscal_code false-positive: {firings}')


# ---------------------------------------------------------------------------
# es_nie — X/Y/Z prefix + 7-8 digits + optional dash + check letter
# ---------------------------------------------------------------------------

class TestEsNieBulletproof(unittest.TestCase):
    POSITIVES = (
        'Z8078221M',
        'X9613851N',
        'Y8063915Z',
        'Y8063915-Z',
        'Mi NIE es X9613851N',
        'Z8078221M en mi NIE',
        'Mi Número de identificación de extranjero es Y8063915-Z',
    )
    NEGATIVES = (
        '',
        # Forbidden prefix letter (not X/Y/Z)
        'A8078221M',
        'B9613851N',
        'C8063915Z',
        # Wrong length
        'X961385N',                 # 6 digits
        'X961385123N',              # 9 digits
        'random text',
    )

    def test_positives_all_fire(self):
        misses = [t for t in self.POSITIVES if not _fires(t, 'es_nie')]
        self.assertEqual(misses, [], f'es_nie missed: {misses}')

    def test_negatives_do_not_fire(self):
        firings = [t for t in self.NEGATIVES if _fires(t, 'es_nie')]
        self.assertEqual(firings, [], f'es_nie false-positive: {firings}')


# ---------------------------------------------------------------------------
# se_personnummer — dashed 6-or-8 digits + 4 digits (covers
# organisationsnummer too — they share the dashed format)
# ---------------------------------------------------------------------------

class TestSePersonnummerBulletproof(unittest.TestCase):
    POSITIVES = (
        '871220-2384',                              # 6-4 short form
        '19910924-2397',                            # 8-4 long form
        '20110925-2385',                            # 8-4 newer
        '199109242397 är mitt pnr.',                # bare 12 — actually no dash so this should miss
        '19910924-2397 är mitt pnr.',
        # organisationsnummer (same format)
        '212000-0142',
        'Our company identity code is: 212000-0142. Thank you.',
        '556703-7485',
        '556703-7485 är vårt orgnummer.',
        '556703-7485 tillhör vårt företag.',
        # `+` separator (over-100-years-old marker)
        '231220+1234',
    )
    NEGATIVES = (
        '',
        # Bare-digit forms intentionally not matched (would over-match
        # any 10-12 digit number).
        '189004119807',
        '191005059801',
        '871220 2384',                              # space instead of dash
        # Wrong dash position / lengths
        '12345-1234',                               # 5-4
        '1234567-1234',                             # 7-4
        # Non-digit content
        'AB1234-5678',
    )

    def test_positives_all_fire(self):
        # The '199109242397 är mitt pnr.' input has no dash inside the
        # number — exclude it from the must-fire set (it would fail
        # the dashed-form constraint).
        positives_dashed = [
            text for text in self.POSITIVES
            if '-' in text or '+' in text
        ]
        misses = [t for t in positives_dashed if not _fires(t, 'se_personnummer')]
        self.assertEqual(misses, [], f'se_personnummer missed: {misses}')

    def test_undashed_forms_intentionally_not_matched(self):
        undashed = [
            text for text in self.POSITIVES
            if '-' not in text and '+' not in text
        ]
        for text in undashed:
            self.assertNotIn(
                'se_personnummer', _names(text),
                f'se_personnummer fired on bare form {text!r}; this '
                f'would over-match all 12-digit ids.',
            )

    def test_negatives_do_not_fire(self):
        firings = [t for t in self.NEGATIVES if _fires(t, 'se_personnummer')]
        self.assertEqual(firings, [], f'se_personnummer false-positive: {firings}')


# ---------------------------------------------------------------------------
# in_voter — 3 letters + 7 digits (Indian Voter ID / EPIC)
# ---------------------------------------------------------------------------

class TestInVoterBulletproof(unittest.TestCase):
    POSITIVES = (
        'KSD1287349',
        'this MUP5632811',
        'You can vote with your CPJ4467918 number',
        'EPIC ABC1234567 issued',
    )
    NEGATIVES = (
        '',
        # Wrong letter count
        'KS1287349',                    # 2 letters
        'KSDA1287349',                  # 4 letters
        # Wrong digit count
        'KSD128734',                    # 6 digits
        'KSD12873490',                  # 8 digits
        # Lowercase — voter IDs are uppercase
        # NOTE: the pattern doesn't carry IGNORECASE so 'my voter:
        # DBJ2289013' fires correctly; 'uzb2345117' (lowercase) is in
        # Presidio's corpus and intentionally not matched here because
        # voter IDs in India are uppercase by spec.
        'uzb2345117',
    )

    def test_positives_all_fire(self):
        misses = [t for t in self.POSITIVES if not _fires(t, 'in_voter')]
        self.assertEqual(misses, [], f'in_voter missed: {misses}')

    def test_negatives_do_not_fire(self):
        firings = [t for t in self.NEGATIVES if _fires(t, 'in_voter')]
        self.assertEqual(firings, [], f'in_voter false-positive: {firings}')


# ---------------------------------------------------------------------------
# fi_personal_identity_code — DDMMYY + separator + 3 digits + check char
# ---------------------------------------------------------------------------

class TestFiPersonalIdentityCodeBulletproof(unittest.TestCase):
    POSITIVES = (
        '010594Y9032',
        'My personal identity code is: 010594Y9032. Thank you.',
        '010594Y9021',
        '020594X903P',
        '020594X903P is my hetu.',
        '020594X902N',
        "Here's my henkilötunnus 020594X902N.",
        '030594W903B',
        'My finnish id code is 030594W903B.',
        '030694W9024', '040594V9030', '040594V902Y',
        '050594U903M', '050594U902L',
        '010516B903X', '010516B902W',
        '020516C903K', '020516C902J',
        '030516D9037', '030516D9026',
        '010501E9032', '020502E902X',
        '020503F9037', '020504A902E', '020504B904H',
    )
    NEGATIVES = (
        '',
        # Missing separator
        '010594Y9032X',                # 12 chars without sep
        # Wrong separator
        '010594Z9032',                 # Z is not in [-+A] — wait, Z IS not in the separator set, so this should fail. But the body is `\d{6}[-+A]\d{3}[A-Z0-9]` — `[-+A]` means dash, plus, or capital A. Z would not match.
        # Wrong field widths
        '01059Y9032',                  # 5 leading digits
        '010594Y903',                  # 3 trailing chars
    )

    def test_positives_all_fire(self):
        misses = [t for t in self.POSITIVES if not _fires(t, 'fi_personal_identity_code')]
        self.assertEqual(misses, [], f'fi_personal_identity_code missed: {misses}')

    def test_negatives_do_not_fire(self):
        firings = [t for t in self.NEGATIVES if _fires(t, 'fi_personal_identity_code')]
        self.assertEqual(firings, [], f'fi_personal_identity_code false-positive: {firings}')


# ---------------------------------------------------------------------------
# us_npi — 10 digits, keyword-anchored on NPI
# ---------------------------------------------------------------------------

class TestUsNpiBulletproof(unittest.TestCase):
    POSITIVES = (
        'NPI: 1234567893',
        'NPI 1234567893',
        'npi#1234567893',
        'NPI 1234567893 and NPI 1245319599',
        'see NPI: 1003000126 for billing',
    )
    NEGATIVES = (
        '',
        # Bare 10 digits — same shape as US phone; intentionally not
        # flagged.
        '1234567893',
        '1245319599',
        # Wrong digit count
        'NPI 123456789',
        'NPI 12345678934',
        # Different keyword
        'order 1234567893 shipped',
    )

    def test_positives_all_fire(self):
        misses = [t for t in self.POSITIVES if not _fires(t, 'us_npi')]
        self.assertEqual(misses, [], f'us_npi missed: {misses}')

    def test_negatives_do_not_fire(self):
        firings = [t for t in self.NEGATIVES if _fires(t, 'us_npi')]
        self.assertEqual(firings, [], f'us_npi false-positive: {firings}')


# ---------------------------------------------------------------------------
# au_abn — 11 digits, keyword-anchored on ABN
# ---------------------------------------------------------------------------

class TestAuAbnBulletproof(unittest.TestCase):
    POSITIVES = (
        'ABN: 51 824 753 556',
        'ABN 51824753556',
        'abn 51 824 753 556',
        'see ABN 51824753556 in register',
    )
    NEGATIVES = (
        '',
        # Bare 11-digit shape (collides with PESEL / DE Steuer-ID /
        # TR national ID — keyword anchor disambiguates).
        '51 824 753 556',
        '51824753556',
        # Wrong digit count
        'ABN 5182475355',
        'ABN 518247535560',
    )

    def test_positives_all_fire(self):
        misses = [t for t in self.POSITIVES if not _fires(t, 'au_abn')]
        self.assertEqual(misses, [], f'au_abn missed: {misses}')

    def test_negatives_do_not_fire(self):
        firings = [t for t in self.NEGATIVES if _fires(t, 'au_abn')]
        self.assertEqual(firings, [], f'au_abn false-positive: {firings}')


# ---------------------------------------------------------------------------
# au_acn — 9 digits, keyword-anchored on ACN
# ---------------------------------------------------------------------------

class TestAuAcnBulletproof(unittest.TestCase):
    POSITIVES = (
        'ACN 000 000 019',
        'ACN: 005 499 981',
        'ACN 006249976',
        'acn 000 000 019 registered',
    )
    NEGATIVES = (
        '',
        # Bare 9-digit shape — same shape as ca_sin (3-3-3 dashed),
        # us_routing_number, several passports.
        '000 000 019',
        '006249976',
        # Wrong digit count
        'ACN 00000001',
        'ACN 0000000190',
    )

    def test_positives_all_fire(self):
        misses = [t for t in self.POSITIVES if not _fires(t, 'au_acn')]
        self.assertEqual(misses, [], f'au_acn missed: {misses}')

    def test_negatives_do_not_fire(self):
        firings = [t for t in self.NEGATIVES if _fires(t, 'au_acn')]
        self.assertEqual(firings, [], f'au_acn false-positive: {firings}')


# ---------------------------------------------------------------------------
# sg_uen — 9-10 char alphanumeric, keyword-anchored on UEN
# ---------------------------------------------------------------------------

class TestSgUenBulletproof(unittest.TestCase):
    POSITIVES = (
        'UEN 53125226D',
        'UEN: 201434292D',
        'uen T16RF0037C',
        'UEN S57TU0392K',
        'UEN 53125226D was processed',
    )
    NEGATIVES = (
        '',
        # Bare — would collide with SG FIN / various national IDs
        '53125226D',
        '201434292D',
        'T16RF0037C',
        # Wrong length under keyword
        'UEN ABC123',                  # 6 chars
        'UEN 12345678901234',          # 14 chars
    )

    def test_positives_all_fire(self):
        misses = [t for t in self.POSITIVES if not _fires(t, 'sg_uen')]
        self.assertEqual(misses, [], f'sg_uen missed: {misses}')

    def test_negatives_do_not_fire(self):
        firings = [t for t in self.NEGATIVES if _fires(t, 'sg_uen')]
        self.assertEqual(firings, [], f'sg_uen false-positive: {firings}')


# ---------------------------------------------------------------------------
# th_tnin — 13 digits, keyword-anchored on TNIN / Thai National ID
# (English or Thai script)
# ---------------------------------------------------------------------------

class TestThTninBulletproof(unittest.TestCase):
    POSITIVES = (
        'TNIN: 2345678901234',
        'TNIN 1234567890121',
        'Thai National ID 1234567890121',
        'Thai national ID: 2345678901234',
        'เลขประจำตัวประชาชน: 3456789012347',
        'เลขบัตรประชาชน 2345678901234',
    )
    NEGATIVES = (
        '',
        # Bare 13 digits — too generic
        '1234567890121',
        '2345678901234',
        # Different keyword
        'order 1234567890121',
        'My Thai ID is 1234567890121',     # "Thai ID" not "Thai National ID"
    )

    def test_positives_all_fire(self):
        misses = [t for t in self.POSITIVES if not _fires(t, 'th_tnin')]
        self.assertEqual(misses, [], f'th_tnin missed: {misses}')

    def test_negatives_do_not_fire(self):
        firings = [t for t in self.NEGATIVES if _fires(t, 'th_tnin')]
        self.assertEqual(firings, [], f'th_tnin false-positive: {firings}')


# ---------------------------------------------------------------------------
# tr_national_id — 11 digits, keyword-anchored on TC / TC Kimlik
# ---------------------------------------------------------------------------

class TestTrNationalIdBulletproof(unittest.TestCase):
    POSITIVES = (
        'TC Kimlik No: 10000000146',
        'TC: 10000000146',
        'TC Kimlik 76543210794',
        'tc kimlik no: 36493665440',
    )
    NEGATIVES = (
        '',
        # Bare 11 digits — same shape as PESEL / DE Steuer-ID / AU ABN
        '10000000146',
        '76543210794',
        # Different keyword
        'Turkish ID 10000000146',         # No "TC" prefix
        'order 10000000146 shipped',
    )

    def test_positives_all_fire(self):
        misses = [t for t in self.POSITIVES if not _fires(t, 'tr_national_id')]
        self.assertEqual(misses, [], f'tr_national_id missed: {misses}')

    def test_negatives_do_not_fire(self):
        firings = [t for t in self.NEGATIVES if _fires(t, 'tr_national_id')]
        self.assertEqual(firings, [], f'tr_national_id false-positive: {firings}')


# ---------------------------------------------------------------------------
# Cross-pattern: ensure new patterns don't catastrophically collide
# with the existing set. This is the canary if a new regex turns out
# to be too broad in practice.
# ---------------------------------------------------------------------------

class TestCrossPatternCollisionCanary(unittest.TestCase):
    def test_clean_business_text_does_not_overmatch(self):
        # A realistic CRM tool-result snippet without any PII. None
        # of the new patterns should fire on this.
        clean_text = (
            'The customer requested a follow-up next quarter. '
            'Reference number is ORD-2024-15 and the order shipped on '
            'Monday. No concerns flagged during the review.'
        )
        new_pattern_names = {
            'es_passport', 'de_passport', 'es_nif', 'sg_fin',
            'pl_pesel', 'uk_nhs', 'au_medicare',
            'in_gstin', 'it_fiscal_code', 'es_nie', 'se_personnummer',
            'in_voter', 'fi_personal_identity_code',
            'us_npi', 'au_abn', 'au_acn', 'sg_uen', 'th_tnin',
            'tr_national_id',
        }
        fired = set(_names(clean_text)) & new_pattern_names
        self.assertEqual(
            fired, set(),
            f'New patterns over-matched clean text: {sorted(fired)}',
        )


if __name__ == '__main__':
    unittest.main()
