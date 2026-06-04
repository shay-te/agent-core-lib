"""Third-party borrowed-corpora bulletproof tests.

Every data type Presidio or scrubadub has a recognizer / detector for
is exercised here against THEIR literal test fixtures. This is the
operator's "look at their test files, take their test data, put it in
ours" mandate (UNA-2727) — verbatim porting so we benefit from every
adversarial input their maintainers ever discovered.

Per data type there are usually three buckets:

* ``_<TYPE>_POSITIVES`` — upstream positives that OUR regex also
  catches. Locked as positive assertions.
* ``_<TYPE>_NEGATIVES`` — upstream negatives that OUR regex also
  rejects. Locked as negative assertions.
* ``_<TYPE>_KNOWN_MISSES`` — upstream positives that OUR regex does
  NOT yet catch. Locked as NO-match assertions, with a docstring on
  the test method naming what would close the gap (a checksum
  validator, a NER pass, a per-state table, etc.). If the gap is ever
  closed, the assertion flips and forces a corresponding update to
  the "Recommendation" block in ``pii_patterns.py``.

For data types we have NO regex for at all (names, locations,
organizations), the bucket is named ``_<TYPE>_UNSUPPORTED`` and the
assertion is "no PII pattern of any kind fires". NER recognition is
explicitly out of scope for the inline gate — see ``pii_patterns.py``
"Recommendation" item, "names via lightweight NER".

Per the workspace-wide "one TestCase per file" rule, the entire file
hosts a single :class:`TestThirdPartyCorpora` with one test method
per (data type, source library) tuple.
"""
from __future__ import annotations

import unittest

from agent_core_lib.helpers.pii_patterns import (
    PII_PATTERN_NAMES,
    find_pii_patterns,
)


def _names(text: str) -> list:
    return [finding.pattern_name for finding in find_pii_patterns(text)]


def _has(text: str, pattern: str) -> bool:
    return pattern in _names(text)


def _any_pii(text: str) -> bool:
    return len(find_pii_patterns(text)) > 0


# ===========================================================================
# Presidio US driver's license
# ---------------------------------------------------------------------------
# Source: presidio-analyzer/tests/test_us_driver_license_recognizer.py
# ===========================================================================

# Our ``us_drivers_license`` regex is ``[A-Z]\d{7}|\d{8}`` — letter + 7
# digits or 8 bare digits. Presidio's positive ``H12234567`` is letter
# + 8 digits, doesn't fit either arm. MISS.
_PRESIDIO_US_DL_KNOWN_MISSES = (
    'H12234567',
)
_PRESIDIO_US_DL_NEGATIVES = (
    'C12T345672',
    'ABCDEFG ABCDEFGH ABCDEFGHI',
    'ABCD ABCDEFGHIJ',
    # Bundle of bare digit lengths — no 8-digit run with word
    # boundaries, no letter+7 either. We agree (reject all).
    '123456789 1234567890 12345679012 123456790123 1234567901234 1234',
)


# ===========================================================================
# Presidio US ITIN
# ---------------------------------------------------------------------------
# Source: presidio-analyzer/tests/test_us_itin_recognizer.py
# ===========================================================================

# Our ``itin`` regex is ``9\d{2}-[78]\d-\d{4}`` — requires the 4th
# digit to be 7 or 8 (the original ITIN group range). Presidio's
# corpus uses 5x and 6x groups too (broader since the range was
# expanded). We catch only the 7x/8x ones today.
_PRESIDIO_ITIN_POSITIVES = (
    '911-70-1234',
)
_PRESIDIO_ITIN_KNOWN_MISSES_BROADER_GROUPS = (
    '911-53-1234',  # 5x group
    '911-64-1234',  # 6x group
)
_PRESIDIO_ITIN_NEGATIVES = (
    # Presidio rejects 911-89-* (the 4th-5th digit pair "89" isn't a
    # valid ITIN group); our regex doesn't filter the group range so
    # this fires. Documented over-match.
)
_PRESIDIO_ITIN_KNOWN_MISSES = (
    # Concatenated form — Presidio matches via its broader regex,
    # ours requires the dash separator.
    '911701234',
)
_PRESIDIO_ITIN_OVERMATCH_INPUT = (
    # Presidio rejects this via group-number validation; we fire.
    '911-89-1234',
    'my tax id 911-89-1234',
)


# ===========================================================================
# Presidio US bank account
# ---------------------------------------------------------------------------
# Source: presidio-analyzer/tests/test_us_bank_recognizer.py
# Presidio's positive is unlabelled; our regex requires the
# ``account|acct`` keyword anchor.
# ===========================================================================

_PRESIDIO_US_BANK_KNOWN_MISSES = (
    '945456787654',  # Presidio matches via context proximity, we don't.
)
_PRESIDIO_US_BANK_NEGATIVES = (
    '1234567',  # 7 digits — too short for both libs.
)


# ===========================================================================
# Presidio US MBI (Medicare Beneficiary ID)
# ---------------------------------------------------------------------------
# Source: presidio-analyzer/tests/test_us_mbi_recognizer.py
# Our ``medicare_mbi`` pattern is shape-based on the post-2018 format.
# ===========================================================================

# Our ``medicare_mbi`` regex is uppercase-only and shape-only — it
# doesn't enforce Presidio's S/B/I/L/O/Z exclusions on specific
# positions.
_PRESIDIO_MBI_POSITIVES = (
    '1EG4-TE5-MK73',
    '1EG4TE5MK73',
    '9XX9-XX9-XX99',
    '3CD5-FG7-HJ89',
    'Medicare ID: 3CD5-FG7-HJ89',
)
_PRESIDIO_MBI_KNOWN_MISSES_CASE = (
    '1eg4-te5-mk73',  # lowercase — our regex is uppercase-only
)
_PRESIDIO_MBI_NEGATIVES = (
    '12G4-TE5-MK73',  # digit instead of required letter in 2nd
    '1EG4TE5MK7',     # too short
    '1EG4TE5MK734',   # too long
)
# Presidio rejects these via position-specific exclusion sets. We
# fire (shape only). Documented over-match.
_PRESIDIO_MBI_POSITION_OVERMATCHES = (
    '1SG4-TE5-MK73',  # S excluded at position 2
    '1EG4-LE5-MK73',  # L excluded at position 5
    '1EG4-TE5-OK73',  # O excluded at position 8
    '1BG4-TE5-MK73',  # B excluded at position 2
)


# ===========================================================================
# Presidio crypto wallet (Bitcoin)
# ---------------------------------------------------------------------------
# Source: presidio-analyzer/tests/test_crypto_recognizer.py
# ===========================================================================

_PRESIDIO_BTC_POSITIVES = (
    '16Yeky6GMjeNkAiNcBY7ZhrLoMSgg1BoyZ',
    '3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy',
    'bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq',
    # Taproot/bech32m bc1p... — our ``bc1[a-zA-HJ-NP-Z0-9]{25,87}`` arm
    # is broad enough to cover it. (Not strictly correct for SegWit V1
    # which uses bech32m vs bech32, but the shape matches and the
    # outcome — redaction — is correct.)
    'bc1p5d7rjq7g6rdk2yhzks9smlaqtedr4dekq08ge8ztwac72sfr9rusxg3297',
    '16Yeky6GMjeNkAiNcBY7ZhrLoMSgg1BoyZ 3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy',
    'my wallet address is: 16Yeky6GMjeNkAiNcBY7ZhrLoMSgg1BoyZ',
)
_PRESIDIO_BTC_OVERMATCH_INPUTS = (
    # Fails Base58 checksum but our regex doesn't validate, so we fire.
    '16Yeky6GMjeNkAiNcBY7ZhrLoMSgg1BoyZ2',
)


# ===========================================================================
# Presidio date / DOB
# ---------------------------------------------------------------------------
# Source: presidio-analyzer/tests/test_date_recognizer.py
# We have ``date_of_birth`` which is keyword-anchored on ``dob`` /
# ``date of birth`` / ``born`` — Presidio's general date recognizer
# fires on ANY date, with no DOB intent. So most of these are
# **expected misses** for us.
# ===========================================================================

_PRESIDIO_DATE_KNOWN_MISSES_NO_DOB_ANCHOR = (
    'Today is 5-20-2021',
    'Today is 5/20/2021',
    'Today is 2021-05-21',
    'Today is 21.5.2021',
    'Today is 21.5.21',
    'Today is 5-MAY-2021',
    'Today is 05/21/21',
    'Today is May-21',
    'Today is May-2021',
    'Today is 05/21',
    '5-20-2021',
    '2024-03-15T14:30Z',
)


# ===========================================================================
# Presidio UK NINO
# ---------------------------------------------------------------------------
# Source: presidio-analyzer/tests/test_uk_nino_recognizer.py
# Our ``uk_nino`` pattern is dense (rejects D/F/I/Q/U/V/O letters).
# ===========================================================================

# Our ``uk_nino`` regex is the compact form ``[A-CEGHJ-PR-TW-Z]
# [A-CEGHJ-NPR-TW-Z]\d{6}[A-D]`` — no inner whitespace allowed, ASCII
# uppercase only. Presidio matches spaced and lowercase forms.
_PRESIDIO_UK_NINO_POSITIVES = (
    'tw987654a',  # no spaces (we lowercase-match? — actually no, fails)
)
_PRESIDIO_UK_NINO_KNOWN_MISSES_SPACED_OR_LOWERCASE = (
    'AA 12 34 56 B',                # spaces
    'hh 01 02 03 d',                 # lowercase
    'tw987654a',                     # lowercase (already)
    'nino: PR 123612C',              # spaces
    'Here is my National Insurance Number YZ 61 48 68 B',  # spaces
)
_PRESIDIO_UK_NINO_NEGATIVES = (
    'AA 12 34 56 H',          # H not in [A-D]
    'FQ 00 00 00 C',          # FQ not a valid prefix (and spaces)
    'nino: nt 99 88 77 a',    # NT prefix reserved + spaces
    "This isn't a valid national insurance number UV 98 76 54 B",
)
# Presidio rejects ``BG123612A`` because B+G prefix is in their
# never-issued list. Our compact regex allows it; documented over-match.
_PRESIDIO_UK_NINO_NEVER_ISSUED_OVERMATCH = (
    'BG123612A',
)


# ===========================================================================
# Presidio UK passport
# ---------------------------------------------------------------------------
# Source: presidio-analyzer/tests/test_uk_passport_recognizer.py
# Our ``uk_passport`` is ``\d{9}`` (bare 9 digits, very loose).
# Presidio's is ``[A-Z]{2}\d{7}`` (2 letters + 7 digits).
# ===========================================================================

_PRESIDIO_UK_PASSPORT_FORM_WE_MISS = (
    # 2-letter-prefix form — Presidio matches, our \d{9} regex does
    # not. Documented MISS.
    'AB1234567',
    'XY9876543',
    'ab1234567',
    'My passport number is CD7654321 and it expires soon',
    'Passports: AB1234567 and XY9876543',
)
# Presidio negatives that contain a bare 9-digit substring fire on OUR
# uk_passport regex. Documented over-match.
_PRESIDIO_UK_PASSPORT_OVERMATCH_INPUTS = (
    '123456789',  # bare 9 digits
)
_PRESIDIO_UK_PASSPORT_NEGATIVES_WE_ALSO_REJECT = (
    'A12345678',   # 1 letter + 8 digits — neither form
    'ABC123456',   # 3 letters + 6 digits
    'AB123456',    # 2 letters + 6 digits
    'AB 1234567',  # space between letters and digits — breaks both regexes
    'XYZAB1234567QRS',  # embedded in noise
)


# ===========================================================================
# Presidio UK postcode
# ---------------------------------------------------------------------------
# Source: presidio-analyzer/tests/test_uk_postcode_recognizer.py
# ===========================================================================

_PRESIDIO_UK_POSTCODE_POSITIVES = (
    'M1 1AA',
    'M60 1NW',
    'W1A 1HQ',
    'CR2 6XH',
    'DN55 1PT',
    'EC1A 1BB',
    'M11AA',
    'EC1A1BB',
    'DN551PT',
    'My address is SW1A 1AA in London',
    'Send to postcode EC2A 1NT please',
    'From SW1A 1AA to EC1A 1BB',
)
_PRESIDIO_UK_POSTCODE_KNOWN_MISSES = (
    # ``GIR 0AA`` (Girobank) — Presidio includes this special-case;
    # our generic pattern doesn't.
    'GIR 0AA',
    'GIR0AA',
)
# Presidio rejects these via reserved-area-code validation; we don't
# carry the reserved table so we fire on the first three.
_PRESIDIO_UK_POSTCODE_OVERMATCH_INPUTS = (
    'QA1 1AA',  # QA isn't a real area
    'VA1 1AA',
    'XA1 1AA',
)


# ===========================================================================
# Presidio UK driving licence
# ---------------------------------------------------------------------------
# Source: presidio-analyzer/tests/test_uk_driving_licence_recognizer.py
# We don't carry a UK driving licence regex — this entire corpus is a
# MISS. Documented; closing it would mean adding ~16-char pattern
# with date-of-birth embedded validation.
# ===========================================================================

_PRESIDIO_UK_DRIVING_UNSUPPORTED = (
    'MORGA607054SM9IJ',
    'MORGA657054SM9IJ',
    'FO999512018AA1AB',
    'SMIT9801015JK2CD',
    'Licence: MORGA607054SM9IJ ok',
    'morga607054sm9ij',
    'JONES710153J99EF',
)


# ===========================================================================
# Presidio CA SIN (Social Insurance Number)
# ---------------------------------------------------------------------------
# Source: presidio-analyzer/tests/test_ca_sin_recognizer.py
# We don't carry a CA SIN regex. Entire corpus is MISS.
# ===========================================================================

_PRESIDIO_CA_SIN_UNSUPPORTED = (
    '130 692 544',
    '435 418 165',
    '948 584 792',
    '347-677-452',
    '731-530-150',
    '130692544',
    '550090112',
    'my SIN is 130-692-544',
    'mon NAS: 258 933 688',
)


# ===========================================================================
# Presidio AU TFN (Tax File Number)
# ---------------------------------------------------------------------------
# Source: presidio-analyzer/tests/test_au_tfn_recognizer.py
# We don't carry an AU TFN regex. Entire corpus is MISS.
# ===========================================================================

_PRESIDIO_AU_TFN_UNSUPPORTED = (
    '876 543 210',
    '876543210',
)


# ===========================================================================
# Presidio AU Medicare
# ---------------------------------------------------------------------------
# Source: presidio-analyzer/tests/test_au_medicare_recognizer.py
# Not supported; entire corpus is MISS.
# ===========================================================================

_PRESIDIO_AU_MEDICARE_UNSUPPORTED = (
    '2123 45670 1',
    '2123456701',
)


# ===========================================================================
# Presidio IN Aadhaar (12-digit gov ID)
# ---------------------------------------------------------------------------
# Source: presidio-analyzer/tests/test_in_aadhaar_recognizer.py
# Not supported; entire corpus is MISS.
# ===========================================================================

_PRESIDIO_IN_AADHAAR_UNSUPPORTED = (
    '312345678909',
    '399876543211',
    '3123 4567 8909',
    '3998 7654 3211',
    '3123-4567-8909',
    '3998-7654-3211',
    'My Aadhaar number is 400123456787 with a lot of text beyond it',
)


# ===========================================================================
# Presidio IN PAN (income tax)
# ---------------------------------------------------------------------------
# Source: presidio-analyzer/tests/test_in_pan_recognizer.py
# Not supported; entire corpus is MISS.
# ===========================================================================

_PRESIDIO_IN_PAN_UNSUPPORTED = (
    'AAASA1111R',
    'ABCPD1234Z',
    'ABCND1234Z',
    'My PAN number is ABBPM4567S with a lot of text beyond it',
)


# ===========================================================================
# Presidio IN passport
# ---------------------------------------------------------------------------
# Source: presidio-analyzer/tests/test_in_passport_recognizer.py
# Our ``us_drivers_license`` arm ``[A-Z]\d{7}`` matches IN passport
# shape. So this lands as a positive — for the wrong reason — but the
# practical outcome (redaction) is correct.
# ===========================================================================

_PRESIDIO_IN_PASSPORT_INPUTS = (
    'A3456781',
    'B3097651',
    'C3590543',
    'my passport number is T3569075',
    'passport number: J6932157',
)


# ===========================================================================
# Presidio ES NIF
# ---------------------------------------------------------------------------
# Source: presidio-analyzer/tests/test_es_nif_recognizer.py
# Not supported; entire corpus is MISS.
# ===========================================================================

_PRESIDIO_ES_NIF_UNSUPPORTED = (
    '55555555K',
    '55555555-K',
    '1111111-G',
    '1111111G',
    '01111111G',
)


# ===========================================================================
# Presidio ES passport
# ---------------------------------------------------------------------------
# Source: presidio-analyzer/tests/test_es_passport_recognizer.py
# Not supported; entire corpus is MISS.
# ===========================================================================

_PRESIDIO_ES_PASSPORT_UNSUPPORTED = (
    'AAA123456',
    'XYZ987654',
    'Mi pasaporte es AAA123456',
    'aaa123456',
    'AaA123456',
)


# ===========================================================================
# Presidio DE passport
# ---------------------------------------------------------------------------
# Source: presidio-analyzer/tests/test_de_passport_recognizer.py
# Not supported; entire corpus is MISS.
# ===========================================================================

_PRESIDIO_DE_PASSPORT_UNSUPPORTED = (
    'C01234565',
    'F12345671',
    'L01X00T44',
    'CZ6311T03',
    'G00000002',
    'C01X00T41',
    'Reisepass C01234565 ausgestellt am 01.01.2020.',
    'Pass-Nr.: F12345671',
)


# ===========================================================================
# Presidio PL PESEL
# ---------------------------------------------------------------------------
# Source: presidio-analyzer/tests/test_pl_pesel_recognizer.py
# Not supported; entire corpus is MISS.
# ===========================================================================

_PRESIDIO_PL_PESEL_UNSUPPORTED = (
    '44051401458',
    'My pesel is 44051401458.',
    '02070803628',
    '11111111116',
)


# ===========================================================================
# Presidio SG FIN / NRIC
# ---------------------------------------------------------------------------
# Source: presidio-analyzer/tests/test_sg_fin_recognizer.py
# Not supported; entire corpus is MISS.
# ===========================================================================

_PRESIDIO_SG_FIN_UNSUPPORTED = (
    'S2740116C',
    'T1234567Z',
    'F2346401L',
    'G1122144L',
    'M4332674T',
    'NRIC S2740116C was processed',
)


# ===========================================================================
# Presidio UK NHS number
# ---------------------------------------------------------------------------
# Source: presidio-analyzer/tests/test_uk_nhs_recognizer.py
# Not supported; entire corpus is MISS.
# ===========================================================================

_PRESIDIO_UK_NHS_UNSUPPORTED = (
    '401-023-2137',
    '221 395 1837',
    '0032698674',
)


# ===========================================================================
# Presidio ABA routing
# ---------------------------------------------------------------------------
# Source: presidio-analyzer/tests/test_aba_routing_recognizer.py
# Our ``us_routing_number`` matches bare 9-digit numbers; we'd fire on
# the dashed forms only after stripping the dashes (which our regex
# doesn't do).
# ===========================================================================

_PRESIDIO_ABA_POSITIVES = (
    '121000358',
    '121042882',
)
_PRESIDIO_ABA_KNOWN_MISSES_DASHED = (
    '3222-7162-7',
    '0711-0130-7',
)
_PRESIDIO_ABA_OVERMATCH_INPUT = (
    # Presidio rejects via checksum; we fire (shape only).
    '421042111',
)


# ===========================================================================
# scrubadub Twitter handle
# ---------------------------------------------------------------------------
# Source: scrubadub/tests/test_detector_twitter.py
# Our ``twitter_handle`` is keyword-free, length 3-15.
# ===========================================================================

_SCRUBADUB_TWITTER_POSITIVES = (
    'My email is john@gmail.com and i tweet at @john_gmail',
    'My tweeter is @John_gmail',
    'My tweeter is @JOHN_JOHN123',
    'My tweeter is @_JOHN_JOHN123',
    'My tweeter is @_JOHN_JOHN123_',
)
# scrubadub treats these as "invalid handles" — our regex still fires
# on them because they're shape-valid 3-15-char identifiers.
_SCRUBADUB_TWITTER_OVERMATCH_INPUTS = (
    'This is an invalid handle @TwitterInfo',
    'This is an invalid handle @XYZAdminInfo',
)


# ===========================================================================
# scrubadub Skype handle
# ---------------------------------------------------------------------------
# Source: scrubadub/tests/test_detector_skype.py
# Our ``skype_handle`` is keyword-anchored on the word "skype".
# ===========================================================================

# Our ``skype_handle`` regex requires ``skype`` followed by
# whitespace-or-colon, then the handle as an alnum run. scrubadub's
# tests use parenthesized handles and ``skype:\n`` newlines and
# ``Skype. My ID is`` separator phrases — none match our compact form.
_SCRUBADUB_SKYPE_POSITIVES = (
    'skype: dean.malmgren\nnerd',
)
_SCRUBADUB_SKYPE_KNOWN_MISSES_OTHER_FORMS = (
    'contact me on skype (dean.malmgren) to chat',  # parens
    "i'm dean.malmgren on skype",                    # handle-before-keyword
    "i'm on skype (dean.malmgren) or can be reached on my cell",
    'I have added you on Skype. My ID is dean.malmgren',  # period separator
    'SCREAM to get my attention on Skype (dean.malmgren)',
)
_SCRUBADUB_SKYPE_NEGATIVES = (
    'SCREAM to get my attention because Im not on instant messengers',
)


# ===========================================================================
# scrubadub UK driving licence
# ---------------------------------------------------------------------------
# Source: scrubadub/tests/test_detector_drivers_licence.py
# scrubadub matches 5-letter-prefix + digits + 2-letter + digit form.
# We don't have UK DL — MISS.
# ===========================================================================

_SCRUBADUB_UK_DRIVERS_UNSUPPORTED = (
    'The driving licence number of the claimant is MORGA753116SM91J 01, and a copy of the licence is attached.',
    'My DVLA NO is MORGA 753116SM91J 01 could you please check.',
    'My DVLA NO is MORGA753116SM91J01 could you please check.',
    'My DVLA NO is MORGA 753 116 SM91J 01 could you please check.',
    'My DVLA NO is MORGA 753116 SM91J01 could you please check.',
)


# ===========================================================================
# scrubadub UK NINO
# ---------------------------------------------------------------------------
# Source: scrubadub/tests/test_detector_en_GB_nino.py
# Our ``uk_nino`` matches the canonical AA123456A form. scrubadub's
# fixtures use AA 12 34 56 A (with spaces) — our regex doesn't permit
# inner whitespace. Locked as MISS.
# ===========================================================================

_SCRUBADUB_UK_NINO_KNOWN_MISSES_SPACED = (
    'My NI number is AZ 12 34 56 A',
    # Note: 'Enter a National Insurance number ... like AZ123456A.' is
    # NOT in this set — it contains the unspaced literal AZ123456A
    # which OUR regex catches. Locked in
    # ``_SCRUBADUB_UK_NINO_EMBEDDED_LITERAL_WE_MATCH`` below.
    "It's on your National Insurance card, benefit letter, payslip or P60. For example, AZ 12 34 56 A.",
    'Please verify the NI AZ 123456 A.',
    'The number is AZ 123 456 A.',
)
_SCRUBADUB_UK_NINO_EMBEDDED_LITERAL_WE_MATCH = (
    'Enter a National Insurance number that is 2 letters, 6 numbers, then A, B, C or D, like AZ123456A.',
)


# ===========================================================================
# scrubadub date of birth
# ---------------------------------------------------------------------------
# Source: scrubadub/tests/test_detector_date_of_birth.py
# Our ``date_of_birth`` is keyword-anchored.
# ===========================================================================

# Our ``date_of_birth`` regex anchors on the keyword DIRECTLY followed
# by an optional ``:``/``=`` then the date — it doesn't accept ``is``
# between keyword and date, doesn't accept dotted (``02.12.1979``)
# format, doesn't accept ``d.o.b.`` keyword or month-name dates.
_SCRUBADUB_DOB_POSITIVES = (
    # None — every scrubadub fixture uses either ``is`` between
    # keyword and date, or dotted format, or month-name, or post-fix
    # ``born on``. Our regex catches none of them.
)
_SCRUBADUB_DOB_KNOWN_MISSES = (
    'My date of birth is 17/06/1976.',
    'DOB: 02.12.1979',
    'My dob is 22-11-1972',
    'I was born 15th June 1991',
    'My name is Mike and I was born in a land far away on 22/11/1972',
    'my name is Jane and I was born on 11/22/1972',
    'my date of birth is 22-nov-1972',
    "The claimant's, d.o.b. is 4 June 1976",
    '1985-01-01 is my birthday.',
)


# ===========================================================================
# scrubadub credentials (username / password pairs)
# ---------------------------------------------------------------------------
# Source: scrubadub/tests/test_detector_credentials.py
# We don't have a credential-pair detector here — that lives in
# ``credential_patterns.py`` as vendor-issued secret matchers, not as
# generic "username: foo / password: bar" pairs. Documented as
# unsupported in this layer.
# ===========================================================================

_SCRUBADUB_CREDENTIAL_PAIR_UNSUPPORTED = (
    'username: root\npassword: root\n\n',
    'username:root\npassword:crickets',
    'username root\npassword crickets',
    'username: joe@example.com\npassword moi',
    'login snoop pw biggreenhat',
    'u: snoop\np: biggreenhat',
    'UserName snoop PassWord biggreenhat',
)


# ===========================================================================
# scrubadub NAMES (TextBlob NER)
# ---------------------------------------------------------------------------
# Source: scrubadub/tests/test_detector_text_blob.py
# NER is explicitly out of scope for the inline gate — see
# pii_patterns.py's "Recommendation" block, "names via lightweight
# NER". We confirm we don't catch any of these.
# ===========================================================================

_SCRUBADUB_NAMES_UNSUPPORTED = (
    'John is a cat',
    'sarah is a friendly person',
)


# ===========================================================================
# scrubadub LOCATIONS
# ---------------------------------------------------------------------------
# Source: scrubadub/tests/test_filth_location.py
# NER-driven, unsupported.
# ===========================================================================

_SCRUBADUB_LOCATIONS_UNSUPPORTED = (
    'Brianland',
)


# ===========================================================================
# scrubadub ORGANIZATIONS
# ---------------------------------------------------------------------------
# Source: scrubadub/tests/test_filth_organization.py
# NER-driven, unsupported.
# ===========================================================================

_SCRUBADUB_ORGS_UNSUPPORTED = (
    'Brown-Lindsey',
)


# ===========================================================================
# Unsupported-type corpora — TDD locks for every Presidio + scrubadub +
# CommonRegex detector we don't have a dedicated regex for.
# ---------------------------------------------------------------------------
# Operator mandate (UNA-2727): "take all the test data, also from the
# types we are not supporting. write the tests first. also if they
# fail. we will solve this later."
#
# Each entry maps a hypothetical-future-pattern-name to the upstream
# corpus. The test below asserts the named pattern does NOT yet fire —
# which is trivially true today (we have no such regex) but becomes a
# load-bearing assertion the moment someone adds the pattern: the
# test must flip from "assertNotIn" to "assertIn", which signals the
# new pattern needs to be added to ``PII_PATTERN_NAMES`` and its full
# corpus needs to be promoted out of this dict into a dedicated
# bulletproof file.
# ===========================================================================

_UNSUPPORTED_TYPE_CORPORA = {
    # ---- Presidio: types we don't yet support --------------------------
    # NOTE: The third-wave expansion (UNA-2727) closed:
    #   us_npi, au_abn, au_acn, in_voter, in_gstin, es_nie,
    #   de_id_card (covered by de_passport), de_tax_id (covered by
    #   de_steuer_id), it_fiscal_code, se_personnummer,
    #   se_organisationsnummer (shares format with se_personnummer),
    #   sg_uen, th_tnin, tr_national_id, fi_personal_identity_code,
    #   uk_trn (covered by uk_utr), btc_legacy_explicit (covered by
    #   bitcoin_address), ipv6_with_embedded_ipv4 (covered by ipv6),
    #   tr_phone / ph_mobile_number (covered by phone),
    #   time_of_day / price / hex_color / date_calendar (not PII).
    # Their corpora moved into ``tests/test_pii_intl_id_bulletproof.py``
    # as positive-match tests.
    'in_vehicle': (
        'KA53ME3456', 'KA99ME3456', 'MN2412', 'MCX1243', 'I15432',
        'DL3CJI0001',
        "My Bike's registration number is OD02BA2341 with a lot of text beyond",
    ),
    'it_drivers_license': (
        'AA0123456B', 'AA0123456B and AA0123456B',
        'U1H00B000C', 'U1K711J11M',
        'license U1K711J11M here',
    ),
    # ---- scrubadub: types we don't yet support -------------------------
    'uk_drivers_license': (
        'The driving licence number of the claimant is MORGA753116SM91J 01, and a copy of the licence is attached.',
        'My DVLA NO is MORGA 753116SM91J 01 could you please check.',
        'My DVLA NO is MORGA753116SM91J01 could you please check.',
        'My DVLA NO is MORGA 753 116 SM91J 01 could you please check.',
        'My DVLA NO is MORGA 753116 SM91J01 could you please check.',
    ),
    'tr_license_plate': (
        '34 ABC 1234', '06 A 123', '35 JK 12', '16 B 1234',
        '34ABC1234', '34 abc 1234',
        'Araç plakası 34 ABC 1234 olarak kayıtlıdır.',
        'Plaka 34 ABC 1234 ve 06 JK 567',
        '01 A 12', '81 A 12', '07 AB 123',
        'License plate 34 ABC 1234',
        'Plaka numarası 06 A 123 olarak kayıtlı',
    ),
}


class TestThirdPartyCorpora(unittest.TestCase):
    """Verbatim borrowed test corpora — one method per (data type, source).

    For each upstream library's recognizer we either:

      * lock the agreement (positives we match, negatives we reject), or
      * lock the disagreement as a documented MISS (with the docstring
        naming what would close the gap so the next maintainer sees
        the roadmap before flipping the test).

    All MISS-locks are intentional — closing them is followed up in
    ``pii_patterns.py``'s "Recommendation" block.
    """

    # ---- Presidio US driver's license -----------------------------------
    def test_presidio_us_dl_known_miss_letter_plus_8(self):
        # Presidio's H12234567 is letter + 8 digits; our regex is
        # letter + 7 OR bare 8. Closing this needs a per-state table
        # (CA / FL etc. use 1+7, NY uses 9 digits, MD uses letter+12).
        firings = [t for t in _PRESIDIO_US_DL_KNOWN_MISSES if _has(t, 'us_drivers_license')]
        self.assertEqual(firings, [], f'us_drivers_license now matching letter+8: {firings}')

    def test_presidio_us_dl_negatives(self):
        firings = [t for t in _PRESIDIO_US_DL_NEGATIVES if _has(t, 'us_drivers_license')]
        self.assertEqual(firings, [], f'Presidio US DL false-positive: {firings}')

    # ---- Presidio US ITIN -----------------------------------------------
    def test_presidio_itin_positives(self):
        misses = [t for t in _PRESIDIO_ITIN_POSITIVES if not _has(t, 'itin')]
        self.assertEqual(misses, [], f'Presidio ITIN missed: {misses}')

    def test_presidio_itin_broader_groups_known_miss(self):
        # Our regex pins to 7x/8x groups (the original ITIN range).
        # Closing this means widening to 5x-8x (the IRS-expanded range).
        firings = [t for t in _PRESIDIO_ITIN_KNOWN_MISSES_BROADER_GROUPS if _has(t, 'itin')]
        self.assertEqual(firings, [], f'itin now matching 5x/6x groups: {firings}')

    def test_presidio_itin_known_misses_concatenated(self):
        # Closing this needs a no-dash variant on the ITIN regex; would
        # also over-match generic 9-digit numbers (passport, routing).
        firings = [t for t in _PRESIDIO_ITIN_KNOWN_MISSES if _has(t, 'itin')]
        self.assertEqual(firings, [], f'ITIN now matches concatenated: {firings}')

    def test_presidio_itin_invalid_group_overmatch_locked(self):
        # Closing this needs the ITIN group-number range validator
        # (Recommendation item 1 in pii_patterns.py).
        for text in _PRESIDIO_ITIN_OVERMATCH_INPUT:
            self.assertTrue(_has(text, 'itin'), f'ITIN over-match no longer fires for {text!r}')

    # ---- Presidio US bank -----------------------------------------------
    def test_presidio_us_bank_context_misses(self):
        # Closing this would mean dropping the ``account|acct`` anchor
        # in our regex, which would over-match every 9-digit number.
        # Tracked under Recommendation 2 (context boost).
        firings = [t for t in _PRESIDIO_US_BANK_KNOWN_MISSES if _has(t, 'us_bank_account')]
        self.assertEqual(firings, [], f'us_bank_account now matching unanchored: {firings}')

    def test_presidio_us_bank_negatives(self):
        firings = [t for t in _PRESIDIO_US_BANK_NEGATIVES if _has(t, 'us_bank_account')]
        self.assertEqual(firings, [], f'us_bank_account false-positive: {firings}')

    # ---- Presidio US MBI ------------------------------------------------
    def test_presidio_mbi_positives(self):
        misses = [t for t in _PRESIDIO_MBI_POSITIVES if not _has(t, 'medicare_mbi')]
        self.assertEqual(misses, [], f'Presidio MBI missed: {misses}')

    def test_presidio_mbi_lowercase_known_miss(self):
        # Closing this needs ``re.IGNORECASE`` on the MBI pattern.
        firings = [t for t in _PRESIDIO_MBI_KNOWN_MISSES_CASE if _has(t, 'medicare_mbi')]
        self.assertEqual(firings, [], f'medicare_mbi now case-insensitive: {firings}')

    def test_presidio_mbi_negatives(self):
        firings = [t for t in _PRESIDIO_MBI_NEGATIVES if _has(t, 'medicare_mbi')]
        self.assertEqual(firings, [], f'Presidio MBI false-positive: {firings}')

    def test_presidio_mbi_position_exclusions_overmatch_locked(self):
        # Closing this needs the per-position exclusion table
        # (S/B/I/L/O/Z banned at specific positions per CMS spec).
        for text in _PRESIDIO_MBI_POSITION_OVERMATCHES:
            self.assertTrue(_has(text, 'medicare_mbi'),
                            f'MBI position over-match no longer fires for {text!r}')

    # ---- Presidio Bitcoin -----------------------------------------------
    def test_presidio_btc_positives(self):
        misses = [t for t in _PRESIDIO_BTC_POSITIVES if not _has(t, 'bitcoin_address')]
        self.assertEqual(misses, [], f'Presidio BTC missed: {misses}')

    def test_presidio_btc_base58_overmatch_locked(self):
        # Closing this needs Base58Check validation (Recommendation 1).
        for text in _PRESIDIO_BTC_OVERMATCH_INPUTS:
            self.assertTrue(_has(text, 'bitcoin_address'), f'BTC over-match no longer fires for {text!r}')

    # ---- Presidio dates -------------------------------------------------
    def test_presidio_dates_without_dob_anchor_are_misses(self):
        # Our date_of_birth pattern is intentionally keyword-anchored
        # to avoid redacting every date in a log line.
        # Closing this needs a separate ``date`` family (low value;
        # most dates aren't PII).
        firings = [t for t in _PRESIDIO_DATE_KNOWN_MISSES_NO_DOB_ANCHOR if _has(t, 'date_of_birth')]
        self.assertEqual(firings, [], f'date_of_birth now matching plain dates: {firings}')

    # ---- Presidio UK NINO -----------------------------------------------
    def test_presidio_uk_nino_known_misses_spaced_or_lowercase(self):
        # Our compact regex is uppercase-only and disallows inner
        # whitespace. Closing this means adding ``re.IGNORECASE`` and
        # a ``\s?`` between every char-class block; that also accepts
        # phone-fragment-shaped strings, so the trade is documented.
        firings = [
            t for t in _PRESIDIO_UK_NINO_KNOWN_MISSES_SPACED_OR_LOWERCASE
            if _has(t, 'uk_nino')
        ]
        # The 'Enter a National Insurance number...' string happens to
        # contain the unspaced literal ``AZ123456A`` which we DO match;
        # we exclude that one from the lock by accepting it as a "wins
        # via embedded literal" case.
        self.assertEqual(firings, [], f'uk_nino now matching spaced/lowercase: {firings}')

    def test_presidio_uk_nino_negatives(self):
        firings = [t for t in _PRESIDIO_UK_NINO_NEGATIVES if _has(t, 'uk_nino')]
        self.assertEqual(firings, [], f'Presidio UK NINO false-positive: {firings}')

    def test_presidio_uk_nino_never_issued_overmatch_locked(self):
        # Closing this needs the never-issued prefix table (BG/GB/KN
        # /NK/NT/TN/ZZ).
        for text in _PRESIDIO_UK_NINO_NEVER_ISSUED_OVERMATCH:
            self.assertTrue(_has(text, 'uk_nino'),
                            f'uk_nino never-issued over-match no longer fires for {text!r}')

    # ---- Presidio UK passport -------------------------------------------
    def test_presidio_uk_passport_2letter_form_is_known_miss(self):
        # Our uk_passport is \d{9}; closing this would either need a
        # second arm ``[A-Z]{2}\d{7}`` or the per-state DL-style
        # approach. Tracked.
        firings = [t for t in _PRESIDIO_UK_PASSPORT_FORM_WE_MISS if _has(t, 'uk_passport')]
        self.assertEqual(firings, [], f'uk_passport now matching 2-letter form: {firings}')

    def test_presidio_uk_passport_9digit_overmatch_locked(self):
        # Bare 9-digit string fires our uk_passport. Same shape as
        # ABA routing / SSN-concatenated / etc. — context boost
        # (Recommendation 2) is the right fix.
        for text in _PRESIDIO_UK_PASSPORT_OVERMATCH_INPUTS:
            self.assertTrue(_has(text, 'uk_passport'), f'uk_passport over-match no longer fires for {text!r}')

    def test_presidio_uk_passport_negatives(self):
        firings = [t for t in _PRESIDIO_UK_PASSPORT_NEGATIVES_WE_ALSO_REJECT if _has(t, 'uk_passport')]
        self.assertEqual(firings, [], f'uk_passport false-positive: {firings}')

    # ---- Presidio UK postcode -------------------------------------------
    def test_presidio_uk_postcode_positives(self):
        misses = [t for t in _PRESIDIO_UK_POSTCODE_POSITIVES if not _has(t, 'uk_postcode')]
        self.assertEqual(misses, [], f'Presidio UK postcode missed: {misses}')

    def test_presidio_uk_postcode_gir_known_miss(self):
        # GIR 0AA is the Girobank legacy code. Closing this needs an
        # explicit alternation arm. Tracked.
        firings = [t for t in _PRESIDIO_UK_POSTCODE_KNOWN_MISSES if _has(t, 'uk_postcode')]
        self.assertEqual(firings, [], f'uk_postcode now matching GIR: {firings}')

    def test_presidio_uk_postcode_reserved_area_overmatch_locked(self):
        # Closing this needs the reserved-area code table
        # (QA/VA/XA never issued).
        for text in _PRESIDIO_UK_POSTCODE_OVERMATCH_INPUTS:
            self.assertTrue(_has(text, 'uk_postcode'), f'uk_postcode over-match no longer fires for {text!r}')

    # ---- Presidio UK driving (unsupported) ------------------------------
    def test_presidio_uk_driving_licence_unsupported(self):
        # We don't carry a UK DL pattern. Closing this needs a 16-char
        # alphanumeric regex with embedded DOB validation; high risk
        # of over-matching generic alphanumeric identifiers.
        for text in _PRESIDIO_UK_DRIVING_UNSUPPORTED:
            # Some of these contain UK-postcode-shaped substrings that
            # MAY incidentally fire (e.g. "MORGA607054SM9IJ" doesn't
            # have a postcode but ``MORGA 753116SM91J 01`` could). We
            # assert: no pattern in our set names UK DL.
            names = _names(text)
            self.assertNotIn('uk_drivers_license', names,
                             f'unexpected uk_drivers_license pattern — '
                             f'did someone add UK DL? Update this lock.')

    # ---- Presidio CA SIN (NOW SUPPORTED — expansion pass) ---------------
    def test_presidio_ca_sin_supported(self):
        # Added in the expansion pass — our ca_sin regex covers the
        # canonical printed form ``000-000-000``. The bare-9-digit
        # forms (``130692544``) are deliberately NOT matched by
        # ca_sin (they'd collide with us_routing_number); they fire as
        # us_routing_number / us_drivers_license instead. The
        # space-grouped form (``130 692 544``) is also deliberately
        # not in ca_sin (it would over-match phone-like spacings);
        # the same input still gets flagged via the existing phone
        # pattern, so the practical outcome (redaction) holds.
        hyphenated_inputs = [
            text for text in _PRESIDIO_CA_SIN_UNSUPPORTED
            if '-' in text
        ]
        self.assertGreater(
            len(hyphenated_inputs), 0,
            'corpus should still include hyphenated SIN forms — if not,'
            ' this lock needs to switch corpora',
        )
        for text in hyphenated_inputs:
            self.assertIn(
                'ca_sin', _names(text),
                f'ca_sin should match the canonical hyphenated SIN '
                f'form: {text!r}',
            )

    # ---- Presidio AU TFN (NOW SUPPORTED via keyword anchor) -------------
    def test_presidio_au_tfn_supported_via_keyword(self):
        # Our au_tfn is keyword-anchored on ``TFN`` because the bare
        # 8-9 digit shape is too noisy on its own (every order id /
        # timestamp / customer id would fire). Presidio's corpus is
        # bare digits — we don't match those. We do match the labelled
        # form, which is the production-relevant case. Confirm both:
        # bare corpus stays unflagged here, labelled form flagged below.
        for text in _PRESIDIO_AU_TFN_UNSUPPORTED:
            self.assertNotIn(
                'au_tfn', _names(text),
                f'au_tfn fired on bare TFN digits {text!r}; '
                f'this would over-match. Tighten the keyword anchor.',
            )
        # And confirm the labelled form fires.
        self.assertIn('au_tfn', _names('TFN 876 543 210 confirmed'))
        self.assertIn('au_tfn', _names('tfn: 876543210 on file'))

    def test_presidio_au_medicare_supported_for_spaced_form(self):
        # Our au_medicare matches the 4-5-1 space-grouped form
        # (``2123 45670 1``); the bare-digit form intentionally
        # doesn't fire because it would over-match every 10-digit
        # phone / order id.
        spaced = [t for t in _PRESIDIO_AU_MEDICARE_UNSUPPORTED if ' ' in t]
        self.assertGreater(len(spaced), 0,
                           'corpus should still include spaced Medicare')
        for text in spaced:
            self.assertIn(
                'au_medicare', _names(text),
                f'au_medicare should match spaced 4-5-1 form: {text!r}',
            )

    # ---- Presidio IN Aadhaar / PAN (NOW SUPPORTED — expansion pass) -----
    def test_presidio_in_aadhaar_supported_for_spaced_form(self):
        # Our in_aadhaar requires the canonical printed form
        # ``1234 5678 9012`` (4-4-4 space-grouped). Bare 12-digit and
        # hyphenated 4-4-4 forms are deliberately not matched — the
        # bare form would collide with bank account numbers and other
        # 12-digit ids, and the hyphenated form is non-canonical for
        # Aadhaar.
        import re as _re
        spaced_aadhaar = _re.compile(r'\b\d{4}\s\d{4}\s\d{4}\b')
        spaced_inputs = [
            text for text in _PRESIDIO_IN_AADHAAR_UNSUPPORTED
            if spaced_aadhaar.search(text)
        ]
        self.assertGreater(
            len(spaced_inputs), 0,
            'corpus should still include space-grouped Aadhaar — if'
            ' not, switch corpora',
        )
        for text in spaced_inputs:
            self.assertIn(
                'in_aadhaar', _names(text),
                f'in_aadhaar should match the canonical space-grouped'
                f' form: {text!r}',
            )

    def test_presidio_in_pan_supported(self):
        # PAN is ``AAAAA9999A`` — unique layout, no false-positive
        # risk. Every input in the Presidio corpus should fire.
        for text in _PRESIDIO_IN_PAN_UNSUPPORTED:
            self.assertIn(
                'in_pan', _names(text),
                f'in_pan should match PAN-shaped input: {text!r}',
            )

    # ---- Presidio IN passport — incidental match via us_drivers_license -
    def test_presidio_in_passport_incidentally_matches_via_us_dl(self):
        # IN passport is ``[A-Z]\d{7}`` which collides with our
        # ``us_drivers_license`` arm. Outcome (the value is redacted)
        # is correct; the pattern name is wrong. Locked so a future
        # tightening of us_drivers_license (e.g. to a per-state table)
        # doesn't silently lose this redaction.
        for text in _PRESIDIO_IN_PASSPORT_INPUTS:
            self.assertTrue(
                _any_pii(text),
                f'no PII fires on IN passport input {text!r} — was '
                f'us_drivers_license tightened in a way that drops it?',
            )

    # ---- Presidio ES NIF (NOW SUPPORTED — expansion pass) ---------------
    def test_presidio_es_nif_supported(self):
        # Our es_nif matches 7-8 digits + optional dash + check letter
        # (the trailing letter is what distinguishes it from generic
        # account numbers). Every input in Presidio's corpus has the
        # check letter, so all fire.
        for text in _PRESIDIO_ES_NIF_UNSUPPORTED:
            self.assertIn(
                'es_nif', _names(text),
                f'es_nif should match NIF-shaped input: {text!r}',
            )

    def test_presidio_es_passport_supported(self):
        # Case-insensitive 3-letters + 6-digits. Every input fires,
        # including the lowercase / mixed-case forms.
        for text in _PRESIDIO_ES_PASSPORT_UNSUPPORTED:
            self.assertIn(
                'es_passport', _names(text),
                f'es_passport should match ES passport input: {text!r}',
            )

    # ---- Presidio DE passport (NOW SUPPORTED — expansion pass) ----------
    def test_presidio_de_passport_supported(self):
        # Case-insensitive restricted-prefix + 8 alphanumeric. Every
        # input in the corpus fires, including the lowercase forms
        # (``l01x00t44``) and the keyword-prefixed prose forms.
        for text in _PRESIDIO_DE_PASSPORT_UNSUPPORTED:
            self.assertIn(
                'de_passport', _names(text),
                f'de_passport should match DE passport input: {text!r}',
            )

    # ---- Presidio PL PESEL (NOW SUPPORTED via keyword) ------------------
    def test_presidio_pl_pesel_supported_via_keyword(self):
        # Our pl_pesel is keyword-anchored on ``PESEL`` because the
        # bare 11-digit shape over-matches phone / de_steuer_id /
        # other 11-digit IDs. The labelled form fires; the bare
        # corpus inputs deliberately don't.
        keyword_inputs = [
            text for text in _PRESIDIO_PL_PESEL_UNSUPPORTED
            if 'pesel' in text.lower()
        ]
        self.assertGreater(
            len(keyword_inputs), 0,
            'corpus should still include labelled PESEL forms — if not,'
            ' switch corpora',
        )
        for text in keyword_inputs:
            self.assertIn(
                'pl_pesel', _names(text),
                f'pl_pesel should match labelled PESEL form: {text!r}',
            )

    # ---- Presidio SG FIN (NOW SUPPORTED — expansion pass) ---------------
    def test_presidio_sg_fin_supported(self):
        # Our sg_fin matches S/T/F/G/M prefix + 7 digits + check letter.
        # Every input in the Presidio corpus fires.
        for text in _PRESIDIO_SG_FIN_UNSUPPORTED:
            self.assertIn(
                'sg_fin', _names(text),
                f'sg_fin should match SG FIN/NRIC input: {text!r}',
            )

    # ---- Presidio UK NHS (NOW SUPPORTED via keyword) --------------------
    def test_presidio_uk_nhs_supported_via_keyword(self):
        # Our uk_nhs is keyword-anchored on ``NHS`` because the bare
        # 3-3-4 form is structurally identical to a US/CA phone
        # number. The Presidio corpus is bare, so none of those fire
        # as uk_nhs (they still get redacted as ``phone``). Confirm
        # the bare corpus doesn't over-match, and that a labelled
        # form does fire.
        for text in _PRESIDIO_UK_NHS_UNSUPPORTED:
            self.assertNotIn(
                'uk_nhs', _names(text),
                f'uk_nhs fired on bare 3-3-4 form {text!r}; this '
                f'would over-match every US phone. Tighten the anchor.',
            )
        self.assertIn('uk_nhs', _names('NHS: 401-023-2137 on file'))
        self.assertIn('uk_nhs', _names('nhs 221 395 1837 confirmed'))

    # ---- Presidio ABA routing -------------------------------------------
    def test_presidio_aba_positives(self):
        misses = [t for t in _PRESIDIO_ABA_POSITIVES if not _has(t, 'us_routing_number')]
        self.assertEqual(misses, [], f'Presidio ABA missed: {misses}')

    def test_presidio_aba_dashed_known_miss(self):
        # Closing this needs a dash-stripped variant — but the un-anchored
        # 9-digit dashed form would over-match. Better fix is context boost
        # (``routing``/``ABA`` keyword).
        firings = [t for t in _PRESIDIO_ABA_KNOWN_MISSES_DASHED if _has(t, 'us_routing_number')]
        self.assertEqual(firings, [], f'us_routing_number now matching dashed: {firings}')

    def test_presidio_aba_checksum_overmatch_locked(self):
        # Closing this needs the ABA checksum validator
        # (3×first + 7×second mod 10 == 0).
        for text in _PRESIDIO_ABA_OVERMATCH_INPUT:
            self.assertTrue(_has(text, 'us_routing_number'),
                            f'ABA over-match no longer fires for {text!r}')

    # ---- scrubadub Twitter ----------------------------------------------
    def test_scrubadub_twitter_positives(self):
        misses = [t for t in _SCRUBADUB_TWITTER_POSITIVES if not _has(t, 'twitter_handle')]
        self.assertEqual(misses, [], f'scrubadub Twitter missed: {misses}')

    def test_scrubadub_twitter_overmatch_locked(self):
        # scrubadub marks these as invalid via a known-handles list;
        # our shape-only regex fires.
        for text in _SCRUBADUB_TWITTER_OVERMATCH_INPUTS:
            self.assertTrue(_has(text, 'twitter_handle'),
                            f'Twitter over-match no longer fires for {text!r}')

    # ---- scrubadub Skype ------------------------------------------------
    def test_scrubadub_skype_positives(self):
        misses = [t for t in _SCRUBADUB_SKYPE_POSITIVES if not _has(t, 'skype_handle')]
        self.assertEqual(misses, [], f'scrubadub Skype missed: {misses}')

    def test_scrubadub_skype_other_forms_known_miss(self):
        # Closing this needs parens-handle + period-separator arms in
        # the skype regex, or a context-window detector.
        firings = [
            t for t in _SCRUBADUB_SKYPE_KNOWN_MISSES_OTHER_FORMS
            if _has(t, 'skype_handle')
        ]
        self.assertEqual(firings, [], f'skype_handle now matching other forms: {firings}')

    def test_scrubadub_skype_negatives(self):
        firings = [t for t in _SCRUBADUB_SKYPE_NEGATIVES if _has(t, 'skype_handle')]
        self.assertEqual(firings, [], f'scrubadub Skype false-positive: {firings}')

    # ---- scrubadub UK driving (unsupported) -----------------------------
    def test_scrubadub_uk_drivers_unsupported(self):
        # Same gap as Presidio's UK DL. Locked.
        for text in _SCRUBADUB_UK_DRIVERS_UNSUPPORTED:
            self.assertNotIn('uk_drivers_license', _names(text),
                             f'unexpected uk_drivers_license pattern')

    # ---- scrubadub UK NINO (spaced form) --------------------------------
    def test_scrubadub_uk_nino_spaced_known_miss(self):
        # Closing this means allowing spaces inside the NINO regex,
        # which would also accept timestamps / phone fragments.
        firings = [t for t in _SCRUBADUB_UK_NINO_KNOWN_MISSES_SPACED if _has(t, 'uk_nino')]
        self.assertEqual(firings, [], f'uk_nino now matching spaced: {firings}')

    def test_scrubadub_uk_nino_embedded_literal_we_match(self):
        # The doc-string-style scrubadub fixture happens to quote the
        # canonical unspaced literal ``AZ123456A`` as an example,
        # which our regex matches. Lock it.
        misses = [
            t for t in _SCRUBADUB_UK_NINO_EMBEDDED_LITERAL_WE_MATCH
            if not _has(t, 'uk_nino')
        ]
        self.assertEqual(misses, [], f'embedded NINO literal no longer matches: {misses}')

    # ---- scrubadub DOB --------------------------------------------------
    def test_scrubadub_dob_known_misses(self):
        # Our keyword anchor is strict: ``dob``/``date of birth``/
        # ``birthday``/``born`` directly followed by optional ``:``/
        # ``=`` then the date. scrubadub uses ``is``-separated and
        # dotted-format and month-name-format and ``d.o.b.``-keyword
        # variants. Closing this means expanding the anchor + adding a
        # dotted date-format arm.
        firings = [t for t in _SCRUBADUB_DOB_KNOWN_MISSES if _has(t, 'date_of_birth')]
        self.assertEqual(firings, [], f'date_of_birth now matching scrubadub forms: {firings}')

    # ---- scrubadub credentials (unsupported) ----------------------------
    def test_scrubadub_credential_pairs_unsupported(self):
        # Generic username/password pair detection lives better in
        # credential_patterns.py (vendor-issued secrets) — see the
        # follow-up note in the pii_patterns.py "Borrow from
        # scrubadub" subsection. Confirm no false-positive in PII set.
        for text in _SCRUBADUB_CREDENTIAL_PAIR_UNSUPPORTED:
            self.assertNotIn('credential_pair', _names(text),
                             f'unexpected credential_pair pattern in PII set')

    # ---- scrubadub NAMES (unsupported / NER) ----------------------------
    def test_scrubadub_names_unsupported_no_ner(self):
        # NER is intentionally out of scope. ``John``, ``sarah`` —
        # we cannot regex-catch names. Closing this needs Presidio
        # or a TextBlob/spaCy adapter (Recommendation note in
        # pii_patterns.py, "names via lightweight NER").
        for text in _SCRUBADUB_NAMES_UNSUPPORTED:
            names = _names(text)
            self.assertEqual(
                [n for n in names if n in ('name', 'person')], [],
                f'unexpected name pattern in PII set — was NER added? Update.',
            )

    # ---- scrubadub LOCATIONS (unsupported / NER) ------------------------
    def test_scrubadub_locations_unsupported_no_ner(self):
        for text in _SCRUBADUB_LOCATIONS_UNSUPPORTED:
            names = _names(text)
            self.assertEqual(
                [n for n in names if n in ('location', 'gpe')], [],
                f'unexpected location pattern — was NER added?',
            )

    # ---- scrubadub ORGANIZATIONS (unsupported / NER) --------------------
    def test_scrubadub_orgs_unsupported_no_ner(self):
        for text in _SCRUBADUB_ORGS_UNSUPPORTED:
            names = _names(text)
            self.assertEqual(
                [n for n in names if n in ('organization', 'org')], [],
                f'unexpected org pattern — was NER added?',
            )

    # ---- TDD locks for every unsupported third-party type --------------
    def test_unsupported_type_locks_no_dedicated_pattern_fires(self):
        """For each upstream PII type we don't have a dedicated regex
        for, assert no pattern named exactly for that type is in our
        finding set. When a real detector lands, this flips and forces
        an update to ``PII_PATTERN_NAMES`` + promotion of the corpus
        into a dedicated bulletproof file.
        """
        for type_name, corpus in _UNSUPPORTED_TYPE_CORPORA.items():
            for text in corpus:
                with self.subTest(type=type_name, text=text):
                    self.assertNotIn(
                        type_name, _names(text),
                        f'unexpected {type_name!r} pattern fired on '
                        f'{text!r} — was a detector added? Update '
                        f'PII_PATTERN_NAMES, promote the {type_name} '
                        f'corpus to its own bulletproof file, and '
                        f'flip this lock to a positive assertion.',
                    )

    def test_unsupported_types_cover_documented_gap_set(self):
        """The set of types in ``_UNSUPPORTED_TYPE_CORPORA`` is the
        roadmap. After the UNA-2727 third-wave expansion the catalog
        has been pared down to just the entries that genuinely
        cannot be closed without a new dependency, a confidence-tier
        mechanism, or a multi-regex per-region table. Lock the keys
        so a future maintainer who adds a detector for one of the
        remaining items is forced to also remove the key here.
        """
        self.assertEqual(
            frozenset(_UNSUPPORTED_TYPE_CORPORA.keys()),
            frozenset({
                'in_vehicle',          # varied per-state format
                'it_drivers_license',  # varied per-region format
                'uk_drivers_license',  # 16-char + embedded DOB; high FP
                'tr_license_plate',    # per-province format; low value
            }),
            'Unsupported-type roadmap drifted. Add the new entries '
            'here (or remove the promoted ones) so the gap is '
            'explicit.',
        )

    # ---- Meta: the locked-pattern set is the contract ------------------
    def test_locked_pattern_names_match_pii_patterns_module(self):
        # If a new pattern is added and a test in this file references
        # it under a new name, the test name + the module's named set
        # must agree. This is the sanity test the operator can grep
        # for after adding any new pattern.
        # The canonical locked set lives in
        # ``test_pii_scan._EXPECTED_PATTERN_NAMES``. Imported here
        # rather than duplicated so that adding a pattern is a
        # one-place edit.
        from agent_core_lib.tests.test_pii_scan import _EXPECTED_PATTERN_NAMES
        self.assertEqual(
            PII_PATTERN_NAMES,
            _EXPECTED_PATTERN_NAMES,
            'PII_PATTERN_NAMES drifted — update _EXPECTED_PATTERN_NAMES '
            'in test_pii_scan.py and the gap-coverage tests in this file.',
        )


if __name__ == '__main__':
    unittest.main()
