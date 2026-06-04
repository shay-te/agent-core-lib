"""International government-issued ID patterns + healthcare MRN.

Aggregated into the public ``_PII_PATTERNS`` tuple by
:mod:`agent_core_lib.pii.pii_patterns`. Declaration
order matters (overlap resolver in the scrubber picks the
first-declared span on a tie); the order inside this file
feeds the aggregator in the same sequence.
"""
from __future__ import annotations

import re


PATTERNS = (
    # --- international government IDs ---------------------------------
    # UK National Insurance number.
    ('uk_nino', re.compile(
        r'\b[A-CEGHJ-PR-TW-Z][A-CEGHJ-NPR-TW-Z]\d{6}[A-D]\b'
    )),
    # UK Unique Tax Reference — borrowed from scrubadub's
    # ``TaxReferenceNumberDetector``. 10 digits, optional ``K`` suffix.
    # Keyword-anchored (UTR) because a bare 10-digit number false-
    # positives on too many ids/timestamps; UTRs in real text are
    # almost always labelled.
    ('uk_utr', re.compile(r'\bUTR\s*[:=]?\s*\d{10}K?\b', re.IGNORECASE)),
    # UK passport: 9 digits.
    ('uk_passport', re.compile(r'\b\d{9}\b')),
    # Canadian passport: 2 letters + 6 digits.
    ('ca_passport', re.compile(r'\b[A-Z]{2}\d{6}\b')),
    # Australian passport: 1 letter + 7 digits.
    ('au_passport', re.compile(r'\b[A-Z]\d{7}\b')),
    # Spanish passport — 3 letters + 6 digits (``AAA123456``).
    # Case-insensitive because Presidio's corpus includes lowercase
    # and mixed-case forms; the shape is distinctive enough not to
    # need a keyword anchor.
    ('es_passport', re.compile(r'\b[A-Z]{3}\d{6}\b', re.IGNORECASE)),
    # German passport / ID card (same regex covers both — they share
    # the BSI format, so this single pattern closes both the
    # standalone ``_PRESIDIO_DE_PASSPORT_UNSUPPORTED`` lockdown and
    # the ``_UNSUPPORTED_TYPE_CORPORA['de_id_card']`` catalog entry).
    # Allowed letter set is ``C F G H J K L M N P R T V W X Y Z`` (no
    # A/B/D/E/I/O/Q/S/U). Length is 9, alphanumeric after the leading
    # letter. The restricted letter set is what keeps this from
    # over-matching generic 9-char alphanumerics. Case-insensitive
    # because Presidio's corpus includes lowercase forms
    # (``l01x00t44``).
    ('de_passport', re.compile(
        r'\b[CFGHJKLMNPRTVWXYZ][CFGHJKLMNPRTVWXYZ0-9]{8}\b',
        re.IGNORECASE,
    )),
    # Spanish NIF (Número de Identificación Fiscal) — 7 or 8 digits
    # followed by an optional dash and a check letter. The trailing
    # letter is what distinguishes it from a bare account number; the
    # 7-or-8 digit width covers both old-style (7) and new-style (8)
    # NIFs.
    ('es_nif', re.compile(r'\b\d{7,8}-?[A-Z]\b')),
    # Singapore FIN / NRIC — prefix letter from ``S T F G M`` + 7
    # digits + check letter (``S2740116C``). The restricted prefix
    # letter set is what keeps this from over-matching every
    # ``[A-Z]\d{7}[A-Z]`` ID (which would collide with several other
    # countries' formats).
    ('sg_fin', re.compile(r'\b[STFGM]\d{7}[A-Z]\b')),
    # Polish PESEL — 11 digits, keyword-anchored on ``PESEL``. The
    # bare 11-digit shape over-matches with phone numbers, German
    # tax IDs (``de_steuer_id``), and several other 11-digit
    # identifiers, so we only flag the keyword-labelled form. The
    # anchor accepts a short connector word (``is`` / ``no`` /
    # ``number``) between the keyword and the digits so prose forms
    # like ``My pesel is 44051401458`` match in addition to the
    # field-name form ``PESEL: 44051401458``.
    ('pl_pesel', re.compile(
        r'\bPESEL\b\s*(?:number|no|is)?\s*[:=#]?\s*\d{11}\b',
        re.IGNORECASE,
    )),
    # UK NHS number — 10 digits in 3-3-4 grouping. Keyword-anchored
    # on ``NHS`` because the bare 3-3-4 form is structurally
    # indistinguishable from a US/CA phone number with a leading area
    # code; the production-relevant case (an explicit NHS reference)
    # is what the anchor matches. The phone pattern still fires on
    # the bare form so coverage of the bare 3-3-4 shape isn't lost.
    # ``NHS`` is allowed to be followed by an optional word
    # (``number``/``no``) — the Presidio corpus and realistic prose
    # both use ``NHS number 401-023-2137`` and ``NHS 401-023-2137``.
    ('uk_nhs', re.compile(
        r'\bNHS\s*(?:number|no)?\s*[:#=]?\s*'
        r'\d{3}[\s\-]?\d{3}[\s\-]?\d{4}\b',
        re.IGNORECASE,
    )),
    # Australian Medicare — 10 digits in 4-5-1 grouping
    # (``2123 45670 1``). The space-grouped 4-5-1 layout is what
    # distinguishes Medicare from generic 10-digit phone/account
    # numbers; the bare-digit form is intentionally not matched
    # because it would over-match (Presidio's recognizer uses a
    # checksum validator for that case — a follow-up).
    ('au_medicare', re.compile(r'\b\d{4}\s\d{5}\s\d\b')),
    # Canadian SIN (Social Insurance Number) — 9 digits, canonical
    # printed form ``000-000-000``. The 3-3-3 grouping distinguishes it
    # from US SSN (3-2-4) and from US/Canadian phone (3-3-4), so the
    # bare hyphenated shape is safe to flag without a keyword anchor.
    ('ca_sin', re.compile(r'\b\d{3}-\d{3}-\d{3}\b')),
    # Australian TFN (Tax File Number) — 8 or 9 digits, usually
    # written as ``123 456 782``. Keyword-anchored because the bare
    # digit shape is too noisy.
    ('au_tfn', re.compile(
        r'\bTFN\s*[:=]?\s*\d{3}\s?\d{3}\s?\d{2,3}\b',
        re.IGNORECASE,
    )),
    # German Steueridentifikationsnummer — 11 digits, keyword-anchored
    # (``Steuer-ID`` / ``Steueridentifikationsnummer`` / ``IdNr.`` —
    # the third alias covers the ``IdNr. 98765432106`` form Presidio's
    # corpus uses, closing the ``_UNSUPPORTED_TYPE_CORPORA['de_tax_id']``
    # catalog entry). The 11-digit bare shape would otherwise collide
    # with phone numbers and order ids.
    ('de_steuer_id', re.compile(
        r'\b(?:Steuer-?ID|Steueridentifikationsnummer|IdNr\.?)\s*[:=]?\s*'
        r'\d{2}\s?\d{3}\s?\d{3}\s?\d{3}\b',
        re.IGNORECASE,
    )),
    # Indian Aadhaar — 12 digits, canonical printed form
    # ``1234 5678 9012`` (4-4-4 grouped). The 12-digit shape is
    # distinctive enough to flag without a keyword anchor.
    ('in_aadhaar', re.compile(r'\b\d{4}\s\d{4}\s\d{4}\b')),
    # Indian PAN (Permanent Account Number) — 5 letters + 4 digits +
    # 1 letter = 10 chars. Distinctive layout, no anchor needed.
    ('in_pan', re.compile(r'\b[A-Z]{5}\d{4}[A-Z]\b')),
    # Brazilian CPF (Cadastro de Pessoas Físicas) — canonical printed
    # form ``000.000.000-00`` (11 digits with 3-3-3-2 punctuation).
    ('br_cpf', re.compile(r'\b\d{3}\.\d{3}\.\d{3}-\d{2}\b')),
    # Brazilian CNPJ (Cadastro Nacional da Pessoa Jurídica) — printed
    # form ``00.000.000/0000-00`` (14 digits with 2-3-3-4-2 punctuation).
    ('br_cnpj', re.compile(r'\b\d{2}\.\d{3}\.\d{3}/\d{4}-\d{2}\b')),

    # --- catalog-block close-outs (third wave) ------------------------
    # The patterns below close every documented gap in
    # ``_UNSUPPORTED_TYPE_CORPORA`` whose shape is distinctive enough
    # to flag without a new dependency or a confidence-tier mechanism.
    # See the prior-art note above ("Third wave — catalog close-out")
    # for which catalog keys were closed vs. which stayed deferred.

    # Indian GSTIN — 15 chars in a unique layout:
    # 2 digits (state code) + 5 letters (PAN-style entity) + 4 digits
    # + 1 letter (entity number) + 1 digit/letter + ``Z`` + 1 alphanum.
    ('in_gstin', re.compile(
        r'\b\d{2}[A-Z]{5}\d{4}[A-Z]\d[A-Z]\d\b'
    )),
    # Italian Codice Fiscale — 16 chars, fully deterministic layout:
    # 6 letters (surname/name initials) + 2 digits (year) + 1 letter
    # (month) + 2 digits (day, gender-offset) + 1 letter + 3 digits +
    # check letter. Highly distinctive.
    ('it_fiscal_code', re.compile(
        r'\b[A-Z]{6}\d{2}[A-Z]\d{2}[A-Z]\d{3}[A-Z]\b'
    )),
    # Spanish NIE (Número de Identidad de Extranjero) — foreigner ID:
    # prefix letter from ``X Y Z`` + 7-8 digits + optional dash +
    # check letter. Distinct from NIF (which has digits first).
    ('es_nie', re.compile(r'\b[XYZ]\d{7,8}-?[A-Z]\b')),
    # Swedish personnummer / organisationsnummer — both share the
    # dashed format (one regex closes both catalog entries). The
    # legal date-prefix lengths are 6 (YYMMDD) or 8 (YYYYMMDD) only —
    # never 7 — and the separator is ``-`` or ``+`` (``+`` indicates
    # someone over 100 years old). Bare-digit forms intentionally
    # not matched (would over-match every 10-12 digit number).
    ('se_personnummer', re.compile(r'\b(?:\d{6}|\d{8})[-+]\d{4}\b')),
    # Indian Voter ID / EPIC — 3 letters + 7 digits. The 3-letter
    # prefix is what keeps this from colliding with the
    # ``us_drivers_license`` arm (1 letter + 7 digits).
    ('in_voter', re.compile(r'\b[A-Z]{3}\d{7}\b')),
    # Finnish personal identity code (henkilötunnus / HETU) —
    # DDMMYY + century-separator + 3-digit individual number +
    # check character (digit OR letter). The century separator is
    # one of: ``+`` (1800s); ``- Y X W V U`` (1900s, broadening per
    # the 2023 DVV expansion to cope with running out of individual
    # numbers); ``A B C D E F`` (2000s, same expansion). The full
    # set is ``[+\-ABCDEFUVWXY]``.
    ('fi_personal_identity_code', re.compile(
        r'\b\d{6}[+\-ABCDEFUVWXY]\d{3}[A-Z0-9]\b'
    )),

    # The remaining catalog close-outs are keyword-anchored because
    # the underlying digit/letter shape is too generic to flag on its
    # own. Each fires only when the labelled form appears in the
    # text — the production case for a tool result that names the
    # field.

    # US NPI (National Provider Identifier) — 10 digits, keyword.
    ('us_npi', re.compile(
        r'\bNPI\s*[:#=]?\s*\d{10}\b',
        re.IGNORECASE,
    )),
    # Australian Business Number — 11 digits, keyword ``ABN``.
    # Same 11-digit shape as PESEL / DE Steuer-ID; keyword is the
    # disambiguator.
    ('au_abn', re.compile(
        r'\bABN\s*[:#=]?\s*\d{2}\s?\d{3}\s?\d{3}\s?\d{3}\b',
        re.IGNORECASE,
    )),
    # Australian Company Number — 9 digits, keyword ``ACN``.
    ('au_acn', re.compile(
        r'\bACN\s*[:#=]?\s*\d{3}\s?\d{3}\s?\d{3}\b',
        re.IGNORECASE,
    )),
    # Singapore UEN — 9-10 char alphanumeric, several formats.
    # Keyword-anchored because the bare shape collides with many
    # other 9-10 char identifiers (FIN/NRIC, generic order ids).
    ('sg_uen', re.compile(
        r'\bUEN\s*[:#=]?\s*[A-Z0-9]{9,10}\b',
        re.IGNORECASE,
    )),
    # Thai National ID — 13 digits, keyword on either the English
    # term ``TNIN`` / ``Thai National ID`` or the Thai script
    # forms. The Thai-script keyword captures the production case
    # where the tool result is in Thai locale.
    ('th_tnin', re.compile(
        r'\b(?:TNIN|Thai\s+National\s+ID|เลขประจำตัวประชาชน|เลขบัตรประชาชน)'
        r'\s*[:#=]?\s*\d{13}\b',
        re.IGNORECASE,
    )),
    # Turkish National ID (TC Kimlik No) — 11 digits, keyword
    # ``TC`` optionally followed by ``Kimlik``. The 11-digit shape
    # collides with PESEL / DE Steuer-ID / AU ABN, so the keyword
    # anchor is the disambiguator.
    ('tr_national_id', re.compile(
        r'\bTC\s*(?:Kimlik(?:\s+No)?)?\s*[:#=]?\s*\d{11}\b',
        re.IGNORECASE,
    )),
    # Israeli Teudat Zehut — 9 digits where the last is a Luhn-like
    # check digit. The bare-9-digit shape collides with phone fragments
    # and US passport numbers, so the validator (registered in
    # ``_PATTERN_VALIDATORS``) is doing most of the work here. We also
    # accept the dashed form ``123-456-789`` that some Israeli forms
    # print, and the keyword-anchored form ``תז 123456789``.
    ('il_id', re.compile(
        r'\b(?:תז|teudat\s+zehut|israeli\s+id)\s*[:=]?\s*\d{9}\b'
        r'|\b\d{9}\b'
        r'|\b\d{3}-\d{3}-\d{3}\b',
        re.IGNORECASE,
    )),

    # --- additional government IDs ------------------------------------
    # CN resident identity card — 18 chars (17 digits + check char).
    # Validator drops shape-valid-but-checksum-invalid candidates.
    ('cn_resident_id', re.compile(r'\b\d{17}[\dXx]\b')),
    # JP My Number — 12 digits, keyword-anchored (the bare 12-digit
    # shape collides with too many other ids).
    ('jp_my_number', re.compile(
        r'\b(?:my\s+number|マイナンバー|個人番号)\s*[:=]?\s*\d{12}\b',
        re.IGNORECASE,
    )),
    # KR resident registration number — YYMMDD-SXXXXXX.
    ('kr_rrn', re.compile(r'\b\d{6}-[1-8]\d{6}\b')),
    # RU INN — 10 (legal entity) or 12 (individual) digits, keyword-anchored.
    ('ru_inn', re.compile(
        r'\bИНН\s*[:=]?\s*(?:\d{10}|\d{12})\b',
        re.IGNORECASE,
    )),
    # MX CURP — 4 letters + 6 digits + 6 letters + 2 alphanumerics (18 chars).
    ('mx_curp', re.compile(r'\b[A-Z]{4}\d{6}[A-Z]{6}[A-Z0-9]{2}\b')),
    # MX RFC — 3-4 letters + 6 digits + 3 alphanumerics.
    ('mx_rfc', re.compile(r'\b[A-Z]{3,4}\d{6}[A-Z0-9]{3}\b')),
    # AR CUIL/CUIT — XX-XXXXXXXX-X.
    ('ar_cuil_cuit', re.compile(r'\b\d{2}-\d{8}-\d\b')),
    # ZA ID — 13 digits, Luhn-validated.
    ('za_id', re.compile(r'\b\d{13}\b')),
    # NZ IRD — 8-9 digits, keyword-anchored.
    ('nz_ird', re.compile(r'\bIRD\s*[:=]?\s*\d{8,9}\b', re.IGNORECASE)),
    # US DEA number — 2 letters + 7 digits, keyword-anchored.
    ('us_dea', re.compile(r'\bDEA\s*[:=]?\s*[A-Z]{2}\d{7}\b', re.IGNORECASE)),

    # --- healthcare identifier ----------------------------------------
    # Medical record number — keyword-anchored; the shape varies by
    # health system so we lean on the keyword.
    ('medical_record_number', re.compile(
        r'\b(?:MRN|medical\s+record\s+(?:no|number|#))\s*[:=]?\s*[A-Z0-9\-]{4,20}\b',
        re.IGNORECASE,
    )),
)
