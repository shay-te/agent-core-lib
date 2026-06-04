"""Postal-code patterns (US / UK / CA / NL / DE / FR / IT / ES / AU / JP / BR / IN / IL / SE / DK / NO / FI / CH).

Aggregated into the public ``_PII_PATTERNS`` tuple by
:mod:`agent_core_lib.pii.pii_patterns`. Declaration
order matters (overlap resolver in the scrubber picks the
first-declared span on a tie); the order inside this file
feeds the aggregator in the same sequence.
"""
from __future__ import annotations

import re


PATTERNS = (
    # --- postal -------------------------------------------------------
    # US ZIP (5) and ZIP+4 (5+4). Common but PII when combined with name.
    ('us_zip', re.compile(r'\b\d{5}(?:-\d{4})?\b')),
    # UK postcode: AA9A 9AA / A9A 9AA / A9 9AA / A99 9AA / AA9 9AA / AA99 9AA.
    ('uk_postcode', re.compile(
        r'\b[A-Z]{1,2}\d[A-Z\d]?\s*\d[A-Z]{2}\b'
    )),
    # Canadian postcode: A1A 1A1.
    ('ca_postcode', re.compile(r'\b[A-Z]\d[A-Z]\s*\d[A-Z]\d\b')),
    # Netherlands postcode: 4 digits + 2 uppercase letters (``1011 AB``).
    # Distinctive shape — the digit-then-letter ordering is unusual
    # enough that a keyword anchor would be redundant.
    ('nl_postcode', re.compile(r'\b\d{4}\s?[A-Z]{2}\b')),

    # --- postal codes (international) ---------------------------------
    # All keyword-anchored where the bare shape collides with too many
    # other id classes (Israel / Sweden / Switzerland 4-5 digit forms
    # would catch every order id without the anchor).
    ('de_postcode', re.compile(
        r'\b(?:PLZ|postleitzahl|D-)\s*[:=]?\s*\d{5}\b',
        re.IGNORECASE,
    )),
    ('fr_postcode', re.compile(
        r'\b(?:code\s+postal|F-)\s*[:=]?\s*\d{5}\b',
        re.IGNORECASE,
    )),
    ('it_postcode', re.compile(
        r'\b(?:CAP|I-)\s*[:=]?\s*\d{5}\b',
        re.IGNORECASE,
    )),
    ('es_postcode', re.compile(
        r'\b(?:CP|código\s+postal|E-)\s*[:=]?\s*\d{5}\b',
        re.IGNORECASE,
    )),
    ('au_postcode', re.compile(
        r'\b(?:postcode|post\s*code)\s*[:=]?\s*\d{4}\b',
        re.IGNORECASE,
    )),
    # JP postcode — XXX-XXXX, ``〒`` prefix or ``zip`` keyword.
    ('jp_postcode', re.compile(
        r'(?:〒|zip|postcode)\s*[:=]?\s*\d{3}-\d{4}\b',
        re.IGNORECASE,
    )),
    # BR CEP — XXXXX-XXX, keyword ``CEP``.
    ('br_cep', re.compile(r'\bCEP\s*[:=]?\s*\d{5}-?\d{3}\b', re.IGNORECASE)),
    # IN PIN code — 6 digits, keyword anchor (``PIN``, ``PIN code``,
    # ``PINcode``, ``postal code``).
    ('in_pincode', re.compile(
        r'\bPIN\s*code\s*[:=]?\s*\d{6}\b|\bPIN\s*[:=]?\s*\d{6}\b'
        r'|\bpostal\s+code\s*[:=]?\s*\d{6}\b',
        re.IGNORECASE,
    )),
    # IL postcode — 7 digits, keyword anchor (Hebrew ``מיקוד`` or English).
    ('il_postcode', re.compile(
        r'\b(?:מיקוד|postcode|zip)\s*[:=]?\s*\d{7}\b',
        re.IGNORECASE,
    )),
    # SE postcode — XXX XX format.
    ('se_postcode', re.compile(
        r'\b(?:postnummer|SE-)\s*[:=]?\s*\d{3}\s?\d{2}\b',
        re.IGNORECASE,
    )),
    ('dk_postcode', re.compile(
        r'\b(?:postnummer|DK-)\s*[:=]?\s*\d{4}\b',
        re.IGNORECASE,
    )),
    ('no_postcode', re.compile(
        r'\b(?:postnummer|NO-)\s*[:=]?\s*\d{4}\b',
        re.IGNORECASE,
    )),
    ('fi_postcode', re.compile(
        r'\b(?:postinumero|FI-)\s*[:=]?\s*\d{5}\b',
        re.IGNORECASE,
    )),
    ('ch_postcode', re.compile(
        r'\b(?:PLZ|CH-)\s*[:=]?\s*\d{4}\b',
        re.IGNORECASE,
    )),

)
