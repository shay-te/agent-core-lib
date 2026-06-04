"""Strict date-of-birth detection via ``dateparser``.

The regex-only ``date_of_birth`` pattern in
:mod:`agent_core_lib.pii._pii_temporal` requires a keyword anchor
(``dob`` / ``date of birth`` / ``birthday`` / ``born``) so it doesn't
fire on every date-shaped string in tool output. This module is the
no-keyword companion: it walks every date-shaped substring, parses it
via ``dateparser``, and flags only those that look plausibly like a
date of birth (in the past, year >= 1900, implied age <= 130).
"""
from __future__ import annotations

import re
from datetime import date, datetime
from typing import List

import dateparser

from agent_core_lib.pii.pii_patterns import PIIPatternFinding


# Loose date-shape regex — matches anything dateparser might parse.
# Stricter than a calendar lookup but loose enough to catch the major
# ISO / US / EU forms.
_DATE_SHAPE = re.compile(
    r'\b\d{4}[-/]\d{1,2}[-/]\d{1,2}\b'
    r'|\b\d{1,2}[-/]\d{1,2}[-/]\d{2,4}\b'
    r'|\b\d{1,2}\s+(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\s+\d{2,4}\b',
    re.IGNORECASE,
)
_MIN_YEAR = 1900


def _redact(matched_text: str) -> str:
    prefix_len = min(4, len(matched_text))
    return f'{matched_text[:prefix_len]}…[REDACTED, len={len(matched_text)}]'


def _looks_like_dob(parsed: datetime) -> bool:
    # ``year >= 1900`` is the age cap: in the current decade that
    # leaves max plausible age ~125, which covers every documented
    # supercentenarian (verified ages cap at 122). No separate
    # ``age <= MAX`` check needed.
    today = date.today()
    parsed_date = parsed.date() if isinstance(parsed, datetime) else parsed
    if parsed_date > today:
        return False
    if parsed_date.year < _MIN_YEAR:
        return False
    return True


def find_strict_dob(text: str) -> List[PIIPatternFinding]:
    """Return every date-of-birth-plausible date in ``text``.

    Two-stage: shape regex finds candidate substrings, ``dateparser``
    parses each, and the plausibility filter keeps only those that
    look like a real DOB (in past, year >= 1900, age <= 130).

    Findings carry ``pattern_name='dob_strict'``.
    """
    if not text or not isinstance(text, str):
        return []
    findings: List[PIIPatternFinding] = []
    for match in _DATE_SHAPE.finditer(text):
        candidate = match.group(0)
        parsed = dateparser.parse(candidate)
        if parsed is None:
            continue
        if not _looks_like_dob(parsed):
            continue
        findings.append(PIIPatternFinding(
            pattern_name='dob_strict',
            redacted_preview=_redact(candidate),
        ))
    return findings
