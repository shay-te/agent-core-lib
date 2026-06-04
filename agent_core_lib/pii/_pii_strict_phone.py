"""Strict phone-number detection via Google's ``phonenumbers`` library.

The regex-only :mod:`agent_core_lib.pii._pii_contact` ``phone``
pattern is intentionally loose (``\\+?\\d[\\d \\-().]{8,}\\d``) — it
fires on every order id, timestamp, and bare number. This module is
the precision pair: it iterates ``phonenumbers.PhoneNumberMatcher``,
which parses + validates per ISO-3166 dialing plans and only fires on
real numbers.

Use this *in addition to* :func:`find_pii_patterns` when false-positive
phone detections matter (audit-log noise, blocking flows). The cost is
the ``phonenumbers`` dependency at runtime.
"""
from __future__ import annotations

from typing import List

import phonenumbers

from agent_core_lib.pii.pii_patterns import PIIPatternFinding


def _redact(matched_text: str) -> str:
    prefix_len = min(4, len(matched_text))
    return f'{matched_text[:prefix_len]}…[REDACTED, len={len(matched_text)}]'


def find_strict_phone(text: str, default_region: str = 'US') -> List[PIIPatternFinding]:
    """Return every ``phonenumbers``-validated phone number in ``text``.

    ``default_region`` is the ISO-3166 country code applied to numbers
    that lack a ``+`` international prefix. Defaults to ``'US'``;
    callers in EU / IL / etc. should pass their region.

    Returns the same :class:`PIIPatternFinding` shape the regex-based
    scanner emits, with ``pattern_name='phone_strict'``.
    """
    if not text or not isinstance(text, str):
        return []
    findings: List[PIIPatternFinding] = []
    for match in phonenumbers.PhoneNumberMatcher(text, default_region):
        findings.append(PIIPatternFinding(
            pattern_name='phone_strict',
            redacted_preview=_redact(match.raw_string),
        ))
    return findings
