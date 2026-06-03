"""PII pattern detector for agent text streams.

Parallel to ``credential_patterns`` — credential_patterns hunts
vendor-issued secrets; this module hunts personal data (email, SSN,
phone, credit-card, IBAN). Both are used by the agent boundary scanner
in :mod:`agent_core_lib.helpers.pii_scan` and may be reused by any
caller that wants to audit a raw text blob before it's persisted /
forwarded / logged.

The patterns deliberately match :mod:`llm_core_lib.safety.pii_patterns`
so the two libraries flag the same shapes. We don't import from
``llm-core-lib`` here — ``agent-core-lib`` doesn't depend on it and we
don't want to introduce that dependency just to reuse five regex
literals. If the two ever drift in semantics, the test in
``test_pii_scan`` is the canary.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable


@dataclass(frozen=True)
class PIIPatternFinding(object):
    """One match of a named PII pattern; the full matched value is never returned."""

    pattern_name: str
    redacted_preview: str


_PII_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ('email', re.compile(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}')),
    ('ssn', re.compile(r'\b\d{3}-\d{2}-\d{4}\b')),
    ('phone', re.compile(r'\+?\d[\d \-().]{8,}\d')),
    ('credit_card', re.compile(r'\b(?:\d[ \-]?){13,16}\b')),
    ('iban', re.compile(r'\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b')),
)


PII_PATTERN_NAMES: frozenset[str] = frozenset(name for name, _ in _PII_PATTERNS)


def _redact(matched_text: str) -> str:
    prefix_len = min(4, len(matched_text))
    return f'{matched_text[:prefix_len]}…[REDACTED, len={len(matched_text)}]'


def find_pii_patterns(text: str) -> list[PIIPatternFinding]:
    """Return every named PII pattern matched in ``text``.

    The raw matched value is never returned — callers receive only the
    pattern name and a redacted preview that is safe to log.
    """
    if not text or not isinstance(text, str):
        return []
    findings: list[PIIPatternFinding] = []
    for pattern_name, regex in _PII_PATTERNS:
        for match in regex.finditer(text):
            findings.append(PIIPatternFinding(
                pattern_name=pattern_name,
                redacted_preview=_redact(match.group(0)),
            ))
    return findings


def summarize_pii_findings(findings: Iterable[PIIPatternFinding]) -> str:
    """Return an operator-facing summary without raw matched values."""
    by_name: dict[str, list[PIIPatternFinding]] = {}
    for finding in findings:
        by_name.setdefault(finding.pattern_name, []).append(finding)
    if not by_name:
        return 'no pii patterns detected'
    parts: list[str] = []
    for pattern_name, group in by_name.items():
        first = group[0].redacted_preview
        if len(group) == 1:
            parts.append(f'{pattern_name}={first}')
        else:
            parts.append(f'{pattern_name}={first} (+{len(group) - 1} more)')
    return '; '.join(parts)
