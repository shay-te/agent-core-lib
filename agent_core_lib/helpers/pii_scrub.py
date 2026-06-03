"""Structured-payload PII scanner + scrubber.

This is the runtime backstop the admin-backend wires into its LLM
tool-result boundary. Three entry points, all reading the workspace's
single source of truth — :mod:`agent_core_lib.helpers.pii_patterns`:

* :func:`find_pii_in_payload` — non-throwing scan over ``dict`` /
  ``list`` / ``tuple`` / ``str``; returns a list of
  :class:`~agent_core_lib.helpers.pii_patterns.PIIPatternFinding` so
  callers can log / count / inspect.
* :func:`assert_no_pii` — raises :class:`PIIDetectedError` if anything
  matched. The test-suite hook for locking the contract that a given
  tool's payload is PII-free.
* :func:`scrub_pii` — recursive in-place rewrite of strings inside
  the payload, replacing every match with ``[redacted:<pattern>]``.
  Containers are walked; non-text primitives (``int`` / ``bool`` /
  ``None`` / ``Decimal`` / ``date``) pass through untouched.

The text-stream WARNING-log helper lives in
:mod:`agent_core_lib.helpers.pii_scan`; this module is for *payloads*
the host app is about to hand to a model.
"""

from __future__ import annotations

import json
from typing import Any, List

from agent_core_lib.helpers.pii_patterns import (
    PIIPatternFinding,
    find_pii_patterns,
    iter_pattern_names_and_regexes,
)


class PIIDetectedError(ValueError):
    """:func:`assert_no_pii` found at least one PII match.

    The error message names the matched patterns but never the raw
    matched values — the redacted preview is the only thing safe to
    surface to logs / test failures.
    """


def _payload_blob(payload: Any) -> str:
    # ``default=str`` so dates / Decimal / UUID don't crash. ``sort_keys``
    # makes the scan deterministic, which matters for test assertions.
    return json.dumps(payload, default=str, sort_keys=True)


def find_pii_in_payload(payload: Any) -> List[PIIPatternFinding]:
    """Return every PII-pattern match found anywhere in ``payload``.

    The payload is serialized once via ``json.dumps`` and scanned with
    every pattern; nested ``dict`` / ``list`` / ``tuple`` values are
    covered by the serialization. Returns an empty list if nothing
    matched or the payload is ``None``.
    """
    if payload is None:
        return []
    return find_pii_patterns(_payload_blob(payload))


def assert_no_pii(payload: Any) -> None:
    """Raise :class:`PIIDetectedError` if ``payload`` contains any PII.

    The error message lists pattern names and *redacted* previews — the
    raw matched value is never re-surfaced. Use this in tests to lock
    the contract that a given tool's payload is PII-free.
    """
    findings = find_pii_in_payload(payload)
    if not findings:
        return
    summary = ', '.join(
        f'{finding.pattern_name}={finding.redacted_preview}'
        for finding in findings
    )
    raise PIIDetectedError(f'PII detected in payload: {summary}')


def _scrub_string(text: str) -> str:
    """Single-pass PII scrubber for one string.

    Iteratively-applied ``regex.sub`` calls don't work here — even
    *one* iterative pass would match the placeholder text inside the
    just-substituted output, producing nested junk like
    ``[[[redacted:us_license_plate]:swift_bic]:email]``. Instead, scan
    the *original* string once per pattern, collect every (start, end,
    name) span, sort, drop overlaps (first-declared wins — the
    declaration order in :mod:`pii_patterns` puts narrow specifics
    before broad catches), and rebuild the output in a single sweep.

    The placeholder format ``[redacted:<name>]`` is **lowercase on
    purpose**. Several patterns require uppercase (``swift_bic``,
    ``us_license_plate``, ``vin``, ``medicare_mbi``, all the
    passports, IBAN) — keeping the marker lowercase means a scrubbed
    string passed back through the scanner (which happens in audit
    paths and round-trip tests) does NOT re-match the marker as a
    bogus finding. Don't change ``redacted`` to ``REDACTED`` without
    re-checking every pattern's case constraints.
    """
    spans: list[tuple[int, int, str]] = []
    for pattern_name, regex in iter_pattern_names_and_regexes():
        for match in regex.finditer(text):
            spans.append((match.start(), match.end(), pattern_name))
    if not spans:
        return text
    # Sort by (start asc, length desc) so a longer span at the same start
    # wins over a shorter one. Then walk in order, dropping anything
    # that overlaps an already-accepted span.
    spans.sort(key=lambda span: (span[0], -(span[1] - span[0])))
    accepted: list[tuple[int, int, str]] = []
    last_end = -1
    for start, end, pattern_name in spans:
        if start < last_end:
            continue
        accepted.append((start, end, pattern_name))
        last_end = end
    out: list[str] = []
    cursor = 0
    for start, end, pattern_name in accepted:
        out.append(text[cursor:start])
        out.append(f'[redacted:{pattern_name}]')
        cursor = end
    out.append(text[cursor:])
    return ''.join(out)


def scrub_pii(payload: Any) -> Any:
    """Recursively replace PII matches inside ``payload`` with placeholders.

    Strings are rewritten via the full pattern set; ``dict`` / ``list``
    / ``tuple`` containers are walked and rebuilt with scrubbed values;
    every other type (numbers, bools, ``None``, dates, ``Decimal``,
    ``UUID``, etc.) passes through unchanged — those types don't carry
    text PII the pattern set could match.

    The function is pure — it never mutates the input, it returns a new
    container at every level.
    """
    if isinstance(payload, str):
        return _scrub_string(payload)
    if isinstance(payload, dict):
        return {key: scrub_pii(value) for key, value in payload.items()}
    if isinstance(payload, list):
        return [scrub_pii(value) for value in payload]
    if isinstance(payload, tuple):
        return tuple(scrub_pii(value) for value in payload)
    return payload
