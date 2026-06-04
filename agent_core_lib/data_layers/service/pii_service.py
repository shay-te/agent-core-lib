"""Service facade for :mod:`agent_core_lib.pii` — one entry point.

The 95% use case is "I have a JSON payload about to leave the
process; make sure no PII goes with it." That's what
:meth:`PiiService.validate` does in one call:

  * scans the payload with the regex pattern set
  * scrubs every match in place
  * returns a new, safe payload

Two optional knobs cover the rest:

  * ``strict=True``  — also runs ``phonenumbers`` + ``dateparser``
    (catches loose phones the regex misses and bare DOBs without a
    keyword anchor).
  * ``raise_on_pii=True`` — raise instead of scrub. For tests / paranoid
    flows where any PII is a contract violation, not a thing to clean up.
  * ``audit_logger`` — when supplied, emits one WARNING per scan that
    finds anything, with the pattern names + redacted previews.

Callers needing the granular surface (single-pattern detection, NER,
category lookups, replacement-mask strategies) import directly from
``agent_core_lib.pii.*`` — the package is the advanced API, the
service is the easy one.
"""
from __future__ import annotations

import logging
from typing import Any, Optional

from agent_core_lib.pii.pii_patterns import (
    PIIPatternFinding,
    find_pii_patterns,
    find_pii_strict,
    summarize_pii_findings,
)
from agent_core_lib.pii.pii_scrub import (
    PIIDetectedError,
    scrub_pii,
)


class PiiService(object):
    """One-call PII validation for any JSON-shaped payload."""

    def validate(
        self,
        payload: Any,
        *,
        strict: bool = False,
        raise_on_pii: bool = False,
        audit_logger: Optional[logging.Logger] = None,
        context: str = 'payload',
    ) -> Any:
        """Validate ``payload`` and return a scrubbed copy.

        Walks the payload recursively (``dict`` / ``list`` / ``tuple`` /
        ``str``), scans every string with the canonical PII pattern set,
        and rewrites matches to ``[redacted:<pattern>]`` placeholders.
        Non-text primitives (``int`` / ``bool`` / ``None`` / dates) pass
        through unchanged. The input is never mutated.

        Args:
            payload: any JSON-shaped value.
            strict: when ``True``, also runs the library-backed
                detectors (``phonenumbers`` for stricter phone parsing,
                ``dateparser`` for bare DOBs without a keyword anchor).
                Costs the two dependencies at runtime.
            raise_on_pii: when ``True``, raise
                :class:`PIIDetectedError` on the first detection instead
                of scrubbing. Useful for tests / hard-gate flows.
            audit_logger: when supplied, emits one ``WARNING`` line on
                any detection with the pattern names + redacted
                previews. The full matched value is never logged.
            context: short label woven into the audit log so operators
                can locate the source (e.g. ``'admin_chat_response'``).

        Returns:
            A new payload with every PII match replaced (when
            ``raise_on_pii=False``). The output is safe to forward to
            the LLM / a log / a downstream service.

        Raises:
            PIIDetectedError: when ``raise_on_pii=True`` and any pattern
                fires. The error message names the matched patterns but
                never echoes the raw matched value.
        """
        findings = self._scan(payload, strict=strict)
        if findings:
            if audit_logger is not None:
                audit_logger.warning(
                    'PII detected in %s: %s',
                    context,
                    summarize_pii_findings(findings),
                )
            if raise_on_pii:
                summary = ', '.join(
                    f'{finding.pattern_name}={finding.redacted_preview}'
                    for finding in findings
                )
                raise PIIDetectedError(f'PII detected in {context}: {summary}')
        return scrub_pii(payload)

    def _scan(self, payload: Any, *, strict: bool) -> list:
        """Walk the payload and return every PII finding.

        Internal helper — :meth:`validate` is the public surface.
        Split out so the strict / non-strict branches stay readable.
        """
        if payload is None:
            return []
        text = self._payload_as_text(payload)
        if strict:
            return find_pii_strict(text)
        return find_pii_patterns(text)

    @staticmethod
    def _payload_as_text(payload: Any) -> str:
        """Coerce ``payload`` into the single string the scan sees.

        Strings pass through; everything else is JSON-serialized with
        ``default=str`` so dates / Decimals / UUIDs don't crash the scan.
        """
        if isinstance(payload, str):
            return payload
        import json
        return json.dumps(payload, default=str, sort_keys=True)
