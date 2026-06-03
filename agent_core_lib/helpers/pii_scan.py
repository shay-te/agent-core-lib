"""Shared output-side PII scan for agent text streams.

Parallel to :mod:`agent_core_lib.helpers.credential_scan` — the
credential scan WARNING-logs vendor-issued secret patterns that leaked
into agent output; this scan does the same for personal data (email,
SSN, phone, credit card, IBAN). Both are detective-only — by the time
the agent's text is being scanned, it has already crossed to / from the
model provider, so the log line is an auditable record (rotate /
respond), never a block.

Pattern names + redacted previews are logged; the raw matched value is
never logged. The patterns themselves live in
:mod:`agent_core_lib.helpers.pii_patterns` — the workspace's single
source of truth (``llm-core-lib`` no longer carries a copy; its safety
subpackage owns only the *structural* defenses — ``LLMView`` +
``to_llm_payload`` — and leaves regex PII detection to this module).
"""

from __future__ import annotations


def scan_text_for_pii(
    text: str,
    *,
    logger,
    context_label: str,
) -> None:
    """WARNING-log PII patterns found in ``text``.

    ``context_label`` is the descriptor woven into the WARNING message
    (e.g. ``'Claude response for triage investigation'`` or
    ``'streaming agent session for task PROJ-1'``). Blank ``text`` is a
    no-op.

    This is a detective audit step — the agent text has already
    transmitted by the time this fires. Use it to detect the leak,
    not to prevent it; prevention belongs at the data-shaping layer
    (typed views with allowlisted fields, scrubbing before string
    interpolation).
    """
    from agent_core_lib.helpers.pii_patterns import (
        find_pii_patterns,
        summarize_pii_findings,
    )

    if not text:
        return
    findings = find_pii_patterns(text)
    if findings:
        logger.warning(
            'PII PATTERN DETECTED in %s: %s. '
            'The agent text has already been transmitted; treat as an '
            'audit signal that the prevention layer (typed LLM views / '
            'scrubbing) missed something. The structural defense lives '
            'in llm-core-lib (llm_core_lib.safety: LLMView + '
            'to_llm_payload); regex-level scrubbing of structured '
            'payloads lives in agent_core_lib.helpers.pii_scrub.',
            context_label,
            summarize_pii_findings(findings),
        )
