"""PII pattern detector — single source of truth for the workspace.

Parallel to ``credential_patterns`` (credential_patterns hunts
vendor-issued secrets; this module hunts personal data). Every
PII-scanning helper across the workspace — ``helpers/pii_scan`` for
text streams, ``helpers/pii_scrub`` for structured payloads, the chat
service's tool-result sanitizer in ``ob-love-admin-backend`` — pulls
its pattern set from here. There is no second copy in
``llm-core-lib``; the structural defense over there (``LLMView``,
``to_llm_payload``) enforces *types*, while regex-level PII detection
lives here.

The set is deliberately broad — false positives are acceptable (the
runtime scrubber and the audit-log helper both tolerate them; the test
suite uses :class:`PIIDetectedError` to lock the contract); false
negatives are not. When in doubt, add a pattern. The named families
below are an attempt at "don't forget a single thing":

  * **Contact** — email, phone (US + international E.164-ish).
  * **Government IDs (US)** — SSN, ITIN, EIN, passport, driver's
    license, Medicare beneficiary id.
  * **Government IDs (intl)** — UK / CA / AU passport, UK NI number.
  * **Financial** — credit card (13–19 digits), CVV-in-context,
    IBAN, SWIFT/BIC, US routing number, US bank account, bitcoin
    address.
  * **Postal** — US ZIP, US ZIP+4, UK postcode, CA postcode.
  * **Network / device** — IPv4, IPv6, MAC address.
  * **Vehicle** — VIN, US license plate.
  * **Address** — US street-address shape (number + street + suffix);
    best-effort, regex can't catch every postal shape so the
    *primary* address defense is the typed-view allowlist in
    ``llm-core-lib`` (``LLMView`` subclasses simply don't declare an
    address field unless the value has already been scrubbed).
  * **Temporal** — date-of-birth shapes (ISO, US, EU).

Address detection is intentionally regex-supported even though the
allowlist is the real defense — the reviewer's note "make it
extensive, don't forget a single thing" trumps the regex-purity
argument; a noisy street-address pattern that flags
``742 Evergreen Terrace`` is a net win over silently missing it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable, List, Tuple


@dataclass(frozen=True)
class PIIPatternFinding(object):
    """One match of a named PII pattern; the full matched value is never returned."""

    pattern_name: str
    redacted_preview: str


# ---------------------------------------------------------------------------
# Prior-art note — open-source PII detection landscape (2025 survey)
# ---------------------------------------------------------------------------
#
# Before extending this file (especially before adding a new dependency for
# PII), read this. We deliberately kept the implementation as a hand-rolled
# regex set + structured scrubber rather than depending on a third-party
# library. Below is what we evaluated and what's worth borrowing.
#
# Projects surveyed (all permissive licenses, all Python):
#
#   * Microsoft Presidio (github.com/microsoft/presidio, MIT, ~4.5k stars,
#     actively maintained). Hybrid regex + NER (spaCy by default), pluggable
#     ``RecognizerRegistry``, context-word boosting, confidence scoring,
#     anonymizer "operators" (replace / mask / hash / encrypt / redact),
#     checksum validators (Luhn / IBAN mod-97 / ABA). Heavy: spaCy + language
#     model balloons install to ~500MB-1.5GB and cold-start is ~1-3s. Wrong
#     tradeoff for a per-tool-call boundary — the gate must be cheap.
#   * scrubadub (github.com/LeapBeyond/scrubadub, Apache 2.0, ~1.9k stars,
#     slow cadence). Clean ``Detector`` / ``Filth`` typed-result design with
#     a ``PostProcessor`` chain for overlap merging. Lightweight core; NER
#     behind extras. Fewer built-in families than our 30 — adopting it would
#     mean rewriting our detectors against its API for marginal gain.
#   * CommonRegex (github.com/madisonmay/CommonRegex, MIT, ~1.7k stars,
#     unmaintained since 2021). Pure-regex grab-bag. Not a library to
#     adopt — mine its US-street-address and time-of-day patterns to
#     cross-check ours.
#   * pii-codex (github.com/EdyVision/pii-codex, BSD-3, ~150 stars). Thin
#     wrapper over Presidio that adds a PII taxonomy / severity tiering
#     layer (financial / health / government-ID / contact). Inherits
#     Presidio's weight; not worth adopting, but the tiering idea is.
#   * datafog (MIT, ~250 stars, newer). Presidio-style hybrid, lighter,
#     async-friendly — too small a community to bet on yet.
#   * Protect AI's pii-detection-anonymizer (transformer-based, DeBERTa).
#     Higher recall on names / locations, but a transformer in the inline
#     scrub path is the wrong place — too heavy.
#
# Recommendation — keep the hand-rolled approach, borrow four techniques
# as small follow-up improvements (not blocking this PR):
#
#   1. **Checksum validators behind the patterns that have them** —
#      Luhn for credit cards, mod-97 for IBAN, ABA routing checksum, VIN
#      check digit, SSN area-number exclusions. Kills the bulk of regex
#      false positives at near-zero runtime cost. Presidio does this; the
#      pattern is "regex matches, then a validator function on the match
#      group decides keep/drop". Easy to bolt on per-pattern here without
#      restructuring the tuple.
#   2. **Context-word boosting / confidence scoring** — a 9-digit match
#      near "SSN", "social", "tax id" is high-confidence; isolated, it's
#      borderline. Today every match fires equally; a confidence score per
#      finding would let the choke point distinguish "definitely PII"
#      (assert/raise) from "probably PII" (scrub-and-log). Presidio's idea.
#   3. **scrubadub's ``Filth`` typed-detector shape** — each detector
#      yields ``(span, type, confidence, detector_name)``. Our scrubber
#      already collects spans for non-overlapping replacement (see
#      ``_scrub_string`` in pii_scrub.py); promoting that to a typed
#      ``Filth`` record would let the resolver use confidence in addition
#      to (start, length) when picking among overlapping matches.
#   4. **pii-codex severity tiers** — tag each pattern family with a
#      category (``government_id``, ``financial``, ``contact``, ``network``,
#      ``address``, ``temporal``) so the payload gate can apply different
#      policies per tier (e.g., never log a ``government_id`` match even
#      in DEBUG; allow ``contact`` matches in admin-confirming views like
#      ``LLMSendEmailResultView``). Conceptual change to the tuple shape,
#      not regex changes.
#
# Re-evaluate Presidio specifically if/when we need NER for free-text
# names / orgs / locations — those simply can't be regex'd and Presidio
# is the mature answer. Run it out-of-process if we go there, so the
# spaCy load cost doesn't sit on every chat tool call.
# ---------------------------------------------------------------------------


_PII_PATTERNS: Tuple[Tuple[str, re.Pattern[str]], ...] = (
    # --- contact ------------------------------------------------------
    ('email', re.compile(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}')),
    # E.164-ish phone numbers: optional leading +, 10+ digits with
    # optional separators. Tighter than the previous form so a card
    # number doesn't double-match here.
    ('phone', re.compile(r'\+?\d[\d \-().]{8,}\d')),

    # --- US government IDs --------------------------------------------
    ('ssn', re.compile(r'\b\d{3}-\d{2}-\d{4}\b')),
    # ITIN: 9XX-7X-XXXX or 9XX-8X-XXXX (the 4th digit is 7 or 8).
    ('itin', re.compile(r'\b9\d{2}-[78]\d-\d{4}\b')),
    # EIN: XX-XXXXXXX
    ('ein', re.compile(r'\b\d{2}-\d{7}\b')),
    # US passport book: 9 digits (newer issues), with optional leading letter.
    ('us_passport', re.compile(r'\b[A-Z]?\d{9}\b')),
    # US driver's license — varies wildly by state; flag the common
    # "1 letter + 7 digits" shape (CA, FL, etc.) and the "8 digit"
    # shape used by several states.
    ('us_drivers_license', re.compile(r'\b[A-Z]\d{7}\b|\b\d{8}\b')),
    # Medicare Beneficiary Identifier (MBI), post-2018 format:
    # 1 numeric + 1 alpha + 1 alphanumeric + 1 numeric + 1 alpha +
    # 1 alphanumeric + 1 numeric + 2 alpha + 2 numeric.
    ('medicare_mbi', re.compile(
        r'\b[1-9][A-Z][A-Z\d][\d]-?[A-Z][A-Z\d][\d]-?[A-Z]{2}\d{2}\b'
    )),

    # --- international government IDs ---------------------------------
    # UK National Insurance number.
    ('uk_nino', re.compile(
        r'\b[A-CEGHJ-PR-TW-Z][A-CEGHJ-NPR-TW-Z]\d{6}[A-D]\b'
    )),
    # UK passport: 9 digits.
    ('uk_passport', re.compile(r'\b\d{9}\b')),
    # Canadian passport: 2 letters + 6 digits.
    ('ca_passport', re.compile(r'\b[A-Z]{2}\d{6}\b')),
    # Australian passport: 1 letter + 7 digits.
    ('au_passport', re.compile(r'\b[A-Z]\d{7}\b')),

    # --- financial ----------------------------------------------------
    # 13–19 digit card numbers, with optional space or dash separators.
    # Doesn't validate the Luhn checksum — that's a job for the
    # scrubber's caller, not the detector.
    ('credit_card', re.compile(r'\b(?:\d[ \-]?){13,19}\b')),
    # CVV in obvious context: "cvv 123", "cvc: 1234", "security code 123".
    ('credit_card_cvv', re.compile(
        r'\b(?:cvv|cvc|security\s+code)\s*[:=]?\s*\d{3,4}\b',
        re.IGNORECASE,
    )),
    # IBAN: 2-letter country, 2-digit check, 11-30 alphanumerics.
    ('iban', re.compile(r'\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b')),
    # SWIFT / BIC: 4 letters + 2 letters + 2 alphanumeric +
    # optional 3 alphanumeric.
    ('swift_bic', re.compile(r'\b[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}(?:[A-Z0-9]{3})?\b')),
    # US ABA routing number: 9 digits, usually whitespace-separated.
    ('us_routing_number', re.compile(r'\b\d{9}\b')),
    # US bank account: 4-17 digits, usually labelled. Match labelled form.
    ('us_bank_account', re.compile(
        r'\b(?:account|acct)[\s#:]*\d{4,17}\b',
        re.IGNORECASE,
    )),
    # Bitcoin address: legacy (1...), p2sh (3...), bech32 (bc1...).
    ('bitcoin_address', re.compile(
        r'\b(?:bc1[a-zA-HJ-NP-Z0-9]{25,87}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b'
    )),

    # --- postal -------------------------------------------------------
    # US ZIP (5) and ZIP+4 (5+4). Common but PII when combined with name.
    ('us_zip', re.compile(r'\b\d{5}(?:-\d{4})?\b')),
    # UK postcode: AA9A 9AA / A9A 9AA / A9 9AA / A99 9AA / AA9 9AA / AA99 9AA.
    ('uk_postcode', re.compile(
        r'\b[A-Z]{1,2}\d[A-Z\d]?\s*\d[A-Z]{2}\b'
    )),
    # Canadian postcode: A1A 1A1.
    ('ca_postcode', re.compile(r'\b[A-Z]\d[A-Z]\s*\d[A-Z]\d\b')),

    # --- network / device --------------------------------------------
    ('ipv4', re.compile(
        r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}'
        r'(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
    )),
    # IPv6: simplified — full or compressed forms.
    ('ipv6', re.compile(
        r'\b(?:[A-F0-9]{1,4}:){2,7}[A-F0-9]{1,4}\b',
        re.IGNORECASE,
    )),
    # MAC address: 6 hex pairs separated by ``:`` or ``-``.
    ('mac_address', re.compile(
        r'\b(?:[0-9A-F]{2}[:\-]){5}[0-9A-F]{2}\b',
        re.IGNORECASE,
    )),

    # --- vehicle ------------------------------------------------------
    # VIN: 17 alphanumerics, no I/O/Q.
    ('vin', re.compile(r'\b[A-HJ-NPR-Z0-9]{17}\b')),
    # US license plate: very loose — 5-8 alphanumerics with at least
    # one digit. Best-effort; tighten per-state if false positives bite.
    ('us_license_plate', re.compile(
        r'\b(?=[A-Z0-9 \-]{5,8}\b)[A-Z0-9]+[ \-]?[A-Z0-9]+\b'
    )),

    # --- address ------------------------------------------------------
    # US street address shape: leading street number + words + a common
    # suffix (St, Ave, Blvd, Rd, Ln, Dr, Ct, Pl, Way, Pkwy, Ter, Cir,
    # Sq, Trl, Hwy, Highway, Avenue, Street, Boulevard, Road, Lane,
    # Drive, Court, Place, Parkway, Terrace, Circle, Square, Trail).
    ('street_address', re.compile(
        r'\b\d{1,6}\s+(?:[A-Za-z0-9.\-\']+\s+){0,5}'
        r'(?:Street|St|Avenue|Ave|Boulevard|Blvd|Road|Rd|Lane|Ln|'
        r'Drive|Dr|Court|Ct|Place|Pl|Way|Parkway|Pkwy|Terrace|Ter|'
        r'Circle|Cir|Square|Sq|Trail|Trl|Highway|Hwy)\b\.?',
        re.IGNORECASE,
    )),
    # PO Box.
    ('po_box', re.compile(r'\bP\.?\s*O\.?\s*Box\s+\d+\b', re.IGNORECASE)),

    # --- temporal -----------------------------------------------------
    # Date-of-birth in obvious context: "dob 1990-01-01", "date of birth 01/01/1990".
    ('date_of_birth', re.compile(
        r'\b(?:dob|date\s+of\s+birth|birthday|born)\s*[:=]?\s*'
        r'(?:\d{4}[-/]\d{1,2}[-/]\d{1,2}|\d{1,2}[-/]\d{1,2}[-/]\d{2,4})\b',
        re.IGNORECASE,
    )),
)


PII_PATTERN_NAMES: frozenset = frozenset(name for name, _ in _PII_PATTERNS)


def _redact(matched_text: str) -> str:
    prefix_len = min(4, len(matched_text))
    return f'{matched_text[:prefix_len]}…[REDACTED, len={len(matched_text)}]'


def find_pii_patterns(text: str) -> List[PIIPatternFinding]:
    """Return every named PII pattern matched in ``text``.

    The raw matched value is never returned — callers receive only the
    pattern name and a redacted preview that is safe to log. Pattern
    order is fixed (declaration order), so cross-test assertions on
    ``findings[0]`` stay stable.
    """
    if not text or not isinstance(text, str):
        return []
    findings: List[PIIPatternFinding] = []
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


def iter_pattern_names_and_regexes() -> Iterable[Tuple[str, re.Pattern[str]]]:
    """Expose the underlying ``(name, regex)`` pairs for callers that
    need to scrub text in place (see :mod:`pii_scrub`). Iteration order
    is the declaration order, which the scrubber relies on for
    deterministic output."""
    return _PII_PATTERNS
