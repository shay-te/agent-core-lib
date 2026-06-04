"""Bulletproof corpus for the ``email`` PII pattern.

Inputs borrowed from the test fixtures of:

  * Microsoft Presidio's ``email_recognizer`` tests
    (``presidio-analyzer/tests/test_recognizers/test_email_recognizer.py``).
  * scrubadub's ``test_email.py``.
  * RFC 5322 examples + adversarial unicode + display-name variants.

Three corpora live here:

  * ``test_email_positive_corpus`` — 25 hard positives the regex MUST
    catch.
  * ``test_email_negative_corpus`` — 20 inputs that LOOK like emails
    but must NOT be flagged (would be false-positives).
  * ``test_email_in_json_payload`` — 10 nested JSON shapes that
    embed an email at various depths; the structured scrubber must
    surface them via ``find_pii_in_payload``.

Per the workspace-wide "one TestCase per file" rule (see
``architecture.md`` and the matching note in each project's
``AGENTS.md``), this file owns exactly one TestCase.
"""
from __future__ import annotations

import unittest

from agent_core_lib.helpers.pii_patterns import find_pii_patterns
from agent_core_lib.helpers.pii_scrub import find_pii_in_payload


# ---- positive corpus ----------------------------------------------------
# These are the inputs Presidio + scrubadub assert must be detected as
# email. Several are RFC-5322 corners the simpler regex (``\w+@\w+\.\w+``)
# misses; we carry a richer pattern (`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`)
# that catches all of these.
_EMAIL_POSITIVES = (
    # standard
    'john.doe@example.com',
    'jane@example.co.uk',
    'admin@localhost.example',
    # plus-tagged (gmail-style)
    'jane+filter@example.com',
    'name+tag@sub.example.co.uk',
    # underscore + numeric local
    'user_123@example.com',
    'a1b2c3@example.com',
    # dotted host
    'user@e.x.a.m.p.l.e.com',
    # hyphenated host
    'j.doe@example-host.com',
    # short TLD (2-char)
    'me@ab.cd',
    # long TLD (.museum, .photography, .international)
    'me@example.museum',
    'studio@example.photography',
    # ccTLD with subdomain
    'sales@store.example.co.jp',
    # mixed case
    'John.Doe@Example.COM',
    # numeric subdomain
    'noreply@01.example.com',
    # leading + in local
    '+1@example.com',
    # all-digit local
    '12345@example.com',
    # dots in local
    'first.middle.last@example.com',
    # very short local
    'a@example.com',
    # very long local (RFC says ≤64 chars — we accept up to whatever
    # the regex allows; this string is 30)
    'abcdefghijklmnopqrstuvwxyz1234@example.com',
    # apostrophe + hyphen in display-style (the email itself is plain
    # — display-name handling is upstream)
    "o-brien@example.com",
    # embedded in punctuation
    'send to <jane@example.com> please',
    # embedded in sentence
    'reach me at jane@example.com today',
    # multiple emails one line
    'cc both: jane@example.com and john@example.com please',
    # email next to other PII
    'jane@example.com phone 555-1234',
)


# ---- negative corpus ----------------------------------------------------
# These look email-like but must NOT match the ``email`` regex. NOTE:
# the regex is intentionally loose (false positives are acceptable; false
# negatives are not — see ``pii_patterns.py``'s prior-art note), so the
# negatives here are limited to inputs that contain NO valid email-shaped
# substring at all. Strings like ``'jane@inner@example.com'`` would fire
# because they contain the substring ``inner@example.com`` — those are
# documented in ``_EMAIL_DOCUMENTED_OVERMATCHES`` below.
_EMAIL_NEGATIVES = (
    # missing local part
    '@example.com',
    # missing host
    'jane@',
    # missing TLD
    'jane@example',
    # missing dot before TLD
    'jane@examplecom',
    # whitespace inside host
    'jane@example com',
    # multiple @ adjacent (no embedded valid substring)
    'jane@@example.com',
    # TLD too short (1 char)
    'jane@example.c',
    # bare @ symbol on its own
    'use @ symbol carefully',
    # twitter handle (no @ sign followed by host)
    'follow @user_handle on twitter',
    # python decorator
    '@property def foo(): pass',
    # email pasted inside code block but broken
    'jane (at) example (dot) com',
    # ascii art / arrow
    '-->@example<--',
    # IPv6 with @ — not an email
    '::1@host',
    # URL fragment
    'https://example.com/page#section',
    # JSON-style key without quotes
    'name: jane example',
    # bare ampersand context
    'orders & subscriptions',
    # version-pin syntax without TLD-shape ending
    'package@1.0',
    # cron at-sign
    '@hourly run job',
    # @-style mention in code
    '@deprecated since v2',
)


# ---- documented over-matches --------------------------------------------
# Inputs the loose email regex fires on AT LEAST a substring of — we
# accept the false positive because the substring is itself a real
# email-looking shape, and the scrubber will redact it as such. The
# scan ultimately errs on the safe side (overshoot → redact more →
# privacy-positive). Locked here so a future regex tightening that
# breaks these expectations is visible.
_EMAIL_DOCUMENTED_OVERMATCHES = (
    # "jane doe@example.com" — fires on "doe@example.com" substring
    ('jane doe@example.com', 'doe@example.com'),
    # multi-@ — fires on the second valid email-shape
    ('jane@inner@example.com', 'inner@example.com'),
    # leading dot in host — fires on "example.com" substring after the dot
    ('jane@.example.com', 'example.com'),
    # trailing dot — fires on "jane@example.com" with the dot ignored
    ('jane@example.com.', 'jane@example.com'),
    # consecutive dots — fires on "example..com" via the host-chars class
    ('jane@example..com', 'jane@example..com'),
    # package@version syntax where the version trails into a TLD-shape
    # (npm-style ``package@v1.tar.gz``) — fires on the whole thing because
    # ``.gz`` matches ``\.[a-zA-Z]{2,}``. The over-match is safe (we'd
    # rather redact a package id than miss a buried email).
    ('file@v1.tar.gz', 'file@v1.tar.gz'),
)


# ---- JSON payload corpus ------------------------------------------------
# Nested shapes the structured scrubber must walk. Each entry is a
# Python value (dict / list / mixed) with an email at some depth.
_EMAIL_JSON_PAYLOADS = (
    {'email': 'jane@example.com'},
    {'user': {'email': 'jane@example.com'}},
    {'users': [{'email': 'a@b.com'}, {'email': 'c@d.com'}]},
    {'log': 'reach jane@example.com please', 'count': 2},
    [{'id': 1, 'note': 'forward to jane@example.com'}, {'id': 2}],
    {'metadata': {'tags': ['support', 'jane@example.com', 'urgent']}},
    {'admin': {'profile': {'contact': {'email': 'admin@example.com'}}}},
    {'nested': {'list': [{'free_text': 'see jane@example.com'}]}},
    {'comment': "Note from 2024: cc to jane+tag@sub.example.co.uk"},
    {'raw': '{"email": "jane@example.com"}'},  # email inside string-encoded JSON
)


# ---- verbatim third-party corpora ---------------------------------------
# The lists below are copied verbatim from each upstream project's test
# file (linked in the docstring). Provenance matters: the operator's
# instruction was "look at their test files; borrow the inputs". Each
# entry is a real adversarial input that the library's maintainers
# discovered hurts their detector; running our regex against them tells
# us where we agree and where we differ.

# Presidio: presidio-analyzer/tests/test_recognizers/test_email_recognizer.py
# (commit at time of borrow: main branch, microsoft/presidio).
_EMAIL_PRESIDIO_POSITIVES = (
    'info@presidio.site',
    'my email address is info@presidio.site',
    'try one of these emails: info@presidio.site or anotherinfo@presidio.site',
)
_EMAIL_PRESIDIO_NEGATIVES = (
    # Presidio rejects this because the host lacks a TLD; our regex
    # requires ``\.[a-zA-Z]{2,}`` after the host, so we also reject it.
    # Lock the agreement so a future regex relaxation that starts
    # matching ``info@presidio.`` is caught here.
    'my email is info@presidio.',
)

# scrubadub: tests/test_detector_emails.py.
_EMAIL_SCRUBADUB_POSITIVES = (
    'My email is john@gmail.com',
    'My email is John@gmail.com',
    'My email is John1@example.com',
    'My email is adam80@example.info',
    'My email is HELLO@EXAMPLE.COM',
)
# scrubadub's ``test_fancy_john_gmail`` asserts the "at"-spelled form
# resolves to ``john at gmail.com``. Their detector catches it via a
# fuzzy fallback; ours intentionally does not (a literal-only regex on
# the inline gate must not redact every phrase containing the word
# "at"). Locked as a documented MISS so the next maintainer sees the
# gap explicitly — closing it would require a separate fuzzy-form
# detector pass with context anchoring, tracked in pii_patterns.py's
# "Recommendation" block.
_EMAIL_SCRUBADUB_FUZZY_MISSES = (
    'My email is john at gmail.com',
)

# CommonRegex: test.py (madisonmay/CommonRegex master branch).
_EMAIL_COMMONREGEX_POSITIVES = (
    'john.smith@gmail.com',
    'john_smith@gmail.com',
    'john@example.net',
)


class TestEmailBulletproofCorpus(unittest.TestCase):
    """Email detection — 55 inputs spanning positive / negative / JSON."""

    def test_email_positive_corpus(self):
        failures = []
        for text in _EMAIL_POSITIVES:
            found = [f.pattern_name for f in find_pii_patterns(text)]
            if 'email' not in found:
                failures.append(text)
        self.assertEqual(
            failures, [],
            f'email regex missed {len(failures)} positives: {failures}',
        )

    def test_email_negative_corpus(self):
        failures = []
        for text in _EMAIL_NEGATIVES:
            found = [f.pattern_name for f in find_pii_patterns(text)]
            if 'email' in found:
                failures.append(text)
        self.assertEqual(
            failures, [],
            f'email regex false-positive on {len(failures)} inputs: '
            f'{failures}',
        )

    def test_email_in_json_payload(self):
        failures = []
        for payload in _EMAIL_JSON_PAYLOADS:
            found = [f.pattern_name for f in find_pii_in_payload(payload)]
            if 'email' not in found:
                failures.append(payload)
        self.assertEqual(
            failures, [],
            f'email missed in {len(failures)} JSON payload(s): {failures}',
        )

    def test_email_presidio_positive_corpus(self):
        failures = []
        for text in _EMAIL_PRESIDIO_POSITIVES:
            found = [f.pattern_name for f in find_pii_patterns(text)]
            if 'email' not in found:
                failures.append(text)
        self.assertEqual(
            failures, [],
            f'Presidio positive corpus had {len(failures)} miss(es): {failures}',
        )

    def test_email_presidio_negative_corpus(self):
        # Presidio rejects these; assert we agree.
        firings = []
        for text in _EMAIL_PRESIDIO_NEGATIVES:
            found = [f.pattern_name for f in find_pii_patterns(text)]
            if 'email' in found:
                firings.append(text)
        self.assertEqual(
            firings, [],
            f'Presidio rejects these but we fire: {firings}',
        )

    def test_email_scrubadub_positive_corpus(self):
        failures = []
        for text in _EMAIL_SCRUBADUB_POSITIVES:
            found = [f.pattern_name for f in find_pii_patterns(text)]
            if 'email' not in found:
                failures.append(text)
        self.assertEqual(
            failures, [],
            f'scrubadub positive corpus had {len(failures)} miss(es): {failures}',
        )

    def test_email_scrubadub_fuzzy_form_is_known_miss(self):
        # Lock the known gap so a future detector that closes it
        # surfaces the change here (and prompts an update to the
        # follow-up table in pii_patterns.py).
        for text in _EMAIL_SCRUBADUB_FUZZY_MISSES:
            found = [f.pattern_name for f in find_pii_patterns(text)]
            self.assertNotIn(
                'email', found,
                f'unexpected match on fuzzy form {text!r} — the regex '
                f'should not catch the "at" spelling; if a separate '
                f'fuzzy detector is being added, update this lock.',
            )

    def test_email_commonregex_positive_corpus(self):
        failures = []
        for text in _EMAIL_COMMONREGEX_POSITIVES:
            found = [f.pattern_name for f in find_pii_patterns(text)]
            if 'email' not in found:
                failures.append(text)
        self.assertEqual(
            failures, [],
            f'CommonRegex positive corpus had {len(failures)} miss(es): {failures}',
        )

    def test_email_documented_overmatches_still_match(self):
        # The loose regex over-matches on these — that's documented and
        # accepted (privacy-positive). Lock the behaviour so a future
        # tighter regex breaking these is an intentional change, not a
        # silent regression that suddenly stops scrubbing real emails
        # buried in malformed text.
        failures = []
        for input_text, _expected_substring in _EMAIL_DOCUMENTED_OVERMATCHES:
            found = [f.pattern_name for f in find_pii_patterns(input_text)]
            if 'email' not in found:
                failures.append(input_text)
        self.assertEqual(
            failures, [],
            f'documented over-match no longer fires for {len(failures)} '
            f'input(s) — was the email regex tightened? {failures}',
        )


if __name__ == '__main__':
    unittest.main()
