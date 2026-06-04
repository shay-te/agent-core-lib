"""Contact-PII patterns (email / phone / social handles / URLs).

Aggregated into the public ``_PII_PATTERNS`` tuple by
:mod:`agent_core_lib.pii.pii_patterns`. Declaration
order matters (overlap resolver in the scrubber picks the
first-declared span on a tie); the order inside this file
feeds the aggregator in the same sequence.
"""
from __future__ import annotations

import re


PATTERNS = (
    # --- contact ------------------------------------------------------
    # URL — borrowed from scrubadub's ``UrlDetector`` (see prior-art note
    # above). High-value because URLs routinely carry PII in path /
    # query (``/user/123/email/jane@example.com``, ``?reset_token=...``).
    # Restricted to http/https schemes on purpose: mailto: would
    # double-match the email pattern below and provide no extra value
    # over the existing email finding. Declared BEFORE ``email`` so the
    # scrubber's overlap resolver (first-declared wins on equal-start
    # spans, longer wins via the sort key) keeps the URL span when an
    # email is embedded in a URL (``https://host/u/jane@example.com``).
    # URL scheme is case-insensitive per RFC 3986 §3.1; path/query stay
    # case-sensitive but the regex doesn't need to distinguish that —
    # ``re.IGNORECASE`` only affects ASCII letter matching in the
    # scheme prefix here.
    ('url', re.compile(r'https?://[^\s<>"\']+', re.IGNORECASE)),
    ('email', re.compile(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}')),
    # E.164-ish phone numbers: optional leading +, 10+ digits with
    # optional separators. Tighter than the previous form so a card
    # number doesn't double-match here.
    ('phone', re.compile(r'\+?\d[\d \-().]{8,}\d')),
    # Twitter / Mastodon-style handle — borrowed from scrubadub's
    # ``TwitterDetector``. Positive predecessor list (string start or
    # ascii whitespace / punctuation) — a *negative* lookbehind would
    # incorrectly treat invisible Unicode separators (U+200B etc.) as
    # "not an email char" and silently misclassify zero-width-split
    # obscured emails (``jane<U+200B>@example.com``) as Twitter handles.
    # See ``test_pii_adversarial.test_miss_email_with_zero_width_split``.
    ('twitter_handle', re.compile(
        r'(?:^|(?<=[ \t\n\r(\[,;:]))@[A-Za-z0-9_]{3,15}\b'
    )),
    # Skype handle — borrowed from scrubadub's ``SkypeDetector``. The
    # unlabelled form would collide with too many random identifiers,
    # so we anchor on the ``skype`` keyword (case-insensitive,
    # whitespace/colon separator).
    ('skype_handle', re.compile(
        r'\bskype[\s:]+[A-Za-z][A-Za-z0-9.\-_]{5,31}\b',
        re.IGNORECASE,
    )),
    # Instagram handle — keyword-anchored ``@name``. The ``@`` is
    # required (a keyword alone with narrative text — e.g.
    # ``instagram is great`` — is not a handle). Length cap 1-30
    # matches Instagram's username spec. Declared after ``twitter_handle``
    # so a keyword-less ``@name`` falls to the Twitter detector.
    ('instagram_handle', re.compile(
        r'\b(?:instagram|insta|ig)[\s:@]+@[A-Za-z0-9_.]{1,30}\b',
        re.IGNORECASE,
    )),
    # Mastodon handle — ``@user@instance.example`` (two ``@`` signs,
    # the second separating the local part from the federated host).
    # The shape is distinct enough from email that the per-pattern
    # collision resolver in ``pii_scrub`` keeps the right span; we
    # still declare it AFTER ``email`` so a bare ``user@host`` is
    # treated as email rather than partial Mastodon. The lookbehind
    # set includes ``"`` and ``'`` so the handle still matches when
    # the surrounding payload was JSON-serialized.
    ('mastodon_handle', re.compile(
        r'(?:^|(?<=[ \t\n\r(\[,;:"\']))'
        r'@[A-Za-z0-9_]{1,30}@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}'
    )),

    # --- additional social handles ------------------------------------
    ('linkedin_url', re.compile(
        r'\bhttps?://(?:www\.)?linkedin\.com/in/[A-Za-z0-9_\-]{3,100}\b',
        re.IGNORECASE,
    )),
    ('github_url', re.compile(
        r'\bhttps?://(?:www\.)?github\.com/[A-Za-z0-9](?:[A-Za-z0-9\-]{0,38})\b',
        re.IGNORECASE,
    )),
    # Discord snowflake — 17-19 digit ID, keyword anchor.
    ('discord_id', re.compile(
        r'\bdiscord\s*(?:id|user)?\s*[:=]?\s*\d{17,19}\b',
        re.IGNORECASE,
    )),
    ('telegram_handle', re.compile(
        r'\b(?:t\.me/|telegram[:\s]+@?)[A-Za-z][A-Za-z0-9_]{4,31}\b',
        re.IGNORECASE,
    )),
    ('tiktok_handle', re.compile(
        r'\bhttps?://(?:www\.)?tiktok\.com/@[A-Za-z0-9_.]{2,24}\b',
        re.IGNORECASE,
    )),

)
