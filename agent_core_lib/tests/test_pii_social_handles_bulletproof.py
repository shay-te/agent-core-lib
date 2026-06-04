"""Bulletproof corpus for the ``instagram_handle`` + ``mastodon_handle``
PII patterns.

Both patterns were called out in ``pii_patterns.py``'s prior-art
block as one-line follow-ups to the existing Twitter / Skype detectors
(scrubadub-borrowed) — landed here in the validator-dispatch follow-up
that closed the Luhn / SSN-area / mod-97 / ABA / VIN / IL-id gaps.

The two handles are tested together in one file (one TestCase per
detector class, per the workspace rule) because they share the
``@handle`` shape vocabulary and trip many of the same collision
risks (email host clipping, generic identifier collision).
"""
from __future__ import annotations

import unittest

from agent_core_lib.helpers.pii_patterns import find_pii_patterns
from agent_core_lib.helpers.pii_scrub import find_pii_in_payload


# --- Instagram handle ------------------------------------------------------

_INSTAGRAM_POSITIVES = (
    'instagram @jane_doe shared a post',
    'follow me on Instagram: @jane.doe',
    'IG @jane_doe_123 was tagged',
    'insta @j_doe',
    # mixed case keyword
    'Instagram: @JANE_DOE here',
    # at start
    'instagram @user_name posts daily',
    # inside parens
    'check the source (instagram @news_account) please',
    # with colon
    'instagram: @brand_handle',
)

# Keyword absent — the detector intentionally requires it (a bare
# ``@handle`` belongs to the ``twitter_handle`` family, not Instagram).
_INSTAGRAM_NEGATIVES = (
    '@jane_doe shared a post',  # no keyword
    'twitter @jane_doe',         # wrong keyword
    'instagram is great',        # no @ handle
    'see https://example.com',   # narrative, no handle
)


# --- Mastodon handle -------------------------------------------------------

_MASTODON_POSITIVES = (
    'reply from @jane@mastodon.social today',
    'follow @user@fediverse.example for updates',
    # multiple handles
    'see @alice@mastodon.example and @bob@fediverse.example for the thread',
    # inside parens
    '(thread starter @news@masto.host)',
    # at start
    '@admin@instance.example replied',
    # with subdomain
    '@jane@sub.mastodon.example posted',
)

# Anything without the two-``@`` shape: bare emails, single-``@``
# Twitter handles, narrative text.
_MASTODON_NEGATIVES = (
    'jane@example.com',         # email, not Mastodon
    '@jane_doe',                 # Twitter
    'mastodon is a federated network',
    'see https://mastodon.social/about',
)


_JSON_PAYLOADS_INSTAGRAM = (
    {'note': 'instagram @news_account confirmed'},
    {'profile': {'ig': 'IG @brand_handle here'}},
    [{'id': 1, 'comment': 'follow Instagram: @user_name'}],
)

_JSON_PAYLOADS_MASTODON = (
    {'note': 'mention @jane@mastodon.social today'},
    {'profile': {'fedi': '@admin@instance.example'}},
    [{'id': 1, 'thread_starter': '@alice@masto.host posted'}],
)


class TestInstagramHandleBulletproofCorpus(unittest.TestCase):
    def test_instagram_positive_corpus(self):
        failures = [
            text for text in _INSTAGRAM_POSITIVES
            if 'instagram_handle' not in
            {f.pattern_name for f in find_pii_patterns(text)}
        ]
        self.assertEqual(failures, [], f'missed {len(failures)}: {failures}')

    def test_instagram_negative_corpus(self):
        failures = [
            text for text in _INSTAGRAM_NEGATIVES
            if 'instagram_handle' in
            {f.pattern_name for f in find_pii_patterns(text)}
        ]
        self.assertEqual(
            failures, [],
            f'false-positive on {len(failures)}: {failures}',
        )

    def test_instagram_in_json_payload(self):
        failures = [
            payload for payload in _JSON_PAYLOADS_INSTAGRAM
            if 'instagram_handle' not in
            {f.pattern_name for f in find_pii_in_payload(payload)}
        ]
        self.assertEqual(failures, [], f'missed in JSON: {failures}')


class TestMastodonHandleBulletproofCorpus(unittest.TestCase):
    def test_mastodon_positive_corpus(self):
        failures = [
            text for text in _MASTODON_POSITIVES
            if 'mastodon_handle' not in
            {f.pattern_name for f in find_pii_patterns(text)}
        ]
        self.assertEqual(failures, [], f'missed {len(failures)}: {failures}')

    def test_mastodon_negative_corpus(self):
        failures = [
            text for text in _MASTODON_NEGATIVES
            if 'mastodon_handle' in
            {f.pattern_name for f in find_pii_patterns(text)}
        ]
        self.assertEqual(
            failures, [],
            f'false-positive on {len(failures)}: {failures}',
        )

    def test_mastodon_in_json_payload(self):
        failures = [
            payload for payload in _JSON_PAYLOADS_MASTODON
            if 'mastodon_handle' not in
            {f.pattern_name for f in find_pii_in_payload(payload)}
        ]
        self.assertEqual(failures, [], f'missed in JSON: {failures}')


if __name__ == '__main__':
    unittest.main()
