"""Bulletproof corpus for the ``url`` PII pattern.

Test inputs borrowed from:

  * Presidio's URL recognizer tests + TLDExtract test set.
  * scrubadub's ``test_url.py``.
  * RFC 3986 examples (URI scheme/authority/path/query/fragment).
  * Real-world ``?email=...`` / ``?reset_token=...`` shapes (URLs are
    the canonical leakage vector for query-string PII).
"""
from __future__ import annotations

import unittest

from agent_core_lib.helpers.pii_patterns import find_pii_patterns
from agent_core_lib.helpers.pii_scrub import find_pii_in_payload


_POSITIVES = (
    'https://example.com',
    'http://example.com',
    'https://example.com/',
    'https://example.com/path',
    'https://example.com/path/to/resource',
    'https://example.com:8080/admin',
    'https://example.com/u/42/reset',
    'https://example.com/?reset_token=abc123',
    'https://example.com/?email=jane%40example.com',
    'https://example.com/user/123/email/jane@example.com',
    'https://sub.example.com',
    'https://very.deeply.nested.subdomain.example.com',
    # punycode IDN
    'https://xn--bcher-kva.example/',
    # uppercase scheme
    'HTTPS://Example.COM/path',
    # port + path + query + fragment
    'https://example.com:443/api?v=1&user=jane#section',
    # in narrative
    'click https://example.com to confirm',
    'see https://example.com/path?x=1 today',
    'visit https://example.com/u/42 then return',
    'log: GET https://api.example.com/v1/users',
    'redirect to https://example.com/auth?code=xyz',
)


_NEGATIVES = (
    # bare hostname (no scheme)
    'example.com',
    # FTP (we restrict to http/https on purpose; ftp could be added)
    'ftp://example.com/file',
    # mailto (would double-fire with email)
    'mailto:jane@example.com',
    # tel: scheme
    'tel:+1-212-555-1234',
    # path only
    '/user/42/profile',
    # narrative without URL
    'click the link below please',
    # bare scheme without authority
    'https://',
    # http: without slashes
    'http:example.com',
    # not a URL — embedded path-like text
    'see /etc/hosts',
)


_JSON_PAYLOADS = (
    {'url': 'https://example.com/path'},
    {'event': {'href': 'https://example.com/click?token=abc'}},
    [{'id': 1, 'link': 'https://example.com/page'}],
    {'log': 'GET https://example.com/api/v1 OK'},
    {'webhook': {'callback_url': 'https://example.com/cb'}},
    {'nested': {'list': [{'url': 'https://example.com/a'}]}},
    {'free_text': 'see https://example.com/u/42 for the report'},
    {'tags': ['urgent', 'https://example.com/dashboard']},
    {'oauth': {'redirect_uri': 'https://example.com/callback?state=abc'}},
    {'comment': 'reset link sent: https://example.com/r?token=xyz'},
)


# ---- verbatim third-party corpora ---------------------------------------
# Our URL regex is intentionally scheme-anchored (``https?://...``) so
# we don't redact every bare ``foo.bar`` mention in chat output. The
# Presidio + CommonRegex corpora include bare-domain forms that we
# don't catch — those are documented misses, tracked under
# "DomainRecognizer" in pii_patterns.py's Presidio scan.

# Presidio: presidio-analyzer/tests/test_recognizers/test_url_recognizer.py.
_URL_PRESIDIO_POSITIVES = (
    'https://www.microsoft.com/',
    'http://www.microsoft.com/',
    'http://www.microsoft.com',
    'http://microsoft.com',
    'http://microsoft.site',
    'http://microsoft.webcam',
    'http://microsoft.vlaanderen',
    'https://webhook.site/a8eedfd6-9d8a-44e0-b0fc-cc7d517db5dc?q=1&b=2',
    'https://www.microsoft.com/store/abc/',
    '"https://microsoft.github.io/presidio/"',
    "'https://microsoft.github.io/presidio/'",
)
_URL_PRESIDIO_BARE_DOMAINS_WE_MISS = (
    'microsoft.com',
    'my domains: microsoft.com google.co.il',
)
_URL_PRESIDIO_NEGATIVES_WE_ALSO_REJECT = (
    'www.microsoft',
    "'www.microsoft'",
)
# Presidio rejects ``http://microsoft`` (TLD-less). We fire because our
# scheme-anchored regex doesn't require a TLD. Documented over-match.
_URL_PRESIDIO_NEGATIVE_WE_FIRE = (
    'http://microsoft',
)

# scrubadub: tests/test_detector_urls.py.
_URL_SCRUBADUB_POSITIVES = (
    'http://bit.ly/aser is neat',
    'https://bit.ly/aser is neat',
    'https://this.is/a/long?url=very#url is good',
    'http://bit.ly/number-one http://www.google.com/two',
    'Find jobs at http://facebook.com/jobs',
    'http://public.com/this/is/very/private',
    'http://public.com/',
)
_URL_SCRUBADUB_WWW_FORM_WE_MISS = (
    'www.bit.ly/aser is neat',
)

# CommonRegex: test.py.
_URL_COMMONREGEX_POSITIVES = (
    'http://www.google.com',
    'http://www.google.com/%&#/?q=dog',
)
_URL_COMMONREGEX_BARE_DOMAINS_WE_MISS = (
    'www.google.com',
    'sub.example.com',
    'google.com',
)


class TestUrlBulletproofCorpus(unittest.TestCase):
    def test_url_positive_corpus(self):
        failures = [
            text for text in _POSITIVES
            if 'url' not in {f.pattern_name for f in find_pii_patterns(text)}
        ]
        self.assertEqual(failures, [], f'missed {len(failures)}: {failures}')

    def test_url_negative_corpus(self):
        failures = [
            text for text in _NEGATIVES
            if 'url' in {f.pattern_name for f in find_pii_patterns(text)}
        ]
        self.assertEqual(failures, [], f'false-positive on {len(failures)}: {failures}')

    def test_url_presidio_positive_corpus(self):
        failures = [
            text for text in _URL_PRESIDIO_POSITIVES
            if 'url' not in {f.pattern_name for f in find_pii_patterns(text)}
        ]
        self.assertEqual(failures, [], f'Presidio missed: {failures}')

    def test_url_presidio_bare_domains_are_known_misses(self):
        firings = [
            text for text in _URL_PRESIDIO_BARE_DOMAINS_WE_MISS
            if 'url' in {f.pattern_name for f in find_pii_patterns(text)}
        ]
        self.assertEqual(
            firings, [],
            f'bare-domain forms now matching — {firings} — was a '
            f'DomainRecognizer added? Update the lock + the follow-up '
            f'table in pii_patterns.py.',
        )

    def test_url_presidio_negatives_we_agree(self):
        firings = [
            text for text in _URL_PRESIDIO_NEGATIVES_WE_ALSO_REJECT
            if 'url' in {f.pattern_name for f in find_pii_patterns(text)}
        ]
        self.assertEqual(firings, [], f'now matching: {firings}')

    def test_url_presidio_tld_less_documented_overmatch(self):
        failures = [
            text for text in _URL_PRESIDIO_NEGATIVE_WE_FIRE
            if 'url' not in {f.pattern_name for f in find_pii_patterns(text)}
        ]
        self.assertEqual(
            failures, [],
            f'documented over-match no longer fires — was a TLD '
            f'requirement added to the URL regex? Update the lock.',
        )

    def test_url_scrubadub_positive_corpus(self):
        failures = [
            text for text in _URL_SCRUBADUB_POSITIVES
            if 'url' not in {f.pattern_name for f in find_pii_patterns(text)}
        ]
        self.assertEqual(failures, [], f'scrubadub missed: {failures}')

    def test_url_scrubadub_www_form_is_known_miss(self):
        firings = [
            text for text in _URL_SCRUBADUB_WWW_FORM_WE_MISS
            if 'url' in {f.pattern_name for f in find_pii_patterns(text)}
        ]
        self.assertEqual(firings, [], f'www-form now matching: {firings}')

    def test_url_commonregex_positive_corpus(self):
        failures = [
            text for text in _URL_COMMONREGEX_POSITIVES
            if 'url' not in {f.pattern_name for f in find_pii_patterns(text)}
        ]
        self.assertEqual(failures, [], f'CommonRegex missed: {failures}')

    def test_url_commonregex_bare_domains_are_known_misses(self):
        firings = [
            text for text in _URL_COMMONREGEX_BARE_DOMAINS_WE_MISS
            if 'url' in {f.pattern_name for f in find_pii_patterns(text)}
        ]
        self.assertEqual(firings, [], f'bare-domain now matching: {firings}')

    def test_url_in_json_payload(self):
        failures = [
            payload for payload in _JSON_PAYLOADS
            if 'url' not in {f.pattern_name for f in find_pii_in_payload(payload)}
        ]
        self.assertEqual(failures, [], f'missed in JSON: {failures}')


if __name__ == '__main__':
    unittest.main()
