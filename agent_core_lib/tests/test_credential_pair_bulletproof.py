"""Bulletproof corpus for the ``credential_pair`` credential pattern.

Borrowed from scrubadub's ``CredentialDetector``. Catches the
``username: foo, password: bar``-shaped leaks that show up in:

  * config files (YAML, properties, .env)
  * JSON request / response bodies
  * URL query strings (``?username=...&password=...``)
  * narrative tool output (``the login is admin and the password is
    hunter2``)

The point isn't to extract the password — the finding records that a
pair was present and the audit WARNING fires. The full matched value
is never logged (see :func:`agent_core_lib.helpers.credential_patterns._redact`).
"""
from __future__ import annotations

import unittest

from agent_core_lib.helpers.credential_patterns import find_credential_patterns


_POSITIVES = (
    # config-style
    'username: admin password: hunter2',
    'username=admin password=hunter2',
    'login: root pwd: changeme',
    # JSON-ish
    '"username":"admin","password":"hunter2"',
    "'username':'admin','password':'hunter2'",
    # URL query string
    'user=admin&password=hunter2',
    # mixed-case keyword
    'Username: jane Password: hunter42',
    # named fields with surrounding noise
    '{ user: alice; passwd: shh-secret; role: admin }',
)


_NEGATIVES = (
    # narrative, no actual pair
    'we processed the username today',
    'remember to change your password regularly',
    # JWT / token alone (not a pair)
    'token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9',
    # username alone
    'username: admin',
    # password alone
    'password: hunter2',
)


class TestCredentialPairBulletproofCorpus(unittest.TestCase):
    def test_credential_pair_positive_corpus(self):
        failures = [
            text for text in _POSITIVES
            if 'credential_pair' not in {
                finding.pattern_name for finding in find_credential_patterns(text)
            }
        ]
        self.assertEqual(failures, [], f'missed {len(failures)}: {failures}')

    def test_credential_pair_negative_corpus(self):
        failures = [
            text for text in _NEGATIVES
            if 'credential_pair' in {
                finding.pattern_name for finding in find_credential_patterns(text)
            }
        ]
        self.assertEqual(
            failures, [],
            f'false-positive on {len(failures)}: {failures}',
        )

    def test_credential_pair_finding_never_carries_raw_password(self):
        # Redacted preview is the only thing safe to log; the full
        # password must never appear in the finding's preview field.
        findings = find_credential_patterns(
            'username: admin password: extremely-secret-value-123'
        )
        for finding in findings:
            with self.subTest(pattern=finding.pattern_name):
                self.assertNotIn(
                    'extremely-secret-value-123',
                    finding.redacted_preview,
                )


if __name__ == '__main__':
    unittest.main()
