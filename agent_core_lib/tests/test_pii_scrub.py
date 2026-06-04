"""Tests for the structured-payload PII helpers.

``pii_scrub`` is the runtime backstop the LLM tool-result boundary
wires into; it walks ``dict`` / ``list`` / ``tuple`` containers and
applies the canonical pattern set to every string it finds. Three
behaviors locked here:

  * :func:`find_pii_in_payload` — non-throwing scan over structured
    data; returns the same :class:`PIIPatternFinding` family the
    text-scan helpers return so callers can treat the two
    interchangeably.
  * :func:`assert_no_pii` — raises :class:`PIIDetectedError` with the
    matched pattern name + redacted preview; never echoes the raw
    matched value (that's the whole point — even the error message
    has to be safe).
  * :func:`scrub_pii` — pure, recursive, container-preserving rewrite.
    Non-text primitives pass through unchanged.
"""

from __future__ import annotations

import unittest

from agent_core_lib.helpers.pii_scrub import (
    PIIDetectedError,
    assert_no_pii,
    find_pii_in_payload,
    scrub_pii,
)


class FindPiiInPayloadTests(unittest.TestCase):
    def test_clean_payload_returns_no_findings(self):
        self.assertEqual(
            find_pii_in_payload({'id': 'u1', 'display_name': 'Jane', 'rank': 5}),
            [],
        )

    def test_email_in_nested_dict_is_detected(self):
        findings = find_pii_in_payload({
            'users': [
                {'id': 'u1', 'note': 'see jane@example.com'},
                {'id': 'u2', 'note': 'clean'},
            ]
        })
        self.assertIn('email', [f.pattern_name for f in findings])

    def test_credit_card_in_list_is_detected(self):
        findings = find_pii_in_payload(['paid with 4242 4242 4242 4242'])
        self.assertIn('credit_card', [f.pattern_name for f in findings])

    def test_none_payload_returns_empty(self):
        self.assertEqual(find_pii_in_payload(None), [])


class AssertNoPiiTests(unittest.TestCase):
    def test_clean_payload_does_not_raise(self):
        assert_no_pii({'id': 'u1', 'display_name': 'Jane'})

    def test_email_payload_raises_and_does_not_echo_raw_value(self):
        with self.assertRaises(PIIDetectedError) as ctx:
            assert_no_pii({'note': 'jane@example.com'})
        self.assertNotIn('jane@example.com', str(ctx.exception))
        self.assertIn('email', str(ctx.exception))

    def test_lists_every_matched_pattern_in_summary(self):
        with self.assertRaises(PIIDetectedError) as ctx:
            assert_no_pii({
                'email_field': 'jane@example.com',
                'ssn_field': '123-45-6789',
            })
        message = str(ctx.exception)
        self.assertIn('email', message)
        self.assertIn('ssn', message)


class ScrubPiiTests(unittest.TestCase):
    def test_email_in_string_is_replaced(self):
        scrubbed = scrub_pii('reach out to jane@example.com please')
        self.assertNotIn('jane@example.com', scrubbed)
        self.assertIn('[redacted:email]', scrubbed)

    def test_dict_is_walked_recursively(self):
        payload = {
            'id': 'u1',
            'note': 'email is jane@example.com',
            'nested': {'card': '4242 4242 4242 4242'},
        }
        scrubbed = scrub_pii(payload)
        self.assertEqual(scrubbed['id'], 'u1')
        self.assertNotIn('jane@example.com', scrubbed['note'])
        self.assertNotIn('4242 4242 4242 4242', scrubbed['nested']['card'])

    def test_list_is_walked(self):
        scrubbed = scrub_pii(['jane@example.com', 'clean'])
        self.assertNotIn('jane@example.com', scrubbed[0])
        self.assertEqual(scrubbed[1], 'clean')

    def test_tuple_is_walked_and_returned_as_tuple(self):
        scrubbed = scrub_pii(('jane@example.com', 'clean'))
        self.assertIsInstance(scrubbed, tuple)
        self.assertNotIn('jane@example.com', scrubbed[0])

    def test_non_text_primitives_pass_through(self):
        self.assertEqual(scrub_pii(42), 42)
        self.assertEqual(scrub_pii(True), True)
        self.assertIsNone(scrub_pii(None))

    def test_input_payload_is_not_mutated(self):
        original = {'note': 'jane@example.com', 'nested': {'card': '4242 4242 4242 4242'}}
        snapshot = {'note': original['note'], 'nested': dict(original['nested'])}
        scrub_pii(original)
        self.assertEqual(original, snapshot)

    def test_url_with_embedded_email_redacts_to_url_only(self):
        # The url pattern is declared before email in pii_patterns so the
        # overlap resolver in _scrub_string keeps the longer URL span and
        # drops the email span — the redacted output should carry the
        # url marker and have no separate email marker for the embedded
        # address. (Both patterns still fire at the find_pii layer; this
        # is about the rebuild step.)
        scrubbed = scrub_pii('see https://host/u/jane@example.com/profile here')
        self.assertNotIn('jane@example.com', scrubbed)
        self.assertIn('[redacted:url]', scrubbed)
        # No separate [redacted:email] should appear inside the URL span.
        self.assertEqual(scrubbed.count('[redacted:email]'), 0)


if __name__ == '__main__':
    unittest.main()
