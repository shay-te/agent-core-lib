"""Tests for the severity-tier categories and per-pattern replacement
strategies — the two structural follow-ups borrowed from pii-codex
(tiering) and scrubadub (per-type ``FilthReplacer``).

Three layers of coverage:

* :class:`TestCategoryFor` — every locked pattern name is tier-classified;
  the lookup function returns the right category; unknown names return
  ``None``.
* :class:`TestReplacementFor` — the default fall-through replacement and
  every registered per-pattern strategy.
* :class:`TestReplacementsDoNotReMatch` — the masked replacement
  strings must NOT re-match the same pattern (the round-trip property
  ``scrub_pii → find_pii_patterns → []`` is what the chat boundary
  relies on).
"""
from __future__ import annotations

import unittest

from agent_core_lib.pii.pii_patterns import (
    PII_PATTERN_NAMES,
    _PATTERN_CATEGORIES,
    CATEGORY_ADDRESS,
    CATEGORY_CONTACT,
    CATEGORY_CREDENTIAL,
    CATEGORY_FINANCIAL,
    CATEGORY_GOVERNMENT_ID,
    CATEGORY_NETWORK_DEVICE,
    CATEGORY_POSTAL,
    CATEGORY_TEMPORAL,
    CATEGORY_VEHICLE,
    category_for,
    find_pii_patterns,
    replacement_for,
)


_VALID_CATEGORIES = frozenset({
    CATEGORY_CONTACT,
    CATEGORY_GOVERNMENT_ID,
    CATEGORY_FINANCIAL,
    CATEGORY_POSTAL,
    CATEGORY_NETWORK_DEVICE,
    CATEGORY_VEHICLE,
    CATEGORY_ADDRESS,
    CATEGORY_TEMPORAL,
    CATEGORY_CREDENTIAL,
})


class TestCategoryFor(unittest.TestCase):
    def test_every_locked_pattern_has_a_category(self):
        missing = [name for name in PII_PATTERN_NAMES if name not in _PATTERN_CATEGORIES]
        self.assertEqual(
            missing, [],
            f'pattern names without a category — add them to '
            f'_PATTERN_CATEGORIES in pii_patterns.py: {missing}',
        )

    def test_every_category_value_is_a_known_tier(self):
        for pattern_name, category in _PATTERN_CATEGORIES.items():
            with self.subTest(pattern=pattern_name):
                self.assertIn(category, _VALID_CATEGORIES)

    def test_category_for_known_pattern(self):
        self.assertEqual(category_for('email'), CATEGORY_CONTACT)
        self.assertEqual(category_for('ssn'), CATEGORY_GOVERNMENT_ID)
        self.assertEqual(category_for('credit_card'), CATEGORY_FINANCIAL)
        self.assertEqual(category_for('us_zip'), CATEGORY_POSTAL)
        self.assertEqual(category_for('ipv4'), CATEGORY_NETWORK_DEVICE)
        self.assertEqual(category_for('vin'), CATEGORY_VEHICLE)
        self.assertEqual(category_for('po_box'), CATEGORY_ADDRESS)
        self.assertEqual(category_for('date_of_birth'), CATEGORY_TEMPORAL)
        self.assertEqual(category_for('jwt'), CATEGORY_CREDENTIAL)
        self.assertEqual(category_for('il_id'), CATEGORY_GOVERNMENT_ID)

    def test_category_for_unknown_returns_none(self):
        self.assertIsNone(category_for('made_up_pattern'))


class TestReplacementFor(unittest.TestCase):
    def test_default_replacement_for_unmapped_pattern(self):
        # Patterns without a registered strategy fall through to the
        # generic ``[redacted:<name>]`` placeholder.
        self.assertEqual(
            replacement_for('ssn', '123-45-6789'),
            '[redacted:ssn]',
        )
        self.assertEqual(
            replacement_for('us_passport', 'A12345678'),
            '[redacted:us_passport]',
        )

    def test_credit_card_replacement_masks_last_four(self):
        self.assertEqual(
            replacement_for('credit_card', '4111 1111 1111 1234'),
            '[redacted:credit_card:****1234]',
        )
        self.assertEqual(
            replacement_for('credit_card', '4111-1111-1111-9876'),
            '[redacted:credit_card:****9876]',
        )

    def test_phone_replacement_keeps_country_code(self):
        self.assertEqual(
            replacement_for('phone', '+1 555 123 4567'),
            '[redacted:phone:+1]',
        )
        self.assertEqual(
            replacement_for('phone', '+44 20 7946 0958'),
            '[redacted:phone:+44]',
        )

    def test_phone_replacement_without_country_code(self):
        # No ``+`` prefix — fall back to the generic placeholder.
        self.assertEqual(
            replacement_for('phone', '555 123 4567'),
            '[redacted:phone]',
        )

    def test_phone_replacement_truncates_country_code_at_three_digits(self):
        # The longest published country code is 3 digits (``+972``,
        # ``+233``). The collector caps at 3 to avoid spilling into
        # the subscriber number.
        self.assertEqual(
            replacement_for('phone', '+9725012345678'),
            '[redacted:phone:+972]',
        )

    def test_phone_replacement_stops_at_separator_after_country_code(self):
        # A space after the country code marks the boundary; the
        # collector breaks out without consuming the subscriber digits.
        self.assertEqual(
            replacement_for('phone', '+1 5551234567'),
            '[redacted:phone:+1]',
        )

    def test_phone_replacement_only_plus_no_digits_falls_back(self):
        # Just a ``+`` with no digits afterwards (the regex wouldn't
        # produce this in practice, but the helper is defensive).
        self.assertEqual(
            replacement_for('phone', '+abc'),
            '[redacted:phone]',
        )

    def test_phone_replacement_exhausts_input_in_country_code(self):
        # The for-loop hits the end of the string before any
        # separator — exercises the normal loop-exit path.
        self.assertEqual(
            replacement_for('phone', '+1'),
            '[redacted:phone:+1]',
        )

    def test_email_replacement_without_at_falls_back(self):
        # Defensive fallback: a "matched" string with no ``@`` (the
        # regex shouldn't produce this, but ``replacement_for`` is
        # callable directly) returns the generic placeholder.
        self.assertEqual(
            replacement_for('email', 'no-at-sign-here'),
            '[redacted:email]',
        )

    def test_email_replacement_keeps_host_without_at(self):
        # The ``@`` is intentionally omitted so the replacement text
        # doesn't re-match the email regex on a second pass.
        self.assertEqual(
            replacement_for('email', 'jane@example.com'),
            '[redacted:email:host=example.com]',
        )

    def test_gps_replacement_reduces_precision(self):
        self.assertEqual(
            replacement_for('gps_coordinates', '37.4220, -122.0841'),
            '[redacted:gps_coordinates:37.4,-122.1]',
        )

    def test_gps_replacement_unparseable_falls_back(self):
        self.assertEqual(
            replacement_for('gps_coordinates', 'not coordinates'),
            '[redacted:gps_coordinates]',
        )


class TestReplacementsDoNotReMatch(unittest.TestCase):
    """Critical round-trip property: the replacement string emitted
    by every per-pattern strategy must NOT itself match the same
    pattern. The chat boundary's audit path uses ``scrub_pii`` then
    ``assert_no_pii`` — if the replacement re-matched, the audit
    would fail on the very output the scrubber produced.
    """

    _ROUND_TRIPS = (
        ('credit_card', '4111 1111 1111 1234'),
        ('phone', '+1 555 123 4567'),
        ('email', 'jane@example.com'),
        ('gps_coordinates', '37.4220, -122.0841'),
    )

    def test_replacement_does_not_re_match_its_own_pattern(self):
        for pattern_name, original in self._ROUND_TRIPS:
            with self.subTest(pattern=pattern_name):
                replacement = replacement_for(pattern_name, original)
                round_trip = find_pii_patterns(replacement)
                same_pattern_hits = [
                    finding.pattern_name for finding in round_trip
                    if finding.pattern_name == pattern_name
                ]
                self.assertEqual(
                    same_pattern_hits, [],
                    f'{pattern_name} replacement {replacement!r} re-matches '
                    f'its own pattern — round-trip ``scrub_pii → '
                    f'find_pii_patterns`` would loop forever / re-trigger '
                    f'the audit.',
                )


if __name__ == '__main__':
    unittest.main()
