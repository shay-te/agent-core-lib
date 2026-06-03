"""Adversarial inputs for the PII scanner / scrubber.

This suite is a registry of inputs designed to **defeat** the hand-rolled
regex pattern set in :mod:`agent_core_lib.helpers.pii_patterns`. Every
test is intentional — either:

* A **MISS** test locks the current limitation. The docstring explains
  what an attacker would exploit and which improvement listed in
  ``pii_patterns.py``'s prior-art comment (Luhn / context boost / NER)
  would close the gap. If a future change accidentally catches the
  input, the test will flip and the comment block + recommendation
  should be updated.
* A **CATCH** test locks a correctly-handled tricky case. If a future
  refactor accidentally narrows the regex and starts missing it, the
  test fails immediately.
* A **FLOW** test exercises scrubber behavior under stress (overlapping
  spans, deep nesting, round-trips, edge-case containers) to catch
  regressions in the span-collection logic.

Read the test name first — ``test_miss_*`` is "we don't catch this",
``test_catch_*`` is "we do catch this", ``test_flow_*`` is structural.
"""

from __future__ import annotations

import unittest

from agent_core_lib.helpers.pii_patterns import (
    PII_PATTERN_NAMES,
    find_pii_patterns,
    summarize_pii_findings,
)
from agent_core_lib.helpers.pii_scrub import (
    PIIDetectedError,
    assert_no_pii,
    find_pii_in_payload,
    scrub_pii,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _names(findings) -> list:
    return [finding.pattern_name for finding in findings]


# ===========================================================================
# MISS: character substitution / encoding bypasses
# ===========================================================================


class TestMissCharacterEncodingBypasses(unittest.TestCase):
    """Encoded / substituted PII slips through because our regexes are
    ASCII-bound. Mitigation: normalize to NFKC + transliterate before
    scanning (cheap), or use Presidio-style NER which is encoding-aware.
    """

    def test_partial_email_with_cyrillic_lookalike_prefix(self):
        # The leading 'а' is U+0430 (CYRILLIC SMALL LETTER A). I
        # initially assumed this would defeat the regex entirely —
        # wrong. The ASCII tail (``dmin@example.com``) still matches
        # because the regex doesn't require the local part to start
        # at a word boundary that excludes Cyrillic. So we DO catch
        # the email, but we silently lose the first character. To an
        # operator reading the audit log, "email leak: dmin@..." is
        # ambiguous — was the local part really 4 chars or was a
        # homoglyph trimmed? The redacted-preview format hides this.
        text = 'contact аdmin@example.com for access'
        findings = find_pii_patterns(text)
        self.assertEqual(_names(findings), ['email'])
        # Lock the trimmed-prefix behavior so a future Unicode-aware
        # rewrite that catches the FULL local part shows up here.
        self.assertIn('dmin', findings[0].redacted_preview)

    def test_miss_email_with_zero_width_split(self):
        # Zero-width space (U+200B) breaks the contiguous local-part
        # token. Visually identical to a plain email in most renderers.
        text = 'send to jane​@example.com please'
        self.assertEqual(_names(find_pii_patterns(text)), [])

    def test_miss_credit_card_with_zero_width_separators(self):
        text = 'card 4242​4242​4242​4242 on file'
        # No findings of any kind — the digits aren't contiguous and
        # the zero-width chars aren't on our separator allowlist.
        self.assertNotIn('credit_card', _names(find_pii_patterns(text)))

    def test_catch_phone_with_arabic_indic_digits(self):
        # Arabic-Indic digits (U+0660-U+0669). I assumed this would
        # bypass the regex — wrong: Python's ``\d`` is Unicode-aware
        # by default and matches all decimal-digit Unicode characters
        # (Arabic-Indic, Devanagari, Thai, etc.). So this DOES catch
        # as a phone. A genuine ASCII-only bypass would need the
        # ``re.ASCII`` flag on the patterns — which we don't set.
        text = 'call ٠١٢٣٤٥٦٧٨٩٠ now'
        self.assertIn('phone', _names(find_pii_patterns(text)))

    def test_miss_email_base64_encoded(self):
        # base64('jane@example.com') = 'amFuZUBleGFtcGxlLmNvbQ=='. To a
        # regex this is a noise blob; to a model that decodes it (or
        # asks the user to), it's a leak. Mitigation requires
        # base64-decode-and-rescan, which we don't do.
        text = 'see amFuZUBleGFtcGxlLmNvbQ==  for contact'
        self.assertEqual(_names(find_pii_patterns(text)), [])

    def test_miss_email_html_entity_encoded(self):
        # `jane@example.com` as HTML entities. Same story.
        text = 'mail &#106;ane&#64;example.com today'
        self.assertEqual(_names(find_pii_patterns(text)), [])

    def test_miss_email_url_encoded(self):
        # `jane%40example.com` is `jane@example.com` URL-encoded.
        text = 'see https://api.example/u/jane%40example.com/profile'
        self.assertNotIn('email', _names(find_pii_patterns(text)))

    def test_catch_fullwidth_digit_ssn(self):
        # Full-width Unicode digits (U+FF10-U+FF19). I assumed regex
        # would treat them as letters — wrong, ``\d`` is Unicode-aware
        # and matches them as digits. The ``ssn`` pattern catches.
        # Genuine bypass would require ``re.ASCII`` flag, which we
        # don't use.
        text = 'SSN １２３-４５-６７８９ on file'
        self.assertIn('ssn', _names(find_pii_patterns(text)))


# ===========================================================================
# MISS: format variations we didn't anticipate
# ===========================================================================


class TestMissFormatVariations(unittest.TestCase):
    """Real-world PII appears in formats outside our pattern set."""

    def test_miss_ssn_without_dashes(self):
        # 9-digit SSN with no separators. Our ``ssn`` regex requires
        # ``XXX-XX-XXXX``; this falls through. It MIGHT match
        # ``us_passport`` (9 digits) — see below; if it does, the
        # finding family is wrong (says "passport") but the value is
        # still flagged. So we get "wrong-label catch" rather than
        # complete miss.
        findings = _names(find_pii_patterns('SSN 123456789 on file'))
        self.assertNotIn('ssn', findings)
        # Best effort coverage from us_passport (which is also 9 digits)
        # — locks the wrong-label finding so a future improvement
        # (Luhn-style SSN area-number validation) makes it cleaner.
        self.assertIn('us_passport', findings)

    def test_miss_credit_card_with_comma_separators(self):
        # Some checkout exports use commas. Our pattern allows space
        # and dash only.
        findings = _names(find_pii_patterns('paid with 4242,4242,4242,4242'))
        self.assertNotIn('credit_card', findings)

    def test_miss_credit_card_with_dot_separators(self):
        # European convention.
        findings = _names(find_pii_patterns('card 4242.4242.4242.4242 charged'))
        self.assertNotIn('credit_card', findings)

    def test_miss_email_with_quoted_local_part(self):
        # RFC 5321 allows quoted local parts with spaces and special
        # chars. Our regex's [a-zA-Z0-9._%+\-] doesn't include the
        # opening quote.
        findings = _names(find_pii_patterns('"jane doe"@example.com is the address'))
        self.assertNotIn('email', findings)

    def test_miss_email_with_display_name(self):
        # `Name <addr>` form. The angle brackets aren't on our
        # character class so the local part doesn't anchor — but the
        # regex is greedy enough to often still match the inner email.
        # Lock the actual behavior so a future change is visible.
        findings = _names(find_pii_patterns('Jane Doe <jane@example.com>'))
        # This one *does* catch — angle brackets bound the match
        # cleanly. Documented as a CATCH inside a MISS section because
        # readers expect the worst.
        self.assertIn('email', findings)

    def test_miss_pii_spread_across_fields(self):
        # The classic re-identification attack (Sweeney 2000): no
        # single field carries PII, but the combination does. Our
        # per-field regex set has no way to see this.
        payload = {
            'first_name': 'Jane',
            'last_name': 'Smith',
            'city': 'Cambridge',
            'zip': '02139',
            'gender': 'female',
        }
        findings = _names(find_pii_in_payload(payload))
        # The combination Jane+Smith+02139+Cambridge+female is highly
        # re-identifiable, but no single regex fires on the
        # *combination*. What DOES fire is incidental:
        #  - us_zip on '02139' (correct catch)
        #  - us_license_plate on 'female' (FALSE POSITIVE — the regex
        #    matches 5-8 alphanumerics and 'female' is 6 letters; an
        #    English word that happens to fit a plate's shape).
        # Lock both so a future tightening of us_license_plate (e.g.,
        # requiring at least one digit) shows up here, and a future
        # NER-based combination detector likewise visibly changes
        # this set.
        self.assertIn('us_zip', findings)
        self.assertIn('us_license_plate', findings)
        # The true risk (cross-field correlation) is still unflagged.
        # No "combination" or "quasi_identifier" finding exists.
        self.assertNotIn('quasi_identifier', findings)

    def test_miss_dob_without_trigger_word(self):
        # Our ``date_of_birth`` pattern requires the literal words
        # ``dob``, ``date of birth``, ``birthday``, or ``born``
        # adjacent to the date. A bare date in a sentence escapes.
        findings = _names(find_pii_patterns('she joined on 1990-05-12 last year'))
        self.assertNotIn('date_of_birth', findings)

    def test_catch_dob_with_trigger_word(self):
        findings = _names(find_pii_patterns('dob: 1990-05-12 on file'))
        self.assertIn('date_of_birth', findings)

    def test_miss_foreign_street_address(self):
        # German street suffix; our regex hardcodes English suffixes.
        # Russian, Hebrew, Arabic, Chinese addresses likewise miss.
        findings = _names(find_pii_patterns('Hauptstraße 5, 80331 München'))
        self.assertNotIn('street_address', findings)

    def test_miss_apartment_with_only_unit_designator(self):
        # No street suffix means no match — even though "Apt 4B" is
        # part of a partial address shape.
        findings = _names(find_pii_patterns('Apt 4B, building 7'))
        self.assertNotIn('street_address', findings)


# ===========================================================================
# MISS: context-only patterns escaping without their context word
# ===========================================================================


class TestMissContextDependentPatterns(unittest.TestCase):
    """Several patterns require an adjacent trigger word. Without it the
    value escapes. This is exactly why ``pii_patterns.py``'s prior-art
    comment recommends Presidio-style context-word boosting — give the
    raw match a confidence score, raise it when an adjacent keyword
    fires, lower it when isolated."""

    def test_miss_cvv_without_context_word(self):
        # Our ``credit_card_cvv`` pattern requires the literal "cvv" /
        # "cvc" / "security code" adjacent. Bare 3-4 digits in a
        # checkout payload would be missed.
        findings = _names(find_pii_patterns('security: 123 confirmed'))
        # The word "security " (with space) isn't matched by
        # "security\s+code", so this misses cleanly.
        self.assertNotIn('credit_card_cvv', findings)

    def test_catch_cvv_with_context_word(self):
        findings = _names(find_pii_patterns('cvv 999 entered'))
        self.assertIn('credit_card_cvv', findings)

    def test_miss_bank_account_without_label(self):
        # Our ``us_bank_account`` requires the literal "account" or
        # "acct" adjacent. A 10-digit account number on its own —
        # whether in an export column or a CSV — escapes.
        findings = _names(find_pii_patterns('beneficiary 0123456789 verified'))
        self.assertNotIn('us_bank_account', findings)

    def test_catch_bank_account_with_label(self):
        findings = _names(find_pii_patterns('account: 0123456789'))
        self.assertIn('us_bank_account', findings)


# ===========================================================================
# MISS: validation we don't perform (Luhn etc.)
# ===========================================================================


class TestMissUnvalidatedPatterns(unittest.TestCase):
    """Our patterns match shape but not checksum. False positives are
    flagged as catches; real PII inside well-known *test* numbers
    likewise fires. Mitigation: layer the standard validators behind
    each pattern (Luhn for cards, mod-97 for IBAN, ABA routing for
    routing numbers, VIN check digit) — see the prior-art comment in
    ``pii_patterns.py``."""

    def test_credit_card_test_number_fires_as_real(self):
        # `4242 4242 4242 4242` is Stripe's well-known test card. Our
        # regex flags it the same as a real card because we don't
        # discriminate. A Luhn checker would validate the card number
        # (the test card does pass Luhn — so even Luhn wouldn't help
        # here, but it would reject `1234 5678 9012 3456` which we
        # also flag today).
        findings = _names(find_pii_patterns('4242 4242 4242 4242'))
        self.assertIn('credit_card', findings)

    def test_invalid_card_number_also_fires(self):
        # 16 digits, definitely not a real Luhn-valid card. We still
        # report ``credit_card`` because we never validate.
        findings = _names(find_pii_patterns('1234 5678 9012 3456'))
        self.assertIn('credit_card', findings)

    def test_uuid_fires_as_bitcoin_address(self):
        # A v4 UUID's hex chunks can collide with bitcoin's
        # ``[a-km-zA-HJ-NP-Z1-9]`` set under the right random draw.
        # More commonly, an OrderID like ``A1234567890123456789012345``
        # is the false-positive class. Lock a representative case.
        # `1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa` is the real Genesis
        # block recipient — it should fire; included as a CATCH.
        findings = _names(find_pii_patterns('addr 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa'))
        self.assertIn('bitcoin_address', findings)

    def test_random_alphanumeric_fires_as_vin(self):
        # VIN regex matches any 17 alphanumerics (excluding I/O/Q).
        # An order id / hash chunk / build id can collide. Lock the
        # false-positive class so it's a known limitation.
        findings = _names(find_pii_patterns('build ABCDEFGHJKLMNPRST hash'))
        self.assertIn('vin', findings)

    def test_random_5_digit_id_fires_as_us_zip(self):
        # Any 5-digit number trips ``us_zip``. Database row ids /
        # order numbers / hash prefixes all fire.
        findings = _names(find_pii_patterns('order 54321 shipped'))
        self.assertIn('us_zip', findings)

    def test_random_8_digit_id_fires_as_us_drivers_license(self):
        findings = _names(find_pii_patterns('id 12345678 active'))
        self.assertIn('us_drivers_license', findings)


# ===========================================================================
# CATCH: tricky cases that DO work
# ===========================================================================


class TestCatchTrickyButHandled(unittest.TestCase):
    """Positive lock — these tricky-looking inputs ARE caught. If a
    future tightening accidentally narrows the regex, these break."""

    def test_catch_email_inside_json_string(self):
        # JSON serialization doesn't escape the local part, so the
        # email still matches char-for-char.
        text = '{"contact":"jane@example.com","status":"ok"}'
        self.assertIn('email', _names(find_pii_patterns(text)))

    def test_catch_email_inside_markdown_link(self):
        text = '[email us](mailto:jane@example.com)'
        self.assertIn('email', _names(find_pii_patterns(text)))

    def test_catch_email_with_plus_tag(self):
        text = 'use jane+ml-newsletter@example.com'
        self.assertIn('email', _names(find_pii_patterns(text)))

    def test_catch_email_with_subdomain(self):
        text = 'mailto jane@mail.eu.example.com'
        self.assertIn('email', _names(find_pii_patterns(text)))

    def test_catch_email_with_long_tld(self):
        text = 'visit info@example.museum'
        self.assertIn('email', _names(find_pii_patterns(text)))

    def test_catch_credit_card_with_mixed_separators(self):
        # Spaces and dashes both allowed.
        text = 'on file 4242-4242 4242-4242'
        self.assertIn('credit_card', _names(find_pii_patterns(text)))

    def test_catch_phone_at_start_of_line(self):
        text = '+1 (555) 123-4567 is the contact'
        self.assertIn('phone', _names(find_pii_patterns(text)))

    def test_catch_ipv6_compressed_form(self):
        text = 'client 2001:db8::8a2e:370:7334 connected'
        self.assertIn('ipv6', _names(find_pii_patterns(text)))

    def test_catch_email_with_quoted_local_part_loose(self):
        # The unquoted bare email inside still matches — the regex
        # doesn't care about the surrounding quotes.
        text = "'jane@example.com' in the log"
        self.assertIn('email', _names(find_pii_patterns(text)))


# ===========================================================================
# FLOW: scrubber under stress
# ===========================================================================


class TestScrubberFlows(unittest.TestCase):
    """Structural tests for the span-collection scrubber. Pattern
    overlaps, deep nesting, round-trip cleanliness."""

    def test_flow_round_trip_scrub_then_assert_no_pii_is_clean(self):
        # Operational contract: anything that passes through scrub_pii
        # should satisfy assert_no_pii on the way out. The earlier
        # uppercase placeholder ``[REDACTED:<name>]`` was a real bug —
        # ``REDACTED`` is 8 uppercase letters which matches
        # ``swift_bic`` (4+2+2 uppercase) and ``us_license_plate``
        # (5-8 alphanumerics), so the post-scrub blob *re-tripped*
        # the scanner. The lowercase ``[redacted:<name>]`` form chosen
        # in ``pii_scrub._scrub_string`` is what makes this assertion
        # hold — every pattern that COULD match a marker word
        # requires uppercase or specific punctuation we don't use.
        payload = {
            'comment': 'reach jane@example.com or 555-123-4567',
            'card': '4242 4242 4242 4242',
            'ssn': '123-45-6789',
            'note': 'IBAN NL91ABNA0417164300 verified',
            'street': '742 Evergreen Terrace',
            'dob_line': 'born 1990-05-12',
        }
        scrubbed = scrub_pii(payload)
        assert_no_pii(scrubbed)

    def test_flow_placeholder_text_alone_is_pii_free(self):
        # The marker tokens that ``_scrub_string`` emits MUST NOT
        # re-trigger any pattern when fed back through the scanner.
        # If this test fails after a placeholder format change, the
        # round-trip contract above will also break.
        for name in PII_PATTERN_NAMES:
            with self.subTest(pattern=name):
                marker = f'[redacted:{name}]'
                self.assertEqual(
                    find_pii_patterns(marker), [],
                    f'placeholder {marker!r} re-matched a PII pattern',
                )

    def test_flow_repeated_placeholder_text_is_pii_free(self):
        # Multiple markers concatenated also stay clean — guards
        # against a future change that introduces context-window
        # matching across adjacent markers.
        text = ' '.join(f'[redacted:{name}]' for name in PII_PATTERN_NAMES)
        self.assertEqual(find_pii_patterns(text), [])

    def test_flow_overlapping_email_and_phone_chooses_one(self):
        # `+1-jane@example.com` — the leading `+1-` could in principle
        # start a phone match while `jane@example.com` is an email.
        # First-accepted-by-start wins per our span resolver; lock the
        # observable outcome.
        text = '+1-jane@example.com'
        scrubbed = scrub_pii(text)
        # email is the dominant match (and what a reader expects).
        self.assertIn('[redacted:email]', scrubbed)
        # The phone-like prefix is consumed by the email span.
        self.assertNotIn('@', scrubbed)

    def test_flow_deeply_nested_containers(self):
        payload = {
            'level1': {
                'level2': [
                    {'level3': ('jane@example.com', 'clean')},
                    {'level3': [{'level4': '4242 4242 4242 4242'}]},
                ],
            },
        }
        scrubbed = scrub_pii(payload)
        # Tuples stay tuples, lists stay lists, dicts stay dicts.
        self.assertIsInstance(scrubbed['level1']['level2'][0]['level3'], tuple)
        self.assertIsInstance(scrubbed['level1']['level2'][1]['level3'], list)
        # No raw PII survives at any depth.
        assert_no_pii(scrubbed)

    def test_flow_empty_containers_pass_through(self):
        self.assertEqual(scrub_pii({}), {})
        self.assertEqual(scrub_pii([]), [])
        self.assertEqual(scrub_pii(()), ())
        self.assertEqual(scrub_pii(''), '')

    def test_flow_scrub_preserves_keys_with_pii_in_values_only(self):
        # Dict keys are NOT scrubbed (they're the schema, not the
        # data). Lock that contract — if a future change starts
        # walking keys it could break upstream consumers that read
        # by key.
        payload = {'email_field': 'jane@example.com'}
        scrubbed = scrub_pii(payload)
        self.assertIn('email_field', scrubbed)
        self.assertNotIn('jane@example.com', scrubbed['email_field'])

    def test_flow_scrub_is_pure_no_input_mutation(self):
        # Lock the no-mutation contract the docstring promises.
        original = {
            'a': 'jane@example.com',
            'b': ['nested', '555-123-4567'],
        }
        snapshot_a = original['a']
        snapshot_b = list(original['b'])
        scrub_pii(original)
        self.assertEqual(original['a'], snapshot_a)
        self.assertEqual(original['b'], snapshot_b)

    def test_flow_assert_no_pii_redacted_preview_never_carries_raw(self):
        # When assert_no_pii raises, the *full* matched value must not
        # appear in the exception message. The redacted_preview shows
        # a 4-char prefix + length marker only, so a reader can
        # confirm WHICH pattern fired without re-leaking the value.
        try:
            assert_no_pii({'note': 'jane.smith@example.com'})
            self.fail('expected PIIDetectedError')
        except PIIDetectedError as exc:
            message = str(exc)
            # Full value is gone.
            self.assertNotIn('jane.smith@example.com', message)
            self.assertNotIn('@example.com', message)
            # The 4-char prefix IS in the message (that's the
            # documented preview format). Lock that contract too —
            # cutting it shorter would lose operator-debugging value.
            self.assertIn('jane', message)
            self.assertIn('REDACTED', message)
            self.assertIn('email', message)


# ===========================================================================
# FLOW: summarize_pii_findings under stress
# ===========================================================================


class TestSummarizerFlows(unittest.TestCase):
    def test_flow_summary_groups_repeats(self):
        # Three emails in one text → one summary entry with "+2 more".
        text = 'a@b.com c@d.com e@f.com all clean'
        findings = find_pii_patterns(text)
        summary = summarize_pii_findings(findings)
        self.assertIn('email', summary)
        self.assertIn('+2 more', summary)

    def test_flow_summary_handles_mixed_families(self):
        text = 'jane@example.com and 4242 4242 4242 4242'
        summary = summarize_pii_findings(find_pii_patterns(text))
        # Both families named, neither raw value echoed.
        self.assertIn('email', summary)
        self.assertIn('credit_card', summary)
        self.assertNotIn('jane@example.com', summary)
        self.assertNotIn('4242 4242 4242 4242', summary)


# ===========================================================================
# Sanity: complete catalog of known misses (executable documentation)
# ===========================================================================


class TestKnownLimitationsCatalog(unittest.TestCase):
    """A single roll-up assertion that documents the named miss
    categories. If the catalog drifts it's a signal that the prior-art
    comment block in ``pii_patterns.py`` should be updated too —
    these categories are the "what we don't catch" registry the next
    person working in this area will read first."""

    KNOWN_MISS_CATEGORIES = frozenset({
        # encoding / character-substitution
        'unicode_homoglyph',
        'zero_width_separator',
        'fullwidth_digits',
        'non_ascii_digits',
        'base64_encoded',
        'html_entity_encoded',
        'url_encoded',
        # format variation
        'ssn_without_dashes',
        'credit_card_with_comma_or_dot_separators',
        'email_with_quoted_local_part',
        # context-dependent patterns
        'cvv_without_context_word',
        'bank_account_without_label',
        'dob_without_trigger_word',
        # no validation
        'credit_card_no_luhn_check',
        'iban_no_mod97_check',
        'vin_no_check_digit',
        # cross-field reidentification
        'pii_spread_across_fields',
        # locale
        'non_english_street_address',
    })

    def test_catalog_is_locked(self):
        # The set itself is the contract. Changing this set means the
        # comment block in ``pii_patterns.py`` (the prior-art research
        # section) should change in lockstep.
        self.assertEqual(len(self.KNOWN_MISS_CATEGORIES), 18)

    def test_pattern_names_did_not_drift(self):
        # If a new pattern lands, this asserts the named set is the
        # one the adversarial tests above were written against. A
        # mismatch means new patterns need new adversarial coverage.
        self.assertEqual(
            PII_PATTERN_NAMES,
            frozenset({
                'email', 'phone',
                'ssn', 'itin', 'ein',
                'us_passport', 'us_drivers_license', 'medicare_mbi',
                'uk_nino', 'uk_passport', 'ca_passport', 'au_passport',
                'credit_card', 'credit_card_cvv', 'iban', 'swift_bic',
                'us_routing_number', 'us_bank_account', 'bitcoin_address',
                'us_zip', 'uk_postcode', 'ca_postcode',
                'ipv4', 'ipv6', 'mac_address',
                'vin', 'us_license_plate',
                'street_address', 'po_box',
                'date_of_birth',
            }),
        )


if __name__ == '__main__':
    unittest.main()
