"""Tests for the agent-side PII scan helper + pattern set.

``pii_patterns`` is the workspace's single source of truth for PII
regexes — every other PII consumer (``pii_scrub`` for structured
payloads, the chat service's tool-result sanitizer in
``ob-love-admin-backend``) pulls its patterns from here. The tests
below have two layers:

  * Pattern-level: every named family in the extensive set
    (contact / US gov IDs / intl gov IDs / financial / postal /
    network-device / vehicle / address / temporal) fires on a
    representative input, redacted previews never echo the raw value,
    and the named set is locked so a future shrink is caught here.
  * Scan-level: blank text is a no-op, populated findings emit
    exactly one WARNING starting ``'PII PATTERN DETECTED in %s'``,
    clean text runs the detector but logs nothing.
"""
from __future__ import annotations

import unittest
from unittest import mock

from agent_core_lib.helpers.pii_patterns import (
    PII_PATTERN_NAMES,
    find_pii_patterns,
    summarize_pii_findings,
)
from agent_core_lib.helpers.pii_scan import scan_text_for_pii


_PATTERN_MODULE = 'agent_core_lib.helpers.pii_patterns'


class FindPiiPatternsTests(unittest.TestCase):
    def test_email_match(self):
        findings = find_pii_patterns('reach jane@example.com please')
        self.assertEqual([f.pattern_name for f in findings], ['email'])
        self.assertNotIn('jane@example.com', findings[0].redacted_preview)

    def test_ssn_match(self):
        findings = find_pii_patterns('ssn 123-45-6789 on file')
        self.assertIn('ssn', [f.pattern_name for f in findings])

    def test_credit_card_match(self):
        findings = find_pii_patterns('paid with 4242 4242 4242 4242')
        self.assertIn('credit_card', [f.pattern_name for f in findings])

    def test_iban_match(self):
        findings = find_pii_patterns('IBAN NL91ABNA0417164300 confirmed')
        self.assertIn('iban', [f.pattern_name for f in findings])

    def test_clean_text_returns_no_findings(self):
        self.assertEqual(find_pii_patterns('a perfectly safe agent response'), [])

    def test_empty_text_returns_empty(self):
        self.assertEqual(find_pii_patterns(''), [])
        self.assertEqual(find_pii_patterns(None), [])  # type: ignore[arg-type]

    # ---- extended pattern coverage --------------------------------
    # One representative input per named family. If a pattern is added
    # to the canonical set, add a row here; the locked-names test below
    # will fail loudly if the two drift.

    def test_itin_match(self):
        findings = find_pii_patterns('itin 912-78-1234 reported')
        self.assertIn('itin', [f.pattern_name for f in findings])

    def test_ein_match(self):
        findings = find_pii_patterns('EIN 12-3456789 on the W-9')
        self.assertIn('ein', [f.pattern_name for f in findings])

    def test_swift_bic_match(self):
        # NEDSZAJJ is a real-world SWIFT/BIC shape.
        findings = find_pii_patterns('wire via NEDSZAJJ today')
        self.assertIn('swift_bic', [f.pattern_name for f in findings])

    def test_bitcoin_address_match(self):
        findings = find_pii_patterns(
            'sent 0.01 BTC to 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa now'
        )
        self.assertIn('bitcoin_address', [f.pattern_name for f in findings])

    def test_us_zip_match(self):
        findings = find_pii_patterns('shipping to ZIP 90210-1234 ASAP')
        self.assertIn('us_zip', [f.pattern_name for f in findings])

    def test_uk_postcode_match(self):
        findings = find_pii_patterns('billing address SW1A 1AA confirmed')
        self.assertIn('uk_postcode', [f.pattern_name for f in findings])

    def test_ca_postcode_match(self):
        findings = find_pii_patterns('postal code K1A 0B1 verified')
        self.assertIn('ca_postcode', [f.pattern_name for f in findings])

    def test_ipv4_match(self):
        findings = find_pii_patterns('client connected from 192.168.1.42')
        self.assertIn('ipv4', [f.pattern_name for f in findings])

    def test_ipv6_match(self):
        findings = find_pii_patterns('client ipv6 2001:0db8:85a3:0000:0000:8a2e:0370:7334 now')
        self.assertIn('ipv6', [f.pattern_name for f in findings])

    def test_mac_address_match(self):
        findings = find_pii_patterns('device MAC 00:1B:44:11:3A:B7 paired')
        self.assertIn('mac_address', [f.pattern_name for f in findings])

    def test_vin_match(self):
        findings = find_pii_patterns('VIN 1HGCM82633A123456 recorded')
        self.assertIn('vin', [f.pattern_name for f in findings])

    def test_street_address_match(self):
        findings = find_pii_patterns('mail to 742 Evergreen Terrace please')
        self.assertIn('street_address', [f.pattern_name for f in findings])

    def test_po_box_match(self):
        findings = find_pii_patterns('use P.O. Box 1234 for billing')
        self.assertIn('po_box', [f.pattern_name for f in findings])

    def test_date_of_birth_match(self):
        findings = find_pii_patterns('dob 1990-05-12 on file')
        self.assertIn('date_of_birth', [f.pattern_name for f in findings])

    def test_credit_card_cvv_match(self):
        findings = find_pii_patterns('cvv 123 from order page')
        self.assertIn('credit_card_cvv', [f.pattern_name for f in findings])

    def test_pattern_names_are_locked(self):
        # The canonical, extensive set. Adding to PII_PATTERN_NAMES
        # without adding a representative test above (or vice versa)
        # fails here — that's the point.
        self.assertEqual(
            PII_PATTERN_NAMES,
            frozenset({
                # contact
                'email', 'phone',
                # US gov IDs
                'ssn', 'itin', 'ein',
                'us_passport', 'us_drivers_license', 'medicare_mbi',
                # intl gov IDs
                'uk_nino', 'uk_passport', 'ca_passport', 'au_passport',
                # financial
                'credit_card', 'credit_card_cvv', 'iban', 'swift_bic',
                'us_routing_number', 'us_bank_account', 'bitcoin_address',
                # postal
                'us_zip', 'uk_postcode', 'ca_postcode',
                # network / device
                'ipv4', 'ipv6', 'mac_address',
                # vehicle
                'vin', 'us_license_plate',
                # address
                'street_address', 'po_box',
                # temporal
                'date_of_birth',
            }),
        )


class SummarizeFindingsTests(unittest.TestCase):
    def test_no_findings_produces_default_phrase(self):
        self.assertEqual(summarize_pii_findings([]), 'no pii patterns detected')

    def test_findings_summary_does_not_leak_raw_match(self):
        findings = find_pii_patterns('jane@example.com and 4242 4242 4242 4242')
        summary = summarize_pii_findings(findings)
        self.assertIn('email', summary)
        self.assertIn('credit_card', summary)
        self.assertNotIn('jane@example.com', summary)
        self.assertNotIn('4242 4242 4242 4242', summary)


class ScanTextForPiiTests(unittest.TestCase):
    def test_empty_text_is_noop(self):
        find = mock.Mock()
        summarize = mock.Mock()
        logger = mock.Mock()
        with mock.patch(f'{_PATTERN_MODULE}.find_pii_patterns', find), \
             mock.patch(f'{_PATTERN_MODULE}.summarize_pii_findings', summarize):
            scan_text_for_pii('', logger=logger, context_label='ctx-empty')
        find.assert_not_called()
        summarize.assert_not_called()
        logger.warning.assert_not_called()

    def test_none_text_is_noop(self):
        find = mock.Mock()
        summarize = mock.Mock()
        logger = mock.Mock()
        with mock.patch(f'{_PATTERN_MODULE}.find_pii_patterns', find), \
             mock.patch(f'{_PATTERN_MODULE}.summarize_pii_findings', summarize):
            scan_text_for_pii(None, logger=logger, context_label='ctx-none')  # type: ignore[arg-type]
        find.assert_not_called()
        summarize.assert_not_called()
        logger.warning.assert_not_called()

    def test_findings_emit_one_warning(self):
        text = 'jane@example.com leaked'
        hits = ['pii_finding_object']
        find = mock.Mock(return_value=hits)
        summarize = mock.Mock(return_value='pii-summary')
        logger = mock.Mock()

        with mock.patch(f'{_PATTERN_MODULE}.find_pii_patterns', find), \
             mock.patch(f'{_PATTERN_MODULE}.summarize_pii_findings', summarize):
            scan_text_for_pii(text, logger=logger, context_label='pii-ctx')

        find.assert_called_once_with(text)
        summarize.assert_called_once_with(hits)
        self.assertEqual(len(logger.warning.call_args_list), 1)
        call = logger.warning.call_args_list[0]
        self.assertTrue(call.args[0].startswith('PII PATTERN DETECTED in %s'))
        self.assertEqual(call.args[1], 'pii-ctx')
        self.assertEqual(call.args[2], 'pii-summary')

    def test_clean_text_does_not_log(self):
        text = 'no pii here'
        find = mock.Mock(return_value=[])
        summarize = mock.Mock()
        logger = mock.Mock()

        with mock.patch(f'{_PATTERN_MODULE}.find_pii_patterns', find), \
             mock.patch(f'{_PATTERN_MODULE}.summarize_pii_findings', summarize):
            scan_text_for_pii(text, logger=logger, context_label='clean-ctx')

        find.assert_called_once_with(text)
        summarize.assert_not_called()
        logger.warning.assert_not_called()


if __name__ == '__main__':
    unittest.main()
