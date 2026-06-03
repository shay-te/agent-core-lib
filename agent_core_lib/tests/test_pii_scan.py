"""Tests for the agent-side PII scan helper.

The detector + scan parallel ``credential_patterns`` / ``credential_scan``
— the same WARNING-logging contract, just for personal data. Two layers
of coverage:

  * Pattern-level: the regex set fires on representative emails / SSNs /
    phone numbers / credit cards / IBANs, and the redacted preview
    never echoes the raw matched value.
  * Scan-level: blank text is a no-op, populated findings emit exactly
    one WARNING starting ``'PII PATTERN DETECTED in %s'``, clean text
    runs the detector but logs nothing.
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

    def test_pattern_names_are_locked(self):
        # If the named set drifts, the cross-lib mirror in
        # ``llm_core_lib.safety.pii_patterns`` should drift in lockstep.
        self.assertEqual(
            PII_PATTERN_NAMES,
            frozenset({'email', 'ssn', 'phone', 'credit_card', 'iban'}),
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
