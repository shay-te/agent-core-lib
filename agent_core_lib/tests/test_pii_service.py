"""Tests for :class:`agent_core_lib.data_layers.service.pii_service.PiiService`.

Two methods:
  * :meth:`PiiService.validate` — scan only. Returns a list of
    :class:`PIIPatternFinding`. Never mutates the payload.
  * :meth:`PiiService.scrub` — scan + return a cleaned copy.

Three shared knobs: ``strict``, ``raise_on_pii``, ``audit_logger``.
"""
from __future__ import annotations

import unittest
from unittest import mock

from agent_core_lib.data_layers.service.pii_service import PiiService
from agent_core_lib.pii.pii_patterns import PIIPatternFinding
from agent_core_lib.pii.pii_scrub import PIIDetectedError


# ---------------------------------------------------------------------------
# validate() — scan only, returns findings, never mutates
# ---------------------------------------------------------------------------


class TestValidateReturnsFindings(unittest.TestCase):
    """``validate(payload)`` reports what was found without modifying anything."""

    def setUp(self):
        self.service = PiiService()

    def test_clean_payload_returns_empty_findings(self):
        self.assertEqual(
            self.service.validate({'id': 'u1', 'display_name': 'Jane', 'rank': 5}),
            [],
        )

    def test_pii_payload_returns_finding_per_match(self):
        findings = self.service.validate({'note': 'reach jane@example.com'})
        self.assertEqual(len(findings), 1)
        self.assertIsInstance(findings[0], PIIPatternFinding)
        self.assertIn('email', findings[0].pattern_name)

    def test_multiple_pii_types_each_produce_findings(self):
        findings = self.service.validate({
            'email': 'jane@example.com',
            'iban': 'GB82WEST12345698765432',
        })
        pattern_names = {finding.pattern_name for finding in findings}
        self.assertIn('email', pattern_names)
        self.assertIn('iban', pattern_names)

    def test_findings_carry_redacted_preview_not_raw_value(self):
        findings = self.service.validate({'note': 'jane@example.com'})
        for finding in findings:
            self.assertNotIn('jane@example.com', finding.redacted_preview)

    def test_payload_is_returned_unchanged(self):
        original = {'note': 'jane@example.com'}
        snapshot = dict(original)
        self.service.validate(original)
        # validate() does NOT mutate, and the original keeps its raw value.
        self.assertEqual(original, snapshot)
        self.assertEqual(original['note'], 'jane@example.com')

    def test_none_payload_returns_empty_findings(self):
        self.assertEqual(self.service.validate(None), [])

    def test_findings_are_truthy_for_payloads_with_pii(self):
        self.assertTrue(self.service.validate({'note': 'jane@example.com'}))

    def test_findings_are_falsy_for_clean_payloads(self):
        self.assertFalse(self.service.validate({'id': 'u1'}))


class TestValidateDoesNotScrub(unittest.TestCase):
    """validate() is scan-only; it must not return the scrubbed copy."""

    def test_validate_returns_list_not_payload(self):
        service = PiiService()
        result = service.validate({'note': 'jane@example.com'})
        self.assertIsInstance(result, list)
        # The dict-shaped payload doesn't show up in the return value.
        self.assertNotIsInstance(result, dict)


# ---------------------------------------------------------------------------
# scrub() — scan + return cleaned copy
# ---------------------------------------------------------------------------


class TestScrubReturnsCleanedCopy(unittest.TestCase):

    def setUp(self):
        self.service = PiiService()

    def test_clean_payload_returns_equivalent_copy(self):
        payload = {'id': 'u1', 'display_name': 'Jane', 'rank': 5}
        self.assertEqual(self.service.scrub(payload), payload)

    def test_email_in_dict_is_scrubbed(self):
        scrubbed = self.service.scrub({'note': 'reach jane@example.com'})
        self.assertNotIn('jane@example.com', scrubbed['note'])
        self.assertIn('[redacted:email:host=example.com]', scrubbed['note'])

    def test_nested_payload_is_walked(self):
        scrubbed = self.service.scrub({
            'users': [
                {'note': 'see jane@example.com'},
                {'note': 'and 123-45-6789 too'},
            ],
        })
        self.assertNotIn('jane@example.com', scrubbed['users'][0]['note'])
        self.assertNotIn('123-45-6789', scrubbed['users'][1]['note'])

    def test_input_payload_is_not_mutated(self):
        original = {'note': 'jane@example.com'}
        snapshot = dict(original)
        self.service.scrub(original)
        self.assertEqual(original, snapshot)
        self.assertEqual(original['note'], 'jane@example.com')

    def test_string_input_is_supported(self):
        self.assertNotIn(
            'jane@example.com',
            self.service.scrub('reach jane@example.com'),
        )

    def test_none_payload_returns_none(self):
        self.assertIsNone(self.service.scrub(None))

    def test_list_payload(self):
        scrubbed = self.service.scrub(
            ['clean', 'reach jane@example.com', 'also clean'],
        )
        self.assertEqual(scrubbed[0], 'clean')
        self.assertNotIn('jane@example.com', scrubbed[1])
        self.assertEqual(scrubbed[2], 'also clean')

    def test_tuple_payload_returns_tuple(self):
        scrubbed = self.service.scrub(('jane@example.com', 'clean'))
        self.assertIsInstance(scrubbed, tuple)
        self.assertNotIn('jane@example.com', scrubbed[0])

    def test_empty_dict_returns_empty_dict(self):
        self.assertEqual(self.service.scrub({}), {})

    def test_empty_list_returns_empty_list(self):
        self.assertEqual(self.service.scrub([]), [])

    def test_empty_string_returns_empty_string(self):
        self.assertEqual(self.service.scrub(''), '')

    def test_mixed_nested_with_primitives(self):
        payload = {
            'id': 42,
            'active': True,
            'metadata': None,
            'tags': ['urgent', 'jane@example.com'],
            'nested': {'count': 7, 'note': 'see 123-45-6789'},
        }
        scrubbed = self.service.scrub(payload)
        self.assertEqual(scrubbed['id'], 42)
        self.assertEqual(scrubbed['active'], True)
        self.assertIsNone(scrubbed['metadata'])
        self.assertEqual(scrubbed['nested']['count'], 7)
        self.assertNotIn('jane@example.com', scrubbed['tags'][1])
        self.assertNotIn('123-45-6789', scrubbed['nested']['note'])


class TestScrubMultiplePiiTypes(unittest.TestCase):

    def setUp(self):
        self.service = PiiService()

    def test_email_phone_ssn_credit_card_together(self):
        scrubbed = self.service.scrub({
            'email_field': 'jane@example.com',
            'phone_field': '+1 212 555 1234',
            'ssn_field': '123-45-6789',
            'card_field': '4111 1111 1111 1111',
        })
        self.assertNotIn('jane@example.com', scrubbed['email_field'])
        self.assertNotIn('555 1234', scrubbed['phone_field'])
        self.assertNotIn('123-45-6789', scrubbed['ssn_field'])
        self.assertNotIn('4111', scrubbed['card_field'])

    def test_iban_bitcoin_jwt_together(self):
        scrubbed = self.service.scrub({
            'iban': 'GB82WEST12345698765432',
            'wallet': '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa',
            'token': 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signature_here',
        })
        self.assertNotIn('GB82WEST12345698765432', scrubbed['iban'])
        self.assertNotIn('1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa', scrubbed['wallet'])
        self.assertNotIn('eyJhbGc', scrubbed['token'])


class TestScrubRoundTrip(unittest.TestCase):
    """Scrubbing twice produces the same output as scrubbing once.

    The scrubber's replacement strings (``[redacted:<pattern>]``) are
    lowercase on purpose so they don't re-match any pattern."""

    def test_double_scrub_is_idempotent(self):
        service = PiiService()
        once = service.scrub({'note': 'reach jane@example.com today'})
        twice = service.scrub(once)
        self.assertEqual(once, twice)

    def test_scrubbed_output_has_no_findings(self):
        service = PiiService()
        scrubbed = service.scrub({'note': 'jane@example.com and 4111111111111111'})
        self.assertEqual(service.validate(scrubbed), [])


class TestScrubNonStandardTypes(unittest.TestCase):

    def setUp(self):
        self.service = PiiService()

    def test_payload_with_date(self):
        from datetime import date
        scrubbed = self.service.scrub(
            {'created_at': date(2024, 1, 1), 'note': 'jane@example.com'},
        )
        self.assertEqual(scrubbed['created_at'], date(2024, 1, 1))
        self.assertNotIn('jane@example.com', scrubbed['note'])

    def test_payload_with_decimal(self):
        from decimal import Decimal
        scrubbed = self.service.scrub(
            {'amount': Decimal('100.50'), 'note': 'card 4111111111111111'},
        )
        self.assertEqual(scrubbed['amount'], Decimal('100.50'))
        self.assertNotIn('4111111111111111', scrubbed['note'])

    def test_payload_with_uuid(self):
        import uuid
        scrubbed = self.service.scrub(
            {'request_id': uuid.uuid4(), 'note': 'reach jane@example.com'},
        )
        self.assertIsInstance(scrubbed['request_id'], uuid.UUID)
        self.assertNotIn('jane@example.com', scrubbed['note'])

    def test_int_payload(self):
        self.assertEqual(self.service.scrub(42), 42)

    def test_bool_payload(self):
        self.assertEqual(self.service.scrub(True), True)
        self.assertEqual(self.service.scrub(False), False)


class TestScrubRealisticChatToolPayload(unittest.TestCase):

    def setUp(self):
        self.service = PiiService()

    def test_user_search_results_shape(self):
        payload = {
            'users': [
                {'id': 1, 'display_name': 'Jane', 'note': 'contact at jane@example.com or call 212-555-1234'},
                {'id': 2, 'display_name': 'John', 'note': 'SSN 123-45-6789 on file'},
            ],
            'total_count': 2,
            'page': 1,
        }
        scrubbed = self.service.scrub(payload)
        self.assertEqual(scrubbed['total_count'], 2)
        self.assertEqual(scrubbed['page'], 1)
        self.assertEqual(len(scrubbed['users']), 2)
        self.assertEqual(scrubbed['users'][0]['id'], 1)
        self.assertEqual(scrubbed['users'][0]['display_name'], 'Jane')
        self.assertNotIn('jane@example.com', scrubbed['users'][0]['note'])
        self.assertNotIn('123-45-6789', scrubbed['users'][1]['note'])

    def test_chat_message_history_shape(self):
        payload = [
            {'role': 'user', 'content': 'find user jane@example.com'},
            {'role': 'assistant', 'content': 'Found 1 user. Email withheld.'},
            {'role': 'user', 'content': 'their ssn is 123-45-6789'},
        ]
        scrubbed = self.service.scrub(payload)
        self.assertEqual(len(scrubbed), 3)
        self.assertNotIn('jane@example.com', scrubbed[0]['content'])
        self.assertEqual(scrubbed[1]['content'], 'Found 1 user. Email withheld.')
        self.assertNotIn('123-45-6789', scrubbed[2]['content'])


# ---------------------------------------------------------------------------
# Shared knobs — exercised against both validate() and scrub()
# ---------------------------------------------------------------------------


class TestStrictMode(unittest.TestCase):
    """``strict=True`` also runs ``phonenumbers`` + ``dateparser``."""

    def setUp(self):
        self.service = PiiService()

    def test_validate_strict_catches_bare_dob_the_regex_misses(self):
        text = 'patient 1990/05/15 active'
        self.assertEqual(self.service.validate(text, strict=False), [])
        self.assertTrue(self.service.validate(text, strict=True))

    def test_scrub_strict_catches_bare_dob_via_raise(self):
        text = 'patient 1990/05/15 active'
        self.service.scrub(text, strict=False, raise_on_pii=True)
        with self.assertRaises(PIIDetectedError):
            self.service.scrub(text, strict=True, raise_on_pii=True)


class TestRaiseOnPii(unittest.TestCase):
    """``raise_on_pii=True`` — raise instead of returning."""

    def setUp(self):
        self.service = PiiService()

    def test_validate_clean_payload_does_not_raise(self):
        self.service.validate({'id': 'u1'}, raise_on_pii=True)

    def test_scrub_clean_payload_does_not_raise(self):
        self.service.scrub({'id': 'u1'}, raise_on_pii=True)

    def test_validate_pii_payload_raises(self):
        with self.assertRaises(PIIDetectedError):
            self.service.validate({'note': 'jane@example.com'}, raise_on_pii=True)

    def test_scrub_pii_payload_raises(self):
        with self.assertRaises(PIIDetectedError):
            self.service.scrub({'note': 'jane@example.com'}, raise_on_pii=True)

    def test_raised_error_message_carries_pattern_name_not_raw_value(self):
        with self.assertRaises(PIIDetectedError) as ctx:
            self.service.validate(
                {'note': 'jane@example.com'}, raise_on_pii=True,
            )
        message = str(ctx.exception)
        self.assertIn('email', message)
        self.assertNotIn('jane@example.com', message)

    def test_raised_error_uses_context_in_message(self):
        with self.assertRaises(PIIDetectedError) as ctx:
            self.service.scrub(
                {'note': 'jane@example.com'},
                raise_on_pii=True,
                context='admin_chat_response',
            )
        self.assertIn('admin_chat_response', str(ctx.exception))


class TestAuditLogger(unittest.TestCase):
    """``audit_logger`` — one WARNING per scan that finds something."""

    def setUp(self):
        self.service = PiiService()

    def test_validate_clean_payload_does_not_log(self):
        logger = mock.Mock()
        self.service.validate({'id': 'u1'}, audit_logger=logger)
        logger.warning.assert_not_called()

    def test_scrub_clean_payload_does_not_log(self):
        logger = mock.Mock()
        self.service.scrub({'id': 'u1'}, audit_logger=logger)
        logger.warning.assert_not_called()

    def test_validate_pii_payload_logs_one_warning_with_summary(self):
        logger = mock.Mock()
        self.service.validate(
            {'note': 'jane@example.com'},
            audit_logger=logger,
            context='test_context',
        )
        self.assertEqual(len(logger.warning.call_args_list), 1)
        call = logger.warning.call_args_list[0]
        self.assertEqual(call.args[1], 'test_context')
        self.assertIn('email', call.args[2])

    def test_scrub_pii_payload_logs_one_warning_with_summary(self):
        logger = mock.Mock()
        self.service.scrub(
            {'note': 'jane@example.com'},
            audit_logger=logger,
            context='test_context',
        )
        self.assertEqual(len(logger.warning.call_args_list), 1)
        call = logger.warning.call_args_list[0]
        self.assertEqual(call.args[1], 'test_context')
        self.assertIn('email', call.args[2])

    def test_logged_summary_never_carries_raw_value(self):
        logger = mock.Mock()
        self.service.validate({'note': 'jane@example.com'}, audit_logger=logger)
        full_log_call = ' '.join(str(arg) for arg in logger.warning.call_args.args)
        self.assertNotIn('jane@example.com', full_log_call)

    def test_logger_and_raise_can_combine(self):
        logger = mock.Mock()
        with self.assertRaises(PIIDetectedError):
            self.service.scrub(
                {'note': 'jane@example.com'},
                raise_on_pii=True,
                audit_logger=logger,
            )
        self.assertEqual(len(logger.warning.call_args_list), 1)


class TestAuditLoggerDefaultsToModuleLogger(unittest.TestCase):
    """When the caller omits ``audit_logger``, detections land on the
    service's module-level logger so they never disappear silently."""

    def test_validate_uses_module_logger_when_caller_omits_audit_logger(self):
        with self.assertLogs(
            'agent_core_lib.data_layers.service.pii_service',
            level='WARNING',
        ) as captured:
            PiiService().validate({'note': 'jane@example.com'})
        self.assertTrue(
            any('PII detected' in line for line in captured.output),
            captured.output,
        )

    def test_scrub_uses_module_logger_when_caller_omits_audit_logger(self):
        with self.assertLogs(
            'agent_core_lib.data_layers.service.pii_service',
            level='WARNING',
        ) as captured:
            PiiService().scrub({'note': 'jane@example.com'})
        self.assertTrue(
            any('PII detected' in line for line in captured.output),
            captured.output,
        )


class TestContextDefault(unittest.TestCase):
    """``context`` defaults to ``'payload'`` for both audit log and raised error."""

    def setUp(self):
        self.service = PiiService()

    def test_default_context_in_raised_error(self):
        with self.assertRaises(PIIDetectedError) as ctx:
            self.service.validate(
                {'note': 'jane@example.com'}, raise_on_pii=True,
            )
        self.assertIn('payload', str(ctx.exception))

    def test_default_context_in_audit_log(self):
        logger = mock.Mock()
        self.service.scrub({'note': 'jane@example.com'}, audit_logger=logger)
        call = logger.warning.call_args_list[0]
        self.assertEqual(call.args[1], 'payload')


class TestAllFlagsTogether(unittest.TestCase):

    def test_strict_plus_raise_plus_audit_on_validate(self):
        service = PiiService()
        logger = mock.Mock()
        with self.assertRaises(PIIDetectedError):
            service.validate(
                {'note': 'patient 1990/05/15 active'},
                strict=True,
                raise_on_pii=True,
                audit_logger=logger,
                context='medical_record',
            )
        self.assertEqual(len(logger.warning.call_args_list), 1)
        self.assertEqual(logger.warning.call_args.args[1], 'medical_record')

    def test_strict_plus_raise_plus_audit_on_scrub(self):
        service = PiiService()
        logger = mock.Mock()
        with self.assertRaises(PIIDetectedError):
            service.scrub(
                {'note': 'patient 1990/05/15 active'},
                strict=True,
                raise_on_pii=True,
                audit_logger=logger,
                context='medical_record',
            )
        self.assertEqual(len(logger.warning.call_args_list), 1)


# ---------------------------------------------------------------------------
# Statelessness — repeated calls on one instance are independent
# ---------------------------------------------------------------------------


class TestServiceIsStateless(unittest.TestCase):

    def test_repeated_validate_calls_are_independent(self):
        service = PiiService()
        first = service.validate({'note': 'jane@example.com'})
        second = service.validate({'note': 'jane@example.com'})
        self.assertEqual(
            [(finding.pattern_name, finding.redacted_preview) for finding in first],
            [(finding.pattern_name, finding.redacted_preview) for finding in second],
        )

    def test_repeated_scrub_calls_are_independent(self):
        service = PiiService()
        first = service.scrub({'note': 'jane@example.com'})
        second = service.scrub({'note': 'jane@example.com'})
        self.assertEqual(first, second)

    def test_two_instances_produce_the_same_scrub_output(self):
        payload = {'note': 'reach jane@example.com today'}
        self.assertEqual(
            PiiService().scrub(payload),
            PiiService().scrub(payload),
        )

    def test_alternating_payloads_stay_independent(self):
        service = PiiService()
        payload_x = {'note': 'jane@example.com'}
        payload_y = {'note': 'ssn 123-45-6789'}
        for _ in range(100):
            scrubbed_x = service.scrub(payload_x)
            scrubbed_y = service.scrub(payload_y)
            self.assertNotIn('jane@example.com', scrubbed_x['note'])
            self.assertNotIn('123-45-6789', scrubbed_y['note'])


# ---------------------------------------------------------------------------
# Cross-method invariants — validate() and scrub() must agree on detections
# ---------------------------------------------------------------------------


class TestValidateAndScrubAgreeOnDetections(unittest.TestCase):
    """A switch from one method to the other cannot change which
    detections an operator sees — both call sites must produce the
    same audit signal for the same input."""

    def setUp(self):
        self.service = PiiService()

    def test_validate_findings_match_scrub_findings_for_pii_payload(self):
        payload = {
            'email': 'jane@example.com',
            'ssn': '123-45-6789',
            'card': '4111 1111 1111 1111',
        }
        from_validate = sorted(
            (finding.pattern_name, finding.redacted_preview)
            for finding in self.service.validate(payload)
        )
        scrub_logger = mock.Mock()
        validate_logger = mock.Mock()
        self.service.validate(payload, audit_logger=validate_logger)
        self.service.scrub(payload, audit_logger=scrub_logger)
        # Both paths emit exactly one WARNING with the same summary string.
        self.assertEqual(len(validate_logger.warning.call_args_list), 1)
        self.assertEqual(len(scrub_logger.warning.call_args_list), 1)
        self.assertEqual(
            validate_logger.warning.call_args.args,
            scrub_logger.warning.call_args.args,
        )
        # And the findings list validate() returns is non-empty.
        self.assertTrue(from_validate)

    def test_validate_and_scrub_both_silent_on_clean_payload(self):
        clean = {'id': 'u1', 'display_name': 'Jane'}
        validate_logger = mock.Mock()
        scrub_logger = mock.Mock()
        self.service.validate(clean, audit_logger=validate_logger)
        self.service.scrub(clean, audit_logger=scrub_logger)
        validate_logger.warning.assert_not_called()
        scrub_logger.warning.assert_not_called()


if __name__ == '__main__':
    unittest.main()
