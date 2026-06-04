"""Tests for :class:`agent_core_lib.data_layers.service.pii_service.PiiService`.

One method — :meth:`PiiService.validate`. Three optional knobs:
``strict``, ``raise_on_pii``, ``audit_logger``. The tests below lock
the contract for each.
"""
from __future__ import annotations

import unittest
from unittest import mock

from agent_core_lib.data_layers.service.pii_service import PiiService
from agent_core_lib.pii.pii_scrub import PIIDetectedError


class TestValidateDefaultMode(unittest.TestCase):
    """``validate(payload)`` — no flags — returns a scrubbed copy."""

    def setUp(self):
        self.service = PiiService()

    def test_clean_payload_returns_equivalent_copy(self):
        payload = {'id': 'u1', 'display_name': 'Jane', 'rank': 5}
        self.assertEqual(self.service.validate(payload), payload)

    def test_email_in_dict_is_scrubbed(self):
        validated = self.service.validate({'note': 'reach jane@example.com'})
        self.assertNotIn('jane@example.com', validated['note'])
        self.assertIn('[redacted:email:host=example.com]', validated['note'])

    def test_nested_payload_is_walked(self):
        validated = self.service.validate({
            'users': [
                {'note': 'see jane@example.com'},
                {'note': 'and 123-45-6789 too'},
            ],
        })
        self.assertNotIn('jane@example.com', validated['users'][0]['note'])
        self.assertNotIn('123-45-6789', validated['users'][1]['note'])

    def test_input_payload_is_not_mutated(self):
        original = {'note': 'jane@example.com'}
        snapshot = dict(original)
        self.service.validate(original)
        self.assertEqual(original, snapshot)

    def test_string_input_is_supported(self):
        self.assertNotIn(
            'jane@example.com',
            self.service.validate('reach jane@example.com'),
        )

    def test_none_payload_returns_none(self):
        self.assertIsNone(self.service.validate(None))


class TestValidateStrictMode(unittest.TestCase):
    """``strict=True`` also runs ``phonenumbers`` + ``dateparser``."""

    def setUp(self):
        self.service = PiiService()

    def test_strict_catches_bare_dob_the_regex_misses(self):
        # The regex-only ``date_of_birth`` pattern is keyword-anchored
        # (``dob`` / ``date of birth`` / ``born``). A bare slash-form
        # date with no keyword falls through every regex (no phone /
        # plate collision either) but ``dateparser`` flags it as a
        # plausible DOB in strict mode.
        text = 'patient 1990/05/15 active'
        # Default (regex-only) → no raise.
        self.service.validate(text, strict=False, raise_on_pii=True)
        # Strict → ``dateparser`` finds the bare DOB.
        with self.assertRaises(PIIDetectedError):
            self.service.validate(text, strict=True, raise_on_pii=True)


class TestValidateRaiseOnPii(unittest.TestCase):
    """``raise_on_pii=True`` — raise instead of scrub."""

    def setUp(self):
        self.service = PiiService()

    def test_clean_payload_does_not_raise(self):
        self.service.validate(
            {'id': 'u1', 'display_name': 'Jane'},
            raise_on_pii=True,
        )

    def test_pii_payload_raises(self):
        with self.assertRaises(PIIDetectedError):
            self.service.validate(
                {'note': 'jane@example.com'},
                raise_on_pii=True,
            )

    def test_raised_error_message_carries_pattern_name_not_raw_value(self):
        with self.assertRaises(PIIDetectedError) as ctx:
            self.service.validate(
                {'note': 'jane@example.com'},
                raise_on_pii=True,
            )
        message = str(ctx.exception)
        self.assertIn('email', message)
        self.assertNotIn('jane@example.com', message)

    def test_raised_error_uses_context_in_message(self):
        with self.assertRaises(PIIDetectedError) as ctx:
            self.service.validate(
                {'note': 'jane@example.com'},
                raise_on_pii=True,
                context='admin_chat_response',
            )
        self.assertIn('admin_chat_response', str(ctx.exception))


class TestValidateAuditLogger(unittest.TestCase):
    """``audit_logger`` — emits one WARNING per scan that finds something."""

    def setUp(self):
        self.service = PiiService()

    def test_clean_payload_does_not_log(self):
        logger = mock.Mock()
        self.service.validate({'id': 'u1'}, audit_logger=logger)
        logger.warning.assert_not_called()

    def test_pii_payload_logs_one_warning_with_summary(self):
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

    def test_logged_summary_never_carries_raw_value(self):
        logger = mock.Mock()
        self.service.validate(
            {'note': 'jane@example.com'},
            audit_logger=logger,
        )
        full_log_call = ' '.join(str(arg) for arg in logger.warning.call_args.args)
        self.assertNotIn('jane@example.com', full_log_call)

    def test_logger_and_raise_can_combine(self):
        # ``audit_logger`` fires first, then ``raise_on_pii`` raises.
        logger = mock.Mock()
        with self.assertRaises(PIIDetectedError):
            self.service.validate(
                {'note': 'jane@example.com'},
                raise_on_pii=True,
                audit_logger=logger,
            )
        # The WARNING still fired before the raise.
        self.assertEqual(len(logger.warning.call_args_list), 1)


class TestValidateContainerShapes(unittest.TestCase):
    """``validate`` accepts every JSON-shaped container."""

    def setUp(self):
        self.service = PiiService()

    def test_list_payload(self):
        validated = self.service.validate(
            ['clean', 'reach jane@example.com', 'also clean'],
        )
        self.assertEqual(validated[0], 'clean')
        self.assertNotIn('jane@example.com', validated[1])
        self.assertEqual(validated[2], 'also clean')

    def test_tuple_payload_returns_tuple(self):
        validated = self.service.validate(('jane@example.com', 'clean'))
        self.assertIsInstance(validated, tuple)
        self.assertNotIn('jane@example.com', validated[0])

    def test_empty_dict_returns_empty_dict(self):
        self.assertEqual(self.service.validate({}), {})

    def test_empty_list_returns_empty_list(self):
        self.assertEqual(self.service.validate([]), [])

    def test_empty_string_returns_empty_string(self):
        self.assertEqual(self.service.validate(''), '')

    def test_mixed_nested_with_primitives(self):
        payload = {
            'id': 42,
            'active': True,
            'metadata': None,
            'tags': ['urgent', 'jane@example.com'],
            'nested': {'count': 7, 'note': 'see 123-45-6789'},
        }
        validated = self.service.validate(payload)
        # Primitives pass through.
        self.assertEqual(validated['id'], 42)
        self.assertEqual(validated['active'], True)
        self.assertIsNone(validated['metadata'])
        self.assertEqual(validated['nested']['count'], 7)
        # PII scrubbed.
        self.assertNotIn('jane@example.com', validated['tags'][1])
        self.assertNotIn('123-45-6789', validated['nested']['note'])


class TestValidateMultiplePiiTypes(unittest.TestCase):
    """A single payload can carry several PII types at once. Every
    category that fires must be scrubbed; nothing escapes."""

    def setUp(self):
        self.service = PiiService()

    def test_email_phone_ssn_credit_card_together(self):
        payload = {
            'email_field': 'jane@example.com',
            'phone_field': '+1 212 555 1234',
            'ssn_field': '123-45-6789',
            'card_field': '4111 1111 1111 1111',
        }
        validated = self.service.validate(payload)
        self.assertNotIn('jane@example.com', validated['email_field'])
        self.assertNotIn('555 1234', validated['phone_field'])
        self.assertNotIn('123-45-6789', validated['ssn_field'])
        self.assertNotIn('4111', validated['card_field'])

    def test_iban_bitcoin_jwt_together(self):
        payload = {
            'iban': 'GB82WEST12345698765432',
            'wallet': '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa',
            'token': 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signature_here',
        }
        validated = self.service.validate(payload)
        self.assertNotIn('GB82WEST12345698765432', validated['iban'])
        self.assertNotIn('1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa', validated['wallet'])
        self.assertNotIn('eyJhbGc', validated['token'])


class TestValidateRoundTrip(unittest.TestCase):
    """Validating an already-validated payload must be idempotent —
    the scrubber's replacement strings (``[redacted:<pattern>]``) are
    designed not to re-match any pattern, so a second pass through
    ``validate`` produces the same output as the first."""

    def setUp(self):
        self.service = PiiService()

    def test_double_validate_is_idempotent(self):
        original = {'note': 'reach jane@example.com today'}
        once = self.service.validate(original)
        twice = self.service.validate(once)
        self.assertEqual(once, twice)

    def test_validated_output_passes_raise_on_pii(self):
        original = {'note': 'jane@example.com and 4111111111111111'}
        validated = self.service.validate(original)
        # The output is clean — a follow-up validate with raise_on_pii
        # must not raise.
        self.service.validate(validated, raise_on_pii=True)


class TestValidateNonStandardTypes(unittest.TestCase):
    """``json.dumps(default=str)`` keeps the scan from crashing on
    dates / Decimals / UUIDs the way a strict JSON serializer would."""

    def setUp(self):
        self.service = PiiService()

    def test_payload_with_date(self):
        from datetime import date
        payload = {'created_at': date(2024, 1, 1), 'note': 'jane@example.com'}
        validated = self.service.validate(payload)
        # The date itself isn't text PII; the email is scrubbed.
        self.assertEqual(validated['created_at'], date(2024, 1, 1))
        self.assertNotIn('jane@example.com', validated['note'])

    def test_payload_with_decimal(self):
        from decimal import Decimal
        payload = {'amount': Decimal('100.50'), 'note': 'card 4111111111111111'}
        validated = self.service.validate(payload)
        self.assertEqual(validated['amount'], Decimal('100.50'))
        self.assertNotIn('4111111111111111', validated['note'])

    def test_payload_with_uuid(self):
        import uuid
        payload = {'request_id': uuid.uuid4(), 'note': 'reach jane@example.com'}
        validated = self.service.validate(payload)
        # The UUID is preserved as the same type (containers walk by
        # type, non-text primitives pass through).
        self.assertIsInstance(validated['request_id'], uuid.UUID)
        self.assertNotIn('jane@example.com', validated['note'])

    def test_int_payload(self):
        self.assertEqual(self.service.validate(42), 42)

    def test_bool_payload(self):
        self.assertEqual(self.service.validate(True), True)
        self.assertEqual(self.service.validate(False), False)


class TestValidateRealisticChatToolPayload(unittest.TestCase):
    """End-to-end shapes the LLM tool-result boundary actually sees —
    list-of-dicts user search results, paginated responses, error
    envelopes with comment fields."""

    def setUp(self):
        self.service = PiiService()

    def test_user_search_results_shape(self):
        payload = {
            'users': [
                {
                    'id': 1,
                    'display_name': 'Jane',
                    'note': 'contact at jane@example.com or call 212-555-1234',
                },
                {
                    'id': 2,
                    'display_name': 'John',
                    'note': 'SSN 123-45-6789 on file',
                },
            ],
            'total_count': 2,
            'page': 1,
        }
        validated = self.service.validate(payload)
        # Structure preserved.
        self.assertEqual(validated['total_count'], 2)
        self.assertEqual(validated['page'], 1)
        self.assertEqual(len(validated['users']), 2)
        # IDs and display names pass through.
        self.assertEqual(validated['users'][0]['id'], 1)
        self.assertEqual(validated['users'][0]['display_name'], 'Jane')
        # PII in notes is scrubbed.
        self.assertNotIn('jane@example.com', validated['users'][0]['note'])
        self.assertNotIn('123-45-6789', validated['users'][1]['note'])

    def test_chat_message_history_shape(self):
        payload = [
            {'role': 'user', 'content': 'find user jane@example.com'},
            {'role': 'assistant', 'content': 'Found 1 user. Email withheld.'},
            {'role': 'user', 'content': 'their ssn is 123-45-6789'},
        ]
        validated = self.service.validate(payload)
        self.assertEqual(len(validated), 3)
        self.assertNotIn('jane@example.com', validated[0]['content'])
        # The clean assistant message is untouched.
        self.assertEqual(validated[1]['content'], 'Found 1 user. Email withheld.')
        self.assertNotIn('123-45-6789', validated[2]['content'])


class TestServiceIsStateless(unittest.TestCase):
    """``PiiService`` holds no instance state — multiple ``validate``
    calls on the same instance must be independent and deterministic."""

    def test_repeated_calls_on_same_instance_are_independent(self):
        service = PiiService()
        first = service.validate({'note': 'jane@example.com'})
        second = service.validate({'note': 'jane@example.com'})
        self.assertEqual(first, second)

    def test_two_instances_produce_the_same_output(self):
        instance_a = PiiService()
        instance_b = PiiService()
        payload = {'note': 'reach jane@example.com today'}
        self.assertEqual(
            instance_a.validate(payload),
            instance_b.validate(payload),
        )

    def test_concurrent_calls_do_not_interfere(self):
        # Loose check — issue 200 alternating validates with two
        # different payloads. If any internal state leaked the
        # outputs would interleave.
        service = PiiService()
        payload_x = {'note': 'jane@example.com'}
        payload_y = {'note': 'ssn 123-45-6789'}
        for index in range(100):
            validated_x = service.validate(payload_x)
            validated_y = service.validate(payload_y)
            self.assertNotIn('jane@example.com', validated_x['note'])
            self.assertNotIn('123-45-6789', validated_y['note'])


class TestValidateContextDefault(unittest.TestCase):
    """``context`` defaults to ``'payload'`` for both the audit log
    and the raised-error message."""

    def setUp(self):
        self.service = PiiService()

    def test_default_context_in_raised_error(self):
        with self.assertRaises(PIIDetectedError) as ctx:
            self.service.validate(
                {'note': 'jane@example.com'},
                raise_on_pii=True,
            )
        # Default ``context='payload'`` appears in the message.
        self.assertIn('payload', str(ctx.exception))

    def test_default_context_in_audit_log(self):
        logger = mock.Mock()
        self.service.validate(
            {'note': 'jane@example.com'},
            audit_logger=logger,
        )
        call = logger.warning.call_args_list[0]
        self.assertEqual(call.args[1], 'payload')


class TestValidateAllFlagsTogether(unittest.TestCase):
    """The three knobs (``strict`` / ``raise_on_pii`` / ``audit_logger``)
    must all behave correctly when combined."""

    def test_strict_plus_raise_plus_audit(self):
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
        # Audit fired on the strict-detector finding before the raise.
        self.assertEqual(len(logger.warning.call_args_list), 1)
        self.assertEqual(logger.warning.call_args.args[1], 'medical_record')

    def test_strict_plus_scrub_path(self):
        # No raise, no audit — just strict scrubbing returning a clean copy.
        service = PiiService()
        text = 'patient 1990/05/15 active'
        validated = service.validate(text, strict=True)
        # Default scrubber doesn't redact the bare DOB the strict
        # detector found (the regex scrubber only knows the patterns
        # registered in ``_PII_PATTERNS``; ``dob_strict`` isn't in
        # there). The text comes back unchanged — strict mode's value
        # is detection (audit / raise), not scrub.
        self.assertEqual(validated, text)


if __name__ == '__main__':
    unittest.main()
