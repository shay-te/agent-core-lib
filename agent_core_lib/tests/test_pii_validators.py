"""Direct tests for the per-pattern checksum / range validators.

These tests exercise the validator functions in isolation (not through
the regex pipeline). The pipeline-integration tests live in the
``test_pii_*_bulletproof`` files; here we lock the algorithms
themselves against well-known issuer-published vectors so a future
refactor of the validator doesn't silently regress the family.

Six validators, one TestCase per family:

* :class:`TestLuhnValidator` — credit-card checksum (Luhn, mod-10).
* :class:`TestSsnAreaGroupSerialValidator` — SSA reservation rules.
* :class:`TestIbanMod97Validator` — ISO 13616 mod-97 check.
* :class:`TestAbaRoutingChecksumValidator` — Federal Reserve weighted sum.
* :class:`TestVinCheckDigitValidator` — NHTSA 49 CFR §565 mod-11.
* :class:`TestIlIdCheckDigitValidator` — Israeli teudat zehut check digit.
"""
from __future__ import annotations

import unittest

from agent_core_lib.pii.pii_patterns import (
    _aba_routing_checksum_valid,
    _cn_resident_id_check_valid,
    _iban_mod97_valid,
    _iccid_luhn_valid,
    _il_id_check_digit_valid,
    _imei_luhn_valid,
    _jp_my_number_check_valid,
    _luhn_valid,
    _mx_clabe_check_valid,
    _ssn_area_group_serial_valid,
    _vin_check_digit_valid,
    _za_id_luhn_valid,
)


class TestLuhnValidator(unittest.TestCase):
    """Luhn (mod-10) checksum — credit card numbers."""

    _VALID_PANS = (
        '4111111111111111',   # Visa test
        '4111 1111 1111 1111',
        '4111-1111-1111-1111',
        '5500000000000004',   # Mastercard
        '378282246310005',    # Amex 15
        '6011000400000000',   # Discover
        '4012888888881881',   # Visa test
        '5555555555554444',   # Mastercard Stripe test
    )
    _INVALID_PANS = (
        '4111111111111112',   # Last digit off by one
        '5500000000000005',
        '4012-8888-8888-1882',
        '1234567890123456',
        '0000000000000001',
    )
    _TOO_SHORT_OR_LONG = (
        '12345',
        '123456789012',          # 12 digits
        '12345678901234567890',  # 20 digits
    )

    def test_known_valid_pans(self):
        for pan in self._VALID_PANS:
            with self.subTest(pan=pan):
                self.assertTrue(_luhn_valid(pan))

    def test_known_invalid_pans(self):
        for pan in self._INVALID_PANS:
            with self.subTest(pan=pan):
                self.assertFalse(_luhn_valid(pan))

    def test_length_out_of_range(self):
        for value in self._TOO_SHORT_OR_LONG:
            with self.subTest(value=value):
                self.assertFalse(_luhn_valid(value))


class TestSsnAreaGroupSerialValidator(unittest.TestCase):
    """SSA reservation rules — areas/groups/serials never issued."""

    _ACCEPTED = (
        '123-45-6789',
        '001-01-0001',
        '123456789',  # dashes optional
    )
    _REJECTED_RESERVED = (
        '000-12-3456',  # area 000
        '666-12-3456',  # area 666
        '900-12-3456',  # ITIN range
        '999-12-3456',
        '123-00-3456',  # group 00
        '123-45-0000',  # serial 0000
    )

    def test_accepted_real_shapes(self):
        for ssn in self._ACCEPTED:
            with self.subTest(ssn=ssn):
                self.assertTrue(_ssn_area_group_serial_valid(ssn))

    def test_rejected_reserved_shapes(self):
        for ssn in self._REJECTED_RESERVED:
            with self.subTest(ssn=ssn):
                self.assertFalse(_ssn_area_group_serial_valid(ssn))

    def test_wrong_digit_count_rejected(self):
        # The validator strips dashes before counting, so the legacy
        # ``XXX-XX-XXXX`` form passes shape even with misplaced dashes
        # — but anything that doesn't reduce to exactly nine digits
        # is rejected.
        self.assertFalse(_ssn_area_group_serial_valid('12345678'))
        self.assertFalse(_ssn_area_group_serial_valid('1234567890'))


class TestIbanMod97Validator(unittest.TestCase):
    """ISO 13616 mod-97 — IBAN checksum."""

    _VALID_IBANS = (
        'GB82WEST12345698765432',
        'DE89370400440532013000',
        'NL91ABNA0417164300',
        'FR1420041010050500013M02606',
        'CH9300762011623852957',
        'BE68539007547034',
        # space-separated form (same number)
        'GB82 WEST 1234 5698 7654 32',
        'DE89 3704 0044 0532 0130 00',
    )
    _INVALID_IBANS = (
        # off-by-one on the check block
        'GB83WEST12345698765432',
        'DE90370400440532013000',
        # transposed digits in body
        'NL91ABNA0417164003',
    )

    def test_known_valid_ibans(self):
        for iban in self._VALID_IBANS:
            with self.subTest(iban=iban):
                self.assertTrue(_iban_mod97_valid(iban))

    def test_known_invalid_ibans(self):
        for iban in self._INVALID_IBANS:
            with self.subTest(iban=iban):
                self.assertFalse(_iban_mod97_valid(iban))

    def test_too_short_rejected(self):
        self.assertFalse(_iban_mod97_valid('GB82'))

    def test_non_alphanumeric_char_rejected(self):
        # The validator only accepts A-Z and 0-9 after stripping
        # spaces/dashes; an embedded ``$`` breaks the run.
        self.assertFalse(_iban_mod97_valid('GB82WEST1234$698765432'))


class TestAbaRoutingChecksumValidator(unittest.TestCase):
    """Federal Reserve weighted 3-7-1 mod-10 — ABA routing number."""

    # These are real bank routing numbers published by the Fed
    # (well-known testers used in the Federal Reserve's ABA examples).
    _VALID_ABAS = (
        '021000021',   # JPMorgan Chase, NY
        '011000015',   # Federal Reserve Bank of Boston
        '026009593',   # Bank of America, NY
        '121000358',   # Bank of America, CA
    )
    _INVALID_ABAS = (
        '123456789',
        '999999999',
        '000000001',
        '421042111',   # Presidio negative — fails checksum
    )

    def test_known_valid_routing_numbers(self):
        for routing in self._VALID_ABAS:
            with self.subTest(routing=routing):
                self.assertTrue(_aba_routing_checksum_valid(routing))

    def test_known_invalid_routing_numbers(self):
        for routing in self._INVALID_ABAS:
            with self.subTest(routing=routing):
                self.assertFalse(_aba_routing_checksum_valid(routing))

    def test_wrong_digit_count_rejected(self):
        self.assertFalse(_aba_routing_checksum_valid('12345678'))
        self.assertFalse(_aba_routing_checksum_valid('1234567890'))


class TestVinCheckDigitValidator(unittest.TestCase):
    """NHTSA 49 CFR §565 mod-11 — VIN check digit at position 9."""

    # Real published VINs from NHTSA test vectors / NIST mod-11
    # references. The check digit (position 9, 0-indexed 8) is what
    # the validator enforces.
    _VALID_VINS = (
        '1M8GDM9AXKP042788',     # NIST canonical example
        '1HGCM82633A004352',     # Honda Accord — check digit ``3`` at pos 9
        '11111111111111111',     # All-ones edge case (mod-11 happens to validate)
    )
    _INVALID_VINS = (
        '1HGCM82633A123456',     # Off check digit
        '1HGCM82633A004353',     # Last digit altered
        'ABCDEFGHJKLMNPRST',     # Random alpha
    )

    def test_known_valid_vins(self):
        for vin in self._VALID_VINS:
            with self.subTest(vin=vin):
                self.assertTrue(_vin_check_digit_valid(vin))

    def test_known_invalid_vins(self):
        for vin in self._INVALID_VINS:
            with self.subTest(vin=vin):
                self.assertFalse(_vin_check_digit_valid(vin))

    def test_wrong_length_rejected(self):
        self.assertFalse(_vin_check_digit_valid('1HGCM82633A00435'))   # 16
        self.assertFalse(_vin_check_digit_valid('1HGCM82633A0043522'))  # 18

    def test_forbidden_chars_rejected(self):
        # I, O, Q are excluded by the VIN spec to avoid confusion
        # with 1 and 0; they're missing from ``_VIN_CHAR_VALUES``.
        self.assertFalse(_vin_check_digit_valid('1HGCM82633O004352'))


class TestIlIdCheckDigitValidator(unittest.TestCase):
    """Israeli teudat zehut — Luhn-like check digit at position 9."""

    _VALID_IDS = (
        '123456782',
        '111111118',
        '000000018',
    )
    _INVALID_IDS = (
        '123456789',  # off-by-one
        '111111111',
        '999999999',
    )

    def test_known_valid_ids(self):
        for il_id in self._VALID_IDS:
            with self.subTest(il_id=il_id):
                self.assertTrue(_il_id_check_digit_valid(il_id))

    def test_known_invalid_ids(self):
        for il_id in self._INVALID_IDS:
            with self.subTest(il_id=il_id):
                self.assertFalse(_il_id_check_digit_valid(il_id))

    def test_too_short_rejected(self):
        self.assertFalse(_il_id_check_digit_valid('1234'))

    def test_legacy_padded_short_form_accepted(self):
        # Legacy holders carry 7- or 8-digit IDs; the validator
        # left-pads with zeros before running the algorithm. ``18``
        # padded to ``000000018`` is valid.
        self.assertTrue(_il_id_check_digit_valid('18'.zfill(9)))


class TestCnResidentIdValidator(unittest.TestCase):
    def test_valid_id(self):
        self.assertTrue(_cn_resident_id_check_valid('110101199001010007'))

    def test_invalid_check_digit(self):
        self.assertFalse(_cn_resident_id_check_valid('110101199001010000'))

    def test_x_check_char_accepted(self):
        self.assertTrue(_cn_resident_id_check_valid('23010120000202100X'))

    def test_wrong_length_rejected(self):
        self.assertFalse(_cn_resident_id_check_valid('110101'))

    def test_non_digit_in_prefix_rejected(self):
        self.assertFalse(_cn_resident_id_check_valid('A1010119900101000X'))


class TestImeiLuhnValidator(unittest.TestCase):
    def test_valid_imei(self):
        self.assertTrue(_imei_luhn_valid('490154203237518'))

    def test_invalid_luhn(self):
        self.assertFalse(_imei_luhn_valid('490154203237510'))

    def test_wrong_length_rejected(self):
        self.assertFalse(_imei_luhn_valid('12345'))


class TestIccidLuhnValidator(unittest.TestCase):
    def test_valid_iccid(self):
        self.assertTrue(_iccid_luhn_valid('89014103211118510720'))

    def test_invalid_iccid(self):
        self.assertFalse(_iccid_luhn_valid('89014103211118510721'))

    def test_wrong_length_rejected(self):
        self.assertFalse(_iccid_luhn_valid('123456'))


class TestZaIdValidator(unittest.TestCase):
    def test_valid_id(self):
        self.assertTrue(_za_id_luhn_valid('8001010000008'))

    def test_invalid_check(self):
        self.assertFalse(_za_id_luhn_valid('8001010000000'))

    def test_wrong_length_rejected(self):
        self.assertFalse(_za_id_luhn_valid('12345'))


class TestJpMyNumberValidator(unittest.TestCase):
    def test_valid_number(self):
        self.assertTrue(_jp_my_number_check_valid('100000000005'))

    def test_invalid_check(self):
        self.assertFalse(_jp_my_number_check_valid('100000000000'))

    def test_wrong_length_rejected(self):
        self.assertFalse(_jp_my_number_check_valid('1234'))


class TestMxClabeValidator(unittest.TestCase):
    def test_valid_clabe(self):
        self.assertTrue(_mx_clabe_check_valid('002194000000000037'))

    def test_invalid_check(self):
        self.assertFalse(_mx_clabe_check_valid('002194000000000000'))

    def test_wrong_length_rejected(self):
        self.assertFalse(_mx_clabe_check_valid('123456'))


if __name__ == '__main__':
    unittest.main()
