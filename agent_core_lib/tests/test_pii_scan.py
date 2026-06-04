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

from agent_core_lib.pii.pii_patterns import (
    PII_PATTERN_NAMES,
    find_pii_patterns,
    summarize_pii_findings,
)
from agent_core_lib.pii.pii_scan import scan_text_for_pii


_PATTERN_MODULE = 'agent_core_lib.pii.pii_patterns'


# The single locked-names contract for the workspace. Cross-file
# locked-name asserts (in ``test_pii_adversarial`` and
# ``test_pii_third_party_corpora``) reference this frozenset directly
# so a single edit here propagates across the suite.
_EXPECTED_PATTERN_NAMES = frozenset({
    # ---- contact (url / twitter_handle / skype_handle borrowed from
    # ----          scrubadub — see prior-art note in pii_patterns.py;
    # ----          instagram_handle / mastodon_handle added in the
    # ----          follow-up that landed the validator dispatch)
    'url', 'email', 'phone', 'twitter_handle', 'skype_handle',
    'instagram_handle', 'mastodon_handle',
    # ---- US government IDs
    'ssn', 'itin', 'ein',
    'us_passport', 'us_drivers_license', 'medicare_mbi',
    # ---- intl government IDs (uk_utr from scrubadub; second wave =
    # ---- per-country expansion incl. ca_sin/au_tfn/de_steuer_id/
    # ---- in_aadhaar/in_pan/br_cpf/br_cnpj/es_nif/es_passport/
    # ---- de_passport/sg_fin/pl_pesel/uk_nhs/au_medicare; third wave
    # ---- = catalog close-outs: in_gstin/it_fiscal_code/es_nie/
    # ---- se_personnummer/in_voter/fi_personal_identity_code/us_npi/
    # ---- au_abn/au_acn/sg_uen/th_tnin/tr_national_id)
    'uk_nino', 'uk_utr', 'uk_passport', 'ca_passport', 'au_passport',
    'es_passport', 'de_passport',
    'ca_sin', 'au_tfn', 'de_steuer_id',
    'in_aadhaar', 'in_pan', 'br_cpf', 'br_cnpj',
    'es_nif', 'sg_fin', 'pl_pesel', 'uk_nhs', 'au_medicare',
    'in_gstin', 'it_fiscal_code', 'es_nie', 'se_personnummer',
    'in_voter', 'fi_personal_identity_code',
    'us_npi', 'au_abn', 'au_acn', 'sg_uen', 'th_tnin', 'tr_national_id',
    # ---- Israeli teudat zehut + expansion-batch government IDs
    'il_id',
    'cn_resident_id', 'jp_my_number', 'kr_rrn', 'ru_inn',
    'mx_curp', 'mx_rfc', 'ar_cuil_cuit', 'za_id', 'nz_ird', 'us_dea',
    'medical_record_number',
    # ---- financial
    'credit_card', 'credit_card_cvv', 'iban', 'swift_bic',
    'us_routing_number', 'us_bank_account', 'bitcoin_address',
    # ---- crypto wallets (financial)
    'ethereum_address', 'monero_address', 'solana_address', 'litecoin_address',
    # ---- bank (financial)
    'in_ifsc', 'au_bsb', 'mx_clabe', 'jp_zengin',
    # ---- postal
    'us_zip', 'uk_postcode', 'ca_postcode', 'nl_postcode',
    'de_postcode', 'fr_postcode', 'it_postcode', 'es_postcode',
    'au_postcode', 'jp_postcode', 'br_cep', 'in_pincode',
    'il_postcode', 'se_postcode', 'dk_postcode', 'no_postcode',
    'fi_postcode', 'ch_postcode',
    # ---- network / device
    'ipv4', 'ipv6', 'mac_address',
    'imei', 'imsi', 'iccid', 'android_id', 'ios_udid',
    'uuid_v4', 'aws_instance_id',
    # ---- session / token
    'jwt',
    # ---- geolocation
    'gps_coordinates',
    # ---- vehicle
    'vin', 'us_license_plate',
    # ---- address (UNA-2727 expansion — multiple regex families)
    'street_address_with_city', 'street_address_with_unit',
    'street_address', 'street_address_intl', 'po_box',
    # ---- temporal
    'date_of_birth',
    # ---- additional social handles (contact)
    'linkedin_url', 'github_url', 'discord_id', 'telegram_handle', 'tiktok_handle',
    # ---- long-tail crypto wallets (financial)
    'tron_address', 'cardano_address', 'polkadot_address',
    'cosmos_address', 'ripple_address',
    # ---- long-tail government IDs
    'eg_national_id', 'pk_cnic', 'bd_nid', 'vn_national_id', 'id_ktp',
    'ph_tin', 'sa_nin', 'ng_nin', 'ke_id', 'gh_ghana_card',
    # ---- long-tail postcodes
    'za_postcode', 'nz_postcode', 'ru_postcode', 'kr_postcode',
    'th_postcode', 'tw_postcode', 'hk_postcode', 'sg_postcode',
    # ---- long-tail social handles
    'snapchat_handle', 'whatsapp_number', 'signal_handle',
    'slack_user_id', 'bluesky_handle',
    # ---- long-tail session / auth tokens (credential)
    'oauth_bearer', 'php_session_id', 'jsession_id', 'csrf_token',
    # ---- long-tail vehicle license plates
    'uk_license_plate', 'eu_license_plate', 'ca_license_plate',
    # ---- healthcare codes (government_id tier)
    'clia', 'ndc_drug_code', 'icd10_code',
})


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
        # 1HGCM82633A004352 is shape-AND-check-digit valid (NHTSA-49 CFR §565
        # mod-11 holds). The previous test value ``...A123456`` is shape-only
        # and is correctly rejected by the new check-digit validator.
        findings = find_pii_patterns('VIN 1HGCM82633A004352 recorded')
        self.assertIn('vin', [f.pattern_name for f in findings])

    def test_street_address_match(self):
        findings = find_pii_patterns('mail to 742 Evergreen Terrace please')
        self.assertIn('street_address', [f.pattern_name for f in findings])

    def test_street_address_with_unit_match(self):
        # The unit-modifier shape (apt/suite/#) — common in US mailing.
        findings = find_pii_patterns('ship to 100 Main St Apt 5 please')
        self.assertIn('street_address_with_unit', [f.pattern_name for f in findings])

    def test_street_address_with_city_match(self):
        # The full-line shape (street + city + state + zip).
        findings = find_pii_patterns(
            'mail to 100 Main St, Springfield, IL 12345 today'
        )
        self.assertIn('street_address_with_city', [f.pattern_name for f in findings])

    def test_street_address_intl_match(self):
        # European number-trails-street shape (Hauptstraße 12 / Rue de la Paix 5).
        findings_de = find_pii_patterns('Lieferadresse: Hauptstraße 12 in Berlin')
        self.assertIn('street_address_intl', [f.pattern_name for f in findings_de])
        findings_fr = find_pii_patterns('adresse: Rue de la Paix 5 à Paris')
        self.assertIn('street_address_intl', [f.pattern_name for f in findings_fr])

    def test_po_box_match(self):
        findings = find_pii_patterns('use P.O. Box 1234 for billing')
        self.assertIn('po_box', [f.pattern_name for f in findings])

    def test_date_of_birth_match(self):
        findings = find_pii_patterns('dob 1990-05-12 on file')
        self.assertIn('date_of_birth', [f.pattern_name for f in findings])

    def test_credit_card_cvv_match(self):
        findings = find_pii_patterns('cvv 123 from order page')
        self.assertIn('credit_card_cvv', [f.pattern_name for f in findings])

    # ---- borrowed-from-scrubadub patterns (see prior-art note in
    # pii_patterns.py for the survey + adopted vs. follow-up split).

    def test_url_match(self):
        findings = find_pii_patterns(
            'reset link https://example.com/u/42/reset_token=abc sent'
        )
        self.assertIn('url', [f.pattern_name for f in findings])

    def test_url_with_embedded_email_yields_both_findings(self):
        # Both fire on this string; the overlap resolution that keeps the
        # URL span when scrubbing is exercised in the pii_scrub suite.
        findings = find_pii_patterns(
            'see https://host/u/jane@example.com/profile'
        )
        names = [f.pattern_name for f in findings]
        self.assertIn('url', names)
        self.assertIn('email', names)

    def test_twitter_handle_match(self):
        findings = find_pii_patterns('follow @some_user for updates')
        self.assertIn('twitter_handle', [f.pattern_name for f in findings])

    def test_twitter_handle_does_not_clip_email_host(self):
        # The negative lookbehind must reject ``@`` preceded by any
        # email-local-part character — ``twitter_handle`` may not
        # silently steal ``@example`` out of ``jane@example.com``.
        findings = find_pii_patterns('reach jane@example.com please')
        self.assertNotIn('twitter_handle', [f.pattern_name for f in findings])

    def test_skype_handle_match(self):
        findings = find_pii_patterns('call me on skype jane.doe2025 today')
        self.assertIn('skype_handle', [f.pattern_name for f in findings])

    def test_uk_utr_match(self):
        findings = find_pii_patterns('please remit using UTR 1234567890K')
        self.assertIn('uk_utr', [f.pattern_name for f in findings])

    # ---- remaining per-pattern coverage (every locked name above is
    # ---- backed by at least one positive-match assertion).

    def test_phone_match(self):
        findings = find_pii_patterns('call me at +1 555 123 4567 thanks')
        self.assertIn('phone', [f.pattern_name for f in findings])

    def test_us_passport_match(self):
        # 1 letter + 9 digits (newer-issue US passport shape). The bare
        # 9-digit form also collides with ``uk_passport`` /
        # ``us_routing_number`` (documented overlap — false positives are
        # acceptable per the prior-art note); the test here only locks
        # that the named pattern fires.
        findings = find_pii_patterns('US passport A123456789 issued')
        self.assertIn('us_passport', [f.pattern_name for f in findings])

    def test_us_drivers_license_match(self):
        # The ``[A-Z]\d{7}`` arm: California / Florida-style.
        findings = find_pii_patterns('DL B1234567 confirmed')
        self.assertIn('us_drivers_license', [f.pattern_name for f in findings])

    def test_us_drivers_license_eight_digit_arm_match(self):
        # The ``\d{8}`` arm: states that use 8-digit numeric DLs.
        findings = find_pii_patterns('drivers license 12345678 on file')
        self.assertIn('us_drivers_license', [f.pattern_name for f in findings])

    def test_medicare_mbi_match(self):
        # MBI shape (regex positions, post-Jan-2020 CMS spec):
        #   1=digit(1-9), 2=alpha, 3=alphanum, 4=digit,
        #   (hyphen?) 5=alpha, 6=alphanum, 7=digit,
        #   (hyphen?) 8=alpha, 9=alpha, 10=digit, 11=digit
        # Hyphens between the three blocks are optional in the regex;
        # test both. ``1AB2-CD3-EF45`` satisfies every position.
        findings_hyphen = find_pii_patterns('MBI 1AB2-CD3-EF45 confirmed')
        self.assertIn('medicare_mbi', [f.pattern_name for f in findings_hyphen])
        findings_no_hyphen = find_pii_patterns('mbi 1AB2CD3EF45 confirmed')
        self.assertIn('medicare_mbi', [f.pattern_name for f in findings_no_hyphen])

    def test_uk_nino_match(self):
        # UK NI number: 2 valid prefix letters + 6 digits + suffix letter.
        # ``AB123456C`` uses valid prefix letters (A in first set, B in
        # second set) and a valid suffix.
        findings = find_pii_patterns('NI number AB123456C registered')
        self.assertIn('uk_nino', [f.pattern_name for f in findings])

    def test_uk_passport_match(self):
        # Bare 9-digit number (matches ``us_passport`` /
        # ``us_routing_number`` too — documented broadness; the test
        # only locks the named pattern is present).
        findings = find_pii_patterns('UK passport 987654321 issued')
        self.assertIn('uk_passport', [f.pattern_name for f in findings])

    def test_ca_passport_match(self):
        # 2 letters + 6 digits.
        findings = find_pii_patterns('Canadian passport AB123456 verified')
        self.assertIn('ca_passport', [f.pattern_name for f in findings])

    def test_au_passport_match(self):
        # 1 letter + 7 digits — same shape as the ``[A-Z]\d{7}`` arm
        # of ``us_drivers_license``; both fire on this input, which is
        # documented broadness.
        findings = find_pii_patterns('Aussie passport N1234567 ready')
        self.assertIn('au_passport', [f.pattern_name for f in findings])

    def test_us_routing_number_match(self):
        # 9-digit ABA routing number.
        findings = find_pii_patterns('routing 021000021 wire today')
        self.assertIn('us_routing_number', [f.pattern_name for f in findings])

    def test_us_bank_account_match(self):
        # Keyword-anchored ``account|acct`` + 4-17 digits.
        findings = find_pii_patterns('please debit account 12345678 today')
        self.assertIn('us_bank_account', [f.pattern_name for f in findings])

    def test_us_license_plate_match(self):
        # 5-8 alphanumerics with at least one digit; very loose by
        # design.
        findings = find_pii_patterns('plate ABC1234 spotted')
        self.assertIn('us_license_plate', [f.pattern_name for f in findings])

    # ---- expansion pass: per-country gov IDs, NL postcode, JWT, GPS ----
    # Closes the documented gaps in pii_patterns.py's "Expansion pass"
    # subsection (the reviewer's "make sure we support all the
    # unsupported data" follow-up).

    def test_ca_sin_match(self):
        # 3-3-3 hyphenated — distinct from SSN (3-2-4) and from a
        # standard US phone format (3-3-4).
        findings = find_pii_patterns('SIN 123-456-789 on file')
        self.assertIn('ca_sin', [f.pattern_name for f in findings])

    def test_au_tfn_match(self):
        # Keyword-anchored on ``TFN``.
        findings = find_pii_patterns('TFN 123 456 782 confirmed')
        self.assertIn('au_tfn', [f.pattern_name for f in findings])

    def test_de_steuer_id_match(self):
        # Keyword-anchored on Steuer-ID / Steueridentifikationsnummer.
        findings_short = find_pii_patterns('Steuer-ID 12 345 678 901 received')
        self.assertIn('de_steuer_id', [f.pattern_name for f in findings_short])
        findings_long = find_pii_patterns(
            'Steueridentifikationsnummer: 12345678901 verified'
        )
        self.assertIn('de_steuer_id', [f.pattern_name for f in findings_long])

    def test_in_aadhaar_match(self):
        # 4-4-4 space-grouped. Note: the regex requires a literal space
        # between groups (no-space form would collide with bare 12-digit
        # numbers which appear too often in unrelated contexts).
        findings = find_pii_patterns('Aadhaar 1234 5678 9012 verified')
        self.assertIn('in_aadhaar', [f.pattern_name for f in findings])

    def test_in_pan_match(self):
        # AAAAA9999A layout; unique-shape — no anchor needed.
        findings = find_pii_patterns('PAN ABCDE1234F on the form')
        self.assertIn('in_pan', [f.pattern_name for f in findings])

    def test_br_cpf_match(self):
        # 000.000.000-00 — distinctive punctuation, no anchor needed.
        findings = find_pii_patterns('CPF 123.456.789-09 registrado')
        self.assertIn('br_cpf', [f.pattern_name for f in findings])

    def test_br_cnpj_match(self):
        # 00.000.000/0000-00 — distinctive punctuation, no anchor.
        findings = find_pii_patterns('CNPJ 12.345.678/0001-95 confirmado')
        self.assertIn('br_cnpj', [f.pattern_name for f in findings])

    def test_nl_postcode_match(self):
        # 4 digits + 2 uppercase letters (canonical printed form
        # ``1011 AB``).
        findings = find_pii_patterns('ship to 1011 AB Amsterdam tomorrow')
        self.assertIn('nl_postcode', [f.pattern_name for f in findings])

    def test_jwt_match(self):
        # Three base64url segments joined by dots, ``eyJ`` prefix.
        token = (
            'eyJhbGciOiJIUzI1NiJ9'
            '.eyJzdWIiOiIxMjM0NTY3ODkwIn0'
            '.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c'
        )
        findings = find_pii_patterns(f'session token {token} expired')
        self.assertIn('jwt', [f.pattern_name for f in findings])

    def test_gps_coordinates_match(self):
        # Real coordinate pair (Amsterdam) — 4+ decimal places on each
        # side. Required precision keeps integer-pair noise out.
        findings = find_pii_patterns('last seen at 52.3676,4.9041 yesterday')
        self.assertIn('gps_coordinates', [f.pattern_name for f in findings])

    def test_gps_coordinates_does_not_match_integer_pair(self):
        # The minimum-precision floor (≥4 decimal places per side) is
        # the protection against generic comma-separated numbers.
        findings = find_pii_patterns('totals were 10, 20 and 30, 40 today')
        self.assertNotIn('gps_coordinates', [f.pattern_name for f in findings])

    # ---- second wave: standalone _PRESIDIO_*_UNSUPPORTED close-outs ----
    # Each of these flips a lockdown in
    # ``tests/test_pii_third_party_corpora.py`` from a negative
    # assertion (the pattern doesn't fire) to a positive one (the
    # pattern fires on Presidio's canonical test corpus).

    def test_es_passport_match(self):
        # 3 letters + 6 digits, case-insensitive (Presidio's corpus
        # includes lowercase and mixed-case forms).
        findings = find_pii_patterns('mi pasaporte es AAA123456')
        self.assertIn('es_passport', [f.pattern_name for f in findings])

    def test_es_passport_lowercase_match(self):
        findings = find_pii_patterns('Passport: aaa123456')
        self.assertIn('es_passport', [f.pattern_name for f in findings])

    def test_de_passport_match(self):
        # Restricted letter prefix (C/F/G/H/J/K/L/M/N/P/R/T/V/W/X/Y/Z)
        # + 8 alphanumeric. Shape-only, case-sensitive uppercase.
        findings = find_pii_patterns('Reisepass C01234565 ausgestellt')
        self.assertIn('de_passport', [f.pattern_name for f in findings])

    def test_de_passport_mixed_alphanumeric_body_match(self):
        # ``L01X00T44`` has digits and allowed letters in the body —
        # this is the canonical DE passport / ID card layout.
        findings = find_pii_patterns('Pass-Nr. L01X00T44 gültig')
        self.assertIn('de_passport', [f.pattern_name for f in findings])

    def test_es_nif_match(self):
        # 8 digits + check letter (canonical NIF).
        findings = find_pii_patterns('NIF 55555555K verificado')
        self.assertIn('es_nif', [f.pattern_name for f in findings])

    def test_es_nif_dashed_match(self):
        # 7 digits + dash + check letter (older form).
        findings = find_pii_patterns('NIF 1111111-G en el formulario')
        self.assertIn('es_nif', [f.pattern_name for f in findings])

    def test_sg_fin_match(self):
        # S/T/F/G/M prefix + 7 digits + check letter.
        findings = find_pii_patterns('NRIC S2740116C was processed')
        self.assertIn('sg_fin', [f.pattern_name for f in findings])

    def test_pl_pesel_match(self):
        # Keyword-anchored. The labelled form ``PESEL: digits`` is the
        # one we match — prose forms ("My pesel is X") would need a
        # looser gap regex that would over-match across unrelated text.
        # Bare 11-digit shape is also intentionally not matched (would
        # over-match phone / de_steuer_id / other 11-digit IDs).
        findings = find_pii_patterns('PESEL: 44051401458 on file')
        self.assertIn('pl_pesel', [f.pattern_name for f in findings])
        findings2 = find_pii_patterns('pesel 44051401458 verified')
        self.assertIn('pl_pesel', [f.pattern_name for f in findings2])

    def test_pl_pesel_does_not_match_bare_digits(self):
        # Confirms the keyword anchor — bare 11 digits don't fire as
        # pl_pesel (they may fire as phone instead, which still
        # results in redaction).
        findings = find_pii_patterns('order id 44051401458 closed')
        self.assertNotIn('pl_pesel', [f.pattern_name for f in findings])

    def test_uk_nhs_match(self):
        # Keyword-anchored on ``NHS``. The bare 3-3-4 form is
        # structurally identical to a US/CA phone, so we only flag
        # the keyword-labelled form (production-relevant case).
        findings = find_pii_patterns('NHS 401-023-2137 on file')
        self.assertIn('uk_nhs', [f.pattern_name for f in findings])

    def test_uk_nhs_does_not_match_bare_phone_shape(self):
        findings = find_pii_patterns('call 401-023-2137 between 9-5')
        self.assertNotIn('uk_nhs', [f.pattern_name for f in findings])

    def test_au_medicare_match(self):
        # 4-5-1 space-grouped 10 digits — the distinctive Medicare
        # layout. Bare-digit form is intentionally not matched
        # (Presidio uses a checksum validator for that case).
        findings = find_pii_patterns('Medicare 2123 45670 1 confirmed')
        self.assertIn('au_medicare', [f.pattern_name for f in findings])

    def test_au_medicare_does_not_match_bare_digits(self):
        # Confirms the spaced-only constraint — bare 10 digits don't
        # fire (they'd fire as phone, which is acceptable).
        findings = find_pii_patterns('reference 2123456701 on order')
        self.assertNotIn('au_medicare', [f.pattern_name for f in findings])

    # ---- third wave: catalog close-outs (deep corpora in the
    # ---- dedicated test_pii_intl_id_bulletproof.py file). Each
    # ---- one-line smoke test below is what the coverage-guarantee
    # ---- test_every_locked_pattern_name_has_a_positive_test
    # ---- discovers — the bulletproof file holds the wide
    # ---- positive/negative corpus.

    def test_in_gstin_match(self):
        # 15-char fully-deterministic layout.
        findings = find_pii_patterns('GSTIN: 27ABCDE1234F1Z5 verified')
        self.assertIn('in_gstin', [f.pattern_name for f in findings])

    def test_it_fiscal_code_match(self):
        # 16-char Codice Fiscale layout.
        findings = find_pii_patterns('CF: AAAAAA00B11C333Y registrato')
        self.assertIn('it_fiscal_code', [f.pattern_name for f in findings])

    def test_es_nie_match(self):
        # X/Y/Z prefix + 7-8 digits + check letter.
        findings = find_pii_patterns('Mi NIE es X9613851N')
        self.assertIn('es_nie', [f.pattern_name for f in findings])

    def test_se_personnummer_match(self):
        # 6-or-8 digits + dash + 4 digits (covers organisationsnummer
        # too — they share the dashed format).
        findings = find_pii_patterns('personnummer 871220-2384 verifierad')
        self.assertIn('se_personnummer', [f.pattern_name for f in findings])

    def test_in_voter_match(self):
        # 3 letters + 7 digits (Indian Voter ID / EPIC).
        findings = find_pii_patterns('voter card KSD1287349 issued')
        self.assertIn('in_voter', [f.pattern_name for f in findings])

    def test_fi_personal_identity_code_match(self):
        # DDMMYY + century-separator + 3 digits + check char.
        findings = find_pii_patterns('hetu 010594Y9032 vahvistettu')
        self.assertIn('fi_personal_identity_code',
                      [f.pattern_name for f in findings])

    def test_us_npi_match(self):
        # 10 digits, keyword-anchored on NPI.
        findings = find_pii_patterns('NPI: 1234567893 on file')
        self.assertIn('us_npi', [f.pattern_name for f in findings])

    def test_au_abn_match(self):
        # 11 digits, keyword-anchored on ABN.
        findings = find_pii_patterns('ABN 51 824 753 556 registered')
        self.assertIn('au_abn', [f.pattern_name for f in findings])

    def test_au_acn_match(self):
        # 9 digits, keyword-anchored on ACN.
        findings = find_pii_patterns('ACN: 000 000 019 active')
        self.assertIn('au_acn', [f.pattern_name for f in findings])

    def test_sg_uen_match(self):
        # 9-10 alphanumeric, keyword-anchored on UEN.
        findings = find_pii_patterns('UEN 53125226D was processed')
        self.assertIn('sg_uen', [f.pattern_name for f in findings])

    def test_th_tnin_match(self):
        # 13 digits, keyword-anchored on TNIN / Thai National ID /
        # Thai script.
        findings = find_pii_patterns('TNIN: 2345678901234')
        self.assertIn('th_tnin', [f.pattern_name for f in findings])

    def test_tr_national_id_match(self):
        # 11 digits, keyword-anchored on TC / TC Kimlik.
        findings = find_pii_patterns('TC Kimlik No: 10000000146')
        self.assertIn('tr_national_id', [f.pattern_name for f in findings])

    def test_instagram_handle_match(self):
        # Keyword-anchored on ``instagram`` / ``insta`` / ``ig``.
        findings = find_pii_patterns('instagram @jane_doe shared a post')
        self.assertIn('instagram_handle', [f.pattern_name for f in findings])

    def test_mastodon_handle_match(self):
        # Two-``@`` Mastodon federated handle.
        findings = find_pii_patterns('reply from @jane@mastodon.social today')
        self.assertIn('mastodon_handle', [f.pattern_name for f in findings])

    def test_il_id_match(self):
        # ``123456782`` is a Luhn-like-check-digit-valid teudat zehut.
        # The keyword anchor (``תז`` / ``teudat zehut`` / ``israeli id``)
        # disambiguates the shape from the bare-9-digit collision class.
        findings = find_pii_patterns('teudat zehut 123456782 on file')
        self.assertIn('il_id', [f.pattern_name for f in findings])

    # ---- expansion batch — every new pattern carries a positive test ----

    def test_ethereum_address_match(self):
        findings = find_pii_patterns(
            'transfer to 0xDe0B295669a9FD93d5F28D9Ec85E40f4cb697BAe today'
        )
        self.assertIn('ethereum_address', [f.pattern_name for f in findings])

    def test_monero_address_match(self):
        # Real Monero donation address from the project's contributors
        # page — 95 chars, starts with ``4``, base58 (no ``0OIl``).
        findings = find_pii_patterns(
            'wallet 44AFFq5kSiGBoZ4NMDwYtN18obc8AemS33DBLWs3H7otXft3XjrpDtQGv7SqSsaBYBb98uNbr2VBBEt7f2wfn3RVGQBEP3A '
            'on file'
        )
        self.assertIn('monero_address', [f.pattern_name for f in findings])

    def test_solana_address_match(self):
        findings = find_pii_patterns(
            'solana 7EYnhQoR9YM3N7UoaKRoA44Uy8JeaZV3qyouov87awMs received funds'
        )
        self.assertIn('solana_address', [f.pattern_name for f in findings])

    def test_litecoin_address_match(self):
        findings = find_pii_patterns(
            'paid LcHKeQrCBJUiUaXAYrAo7fzcRKQbX59u91 yesterday'
        )
        self.assertIn('litecoin_address', [f.pattern_name for f in findings])

    def test_de_postcode_match(self):
        findings = find_pii_patterns('PLZ: 10115 in Berlin')
        self.assertIn('de_postcode', [f.pattern_name for f in findings])

    def test_fr_postcode_match(self):
        findings = find_pii_patterns('code postal 75001 in Paris')
        self.assertIn('fr_postcode', [f.pattern_name for f in findings])

    def test_it_postcode_match(self):
        findings = find_pii_patterns('CAP 00100 Roma')
        self.assertIn('it_postcode', [f.pattern_name for f in findings])

    def test_es_postcode_match(self):
        findings = find_pii_patterns('CP 28013 Madrid')
        self.assertIn('es_postcode', [f.pattern_name for f in findings])

    def test_au_postcode_match(self):
        findings = find_pii_patterns('postcode 2000 Sydney')
        self.assertIn('au_postcode', [f.pattern_name for f in findings])

    def test_jp_postcode_match(self):
        findings = find_pii_patterns('zip 100-0001 Tokyo')
        self.assertIn('jp_postcode', [f.pattern_name for f in findings])

    def test_br_cep_match(self):
        findings = find_pii_patterns('CEP 01310-100 São Paulo')
        self.assertIn('br_cep', [f.pattern_name for f in findings])

    def test_in_pincode_match(self):
        findings = find_pii_patterns('PIN code 110001 New Delhi')
        self.assertIn('in_pincode', [f.pattern_name for f in findings])

    def test_il_postcode_match(self):
        findings = find_pii_patterns('postcode 6100000 Tel Aviv')
        self.assertIn('il_postcode', [f.pattern_name for f in findings])

    def test_se_postcode_match(self):
        findings = find_pii_patterns('postnummer 11122 Stockholm')
        self.assertIn('se_postcode', [f.pattern_name for f in findings])

    def test_dk_postcode_match(self):
        findings = find_pii_patterns('postnummer 1050 Copenhagen')
        self.assertIn('dk_postcode', [f.pattern_name for f in findings])

    def test_no_postcode_match(self):
        findings = find_pii_patterns('postnummer 0150 Oslo')
        self.assertIn('no_postcode', [f.pattern_name for f in findings])

    def test_fi_postcode_match(self):
        findings = find_pii_patterns('postinumero 00100 Helsinki')
        self.assertIn('fi_postcode', [f.pattern_name for f in findings])

    def test_ch_postcode_match(self):
        findings = find_pii_patterns('PLZ 8001 Zürich')
        self.assertIn('ch_postcode', [f.pattern_name for f in findings])

    def test_cn_resident_id_match(self):
        # ``110101199001010007`` is mod-11-check-digit valid.
        findings = find_pii_patterns('身份证 110101199001010007 on file')
        self.assertIn('cn_resident_id', [f.pattern_name for f in findings])

    def test_jp_my_number_match(self):
        # ``100000000005`` passes the JP My Number check digit.
        findings = find_pii_patterns('my number: 100000000005 on file')
        self.assertIn('jp_my_number', [f.pattern_name for f in findings])

    def test_kr_rrn_match(self):
        findings = find_pii_patterns('RRN 800101-1234567 verified')
        self.assertIn('kr_rrn', [f.pattern_name for f in findings])

    def test_ru_inn_match(self):
        findings = find_pii_patterns('ИНН 7707083893 confirmed')
        self.assertIn('ru_inn', [f.pattern_name for f in findings])

    def test_mx_curp_match(self):
        findings = find_pii_patterns('CURP HEGG560427MVZRRL04 issued')
        self.assertIn('mx_curp', [f.pattern_name for f in findings])

    def test_mx_rfc_match(self):
        findings = find_pii_patterns('RFC HEGG560427CR2 on file')
        self.assertIn('mx_rfc', [f.pattern_name for f in findings])

    def test_ar_cuil_cuit_match(self):
        findings = find_pii_patterns('CUIT 20-12345678-9 confirmed')
        self.assertIn('ar_cuil_cuit', [f.pattern_name for f in findings])

    def test_za_id_match(self):
        # ``8001010000008`` is Luhn-valid.
        findings = find_pii_patterns('SA ID: 8001010000008 verified')
        self.assertIn('za_id', [f.pattern_name for f in findings])

    def test_nz_ird_match(self):
        findings = find_pii_patterns('IRD 123456789 issued')
        self.assertIn('nz_ird', [f.pattern_name for f in findings])

    def test_us_dea_match(self):
        findings = find_pii_patterns('DEA AB1234567 confirmed')
        self.assertIn('us_dea', [f.pattern_name for f in findings])

    def test_imei_match(self):
        # ``490154203237518`` is Luhn-valid.
        findings = find_pii_patterns('IMEI 490154203237518 reported')
        self.assertIn('imei', [f.pattern_name for f in findings])

    def test_imsi_match(self):
        findings = find_pii_patterns('IMSI 310150123456789 captured')
        self.assertIn('imsi', [f.pattern_name for f in findings])

    def test_iccid_match(self):
        # 20-digit Luhn-valid ICCID.
        findings = find_pii_patterns('ICCID 89014103211118510720 logged')
        self.assertIn('iccid', [f.pattern_name for f in findings])

    def test_android_id_match(self):
        findings = find_pii_patterns('android id: abcdef1234567890')
        self.assertIn('android_id', [f.pattern_name for f in findings])

    def test_ios_udid_match(self):
        findings = find_pii_patterns(
            'UDID a1b2c3d4e5f6789012345678901234567890abcd verified'
        )
        self.assertIn('ios_udid', [f.pattern_name for f in findings])

    def test_linkedin_url_match(self):
        findings = find_pii_patterns(
            'profile https://linkedin.com/in/jane-doe-12345 today'
        )
        self.assertIn('linkedin_url', [f.pattern_name for f in findings])

    def test_github_url_match(self):
        findings = find_pii_patterns('source https://github.com/octocat here')
        self.assertIn('github_url', [f.pattern_name for f in findings])

    def test_discord_id_match(self):
        findings = find_pii_patterns('discord id 123456789012345678 pinged')
        self.assertIn('discord_id', [f.pattern_name for f in findings])

    def test_telegram_handle_match(self):
        findings = find_pii_patterns('reach via t.me/jane_doe today')
        self.assertIn('telegram_handle', [f.pattern_name for f in findings])

    def test_tiktok_handle_match(self):
        findings = find_pii_patterns('see https://tiktok.com/@user_name now')
        self.assertIn('tiktok_handle', [f.pattern_name for f in findings])

    def test_uuid_v4_match(self):
        findings = find_pii_patterns(
            'session 550e8400-e29b-41d4-a716-446655440000 active'
        )
        self.assertIn('uuid_v4', [f.pattern_name for f in findings])

    def test_aws_instance_id_match(self):
        # 17-char form (i- + 8 hex + 9 hex = 17 after the dash).
        findings = find_pii_patterns('instance i-0abcd1234ef567890 running')
        self.assertIn('aws_instance_id', [f.pattern_name for f in findings])

    def test_in_ifsc_match(self):
        findings = find_pii_patterns('IFSC SBIN0001234 routing verified')
        self.assertIn('in_ifsc', [f.pattern_name for f in findings])

    def test_au_bsb_match(self):
        findings = find_pii_patterns('BSB 062-000 confirmed')
        self.assertIn('au_bsb', [f.pattern_name for f in findings])

    def test_mx_clabe_match(self):
        # ``002194000000000037`` is CLABE-checksum valid.
        findings = find_pii_patterns('CLABE 002194000000000037 active')
        self.assertIn('mx_clabe', [f.pattern_name for f in findings])

    def test_jp_zengin_match(self):
        findings = find_pii_patterns('zengin 0001-001-1234567 logged')
        self.assertIn('jp_zengin', [f.pattern_name for f in findings])

    def test_medical_record_number_match(self):
        findings = find_pii_patterns('MRN: ABC-123456 noted')
        self.assertIn('medical_record_number', [f.pattern_name for f in findings])

    # ---- long-tail batch (Group A) ----

    def test_tron_address_match(self):
        findings = find_pii_patterns(
            'sent USDT to TLyqzVGLV1srkB7dToTAEqgDSfPtXRJZYH today'
        )
        self.assertIn('tron_address', [f.pattern_name for f in findings])

    def test_cardano_address_match(self):
        findings = find_pii_patterns(
            'cardano wallet '
            'addr1qx2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzer3jcu5d8ps7zex2k2xt3uqxgjqnnj0vs2qd47s '
            'received'
        )
        self.assertIn('cardano_address', [f.pattern_name for f in findings])

    def test_polkadot_address_match(self):
        findings = find_pii_patterns(
            'dot 12xtAYsRUrmbniiWQqJtECiBQrMn8AypQcXhnQAc6RB6XkLW received'
        )
        self.assertIn('polkadot_address', [f.pattern_name for f in findings])

    def test_cosmos_address_match(self):
        findings = find_pii_patterns(
            'send to cosmos1k0jntykt7e4g3y88ltc60czgjuqdy4c9ag7eas now'
        )
        self.assertIn('cosmos_address', [f.pattern_name for f in findings])

    def test_ripple_address_match(self):
        findings = find_pii_patterns(
            'XRP rEb8TK3gBgk5auZkwc6sHnwrGVJH8DuaLh confirmed'
        )
        self.assertIn('ripple_address', [f.pattern_name for f in findings])

    def test_eg_national_id_match(self):
        findings = find_pii_patterns('national ID 29001011234567 verified')
        self.assertIn('eg_national_id', [f.pattern_name for f in findings])

    def test_pk_cnic_match(self):
        findings = find_pii_patterns('CNIC 12345-1234567-1 on file')
        self.assertIn('pk_cnic', [f.pattern_name for f in findings])

    def test_bd_nid_match(self):
        findings = find_pii_patterns('NID 1234567890123 verified')
        self.assertIn('bd_nid', [f.pattern_name for f in findings])

    def test_vn_national_id_match(self):
        findings = find_pii_patterns('CCCD 012345678901 confirmed')
        self.assertIn('vn_national_id', [f.pattern_name for f in findings])

    def test_id_ktp_match(self):
        findings = find_pii_patterns('KTP 3201234567890123 issued')
        self.assertIn('id_ktp', [f.pattern_name for f in findings])

    def test_ph_tin_match(self):
        findings = find_pii_patterns('TIN 123-456-789-000 on file')
        self.assertIn('ph_tin', [f.pattern_name for f in findings])

    def test_sa_nin_match(self):
        findings = find_pii_patterns('NIN 1234567890 verified')
        self.assertIn('sa_nin', [f.pattern_name for f in findings])

    def test_ng_nin_match(self):
        findings = find_pii_patterns('NIN 12345678901 confirmed')
        self.assertIn('ng_nin', [f.pattern_name for f in findings])

    def test_ke_id_match(self):
        findings = find_pii_patterns('Kenya ID 12345678 verified')
        self.assertIn('ke_id', [f.pattern_name for f in findings])

    def test_gh_ghana_card_match(self):
        findings = find_pii_patterns('GHA-123456789-0 confirmed')
        self.assertIn('gh_ghana_card', [f.pattern_name for f in findings])

    def test_za_postcode_match(self):
        findings = find_pii_patterns('postcode 0001 Pretoria')
        self.assertIn('za_postcode', [f.pattern_name for f in findings])

    def test_nz_postcode_match(self):
        findings = find_pii_patterns('NZ postcode 6011 Wellington')
        self.assertIn('nz_postcode', [f.pattern_name for f in findings])

    def test_ru_postcode_match(self):
        findings = find_pii_patterns('индекс 101000 Moscow')
        self.assertIn('ru_postcode', [f.pattern_name for f in findings])

    def test_kr_postcode_match(self):
        findings = find_pii_patterns('우편번호 04524 Seoul')
        self.assertIn('kr_postcode', [f.pattern_name for f in findings])

    def test_th_postcode_match(self):
        findings = find_pii_patterns('postcode 10200 Bangkok')
        self.assertIn('th_postcode', [f.pattern_name for f in findings])

    def test_tw_postcode_match(self):
        findings = find_pii_patterns('TW-100 Taipei')
        self.assertIn('tw_postcode', [f.pattern_name for f in findings])

    def test_hk_postcode_match(self):
        findings = find_pii_patterns('HK postcode 999077 international')
        self.assertIn('hk_postcode', [f.pattern_name for f in findings])

    def test_sg_postcode_match(self):
        findings = find_pii_patterns('Singapore postcode 018989 confirmed')
        self.assertIn('sg_postcode', [f.pattern_name for f in findings])

    def test_snapchat_handle_match(self):
        findings = find_pii_patterns('snapchat @jane_doe pinged')
        self.assertIn('snapchat_handle', [f.pattern_name for f in findings])

    def test_whatsapp_number_match(self):
        findings = find_pii_patterns('reach https://wa.me/+12125551234 today')
        self.assertIn('whatsapp_number', [f.pattern_name for f in findings])

    def test_signal_handle_match(self):
        findings = find_pii_patterns('signal +12125551234 active')
        self.assertIn('signal_handle', [f.pattern_name for f in findings])

    def test_slack_user_id_match(self):
        findings = find_pii_patterns('mention <@U01ABCDEFGH> in the thread')
        self.assertIn('slack_user_id', [f.pattern_name for f in findings])

    def test_bluesky_handle_match(self):
        findings = find_pii_patterns('@jane-doe.bsky.social posted')
        self.assertIn('bluesky_handle', [f.pattern_name for f in findings])

    def test_oauth_bearer_match(self):
        findings = find_pii_patterns(
            'Authorization: Bearer abc123def456ghi789 ok'
        )
        self.assertIn('oauth_bearer', [f.pattern_name for f in findings])

    def test_php_session_id_match(self):
        findings = find_pii_patterns(
            'cookie PHPSESSID=abcdef1234567890abcdef set'
        )
        self.assertIn('php_session_id', [f.pattern_name for f in findings])

    def test_jsession_id_match(self):
        findings = find_pii_patterns(
            'Cookie: JSESSIONID=ABCDEF1234567890 received'
        )
        self.assertIn('jsession_id', [f.pattern_name for f in findings])

    def test_csrf_token_match(self):
        findings = find_pii_patterns(
            'X-CSRF-TOKEN: abc123def456ghi789jkl0mno verified'
        )
        self.assertIn('csrf_token', [f.pattern_name for f in findings])

    def test_uk_license_plate_match(self):
        findings = find_pii_patterns('UK plate AB12 CDE today')
        self.assertIn('uk_license_plate', [f.pattern_name for f in findings])

    def test_eu_license_plate_match(self):
        findings = find_pii_patterns('EU plate ABC-1234-DE verified')
        self.assertIn('eu_license_plate', [f.pattern_name for f in findings])

    def test_ca_license_plate_match(self):
        findings = find_pii_patterns('Canadian plate ABCD 1234 registered')
        self.assertIn('ca_license_plate', [f.pattern_name for f in findings])

    def test_clia_match(self):
        findings = find_pii_patterns('CLIA 12D1234567 on file')
        self.assertIn('clia', [f.pattern_name for f in findings])

    def test_ndc_drug_code_match(self):
        findings = find_pii_patterns('NDC 12345-678-90 prescribed')
        self.assertIn('ndc_drug_code', [f.pattern_name for f in findings])

    def test_icd10_code_match(self):
        findings = find_pii_patterns('diagnosis ICD-10 A01.0 confirmed')
        self.assertIn('icd10_code', [f.pattern_name for f in findings])

    # ---- coverage guarantee: every locked name has a positive test ----

    def test_every_locked_pattern_name_has_a_positive_test(self):
        """The reviewer's bar — "for each pattern please write tests" —
        enforced mechanically: this asserts each ``PII_PATTERN_NAMES``
        entry has a matching ``test_<name>_match`` method declared
        somewhere on a ``unittest.TestCase`` in this module. If a
        future contributor adds a pattern but forgets the test, this
        fails loudly here (alongside the test for that pattern that
        won't exist)."""
        test_method_names = set()
        for cls in (
            FindPiiPatternsTests,
            # If a new TestCase class is added with per-pattern tests,
            # list it here so this discovery stays accurate.
        ):
            for attr in dir(cls):
                if attr.startswith('test_') and attr.endswith('_match'):
                    test_method_names.add(attr)
        # Map "test_<name>_match" → "<name>", then check coverage.
        # Drop the "_eight_digit_arm" variant (a second test for the
        # same pattern, not a new pattern).
        tested = set()
        for name in test_method_names:
            stem = name[len('test_'):-len('_match')]
            # Strip a documented "_<descriptor>_arm" suffix so the
            # variant test still maps back to its canonical name.
            for suffix in ('_eight_digit_arm',):
                if stem.endswith(suffix):
                    stem = stem[:-len(suffix)]
                    break
            tested.add(stem)
        missing = PII_PATTERN_NAMES - tested
        self.assertEqual(
            missing, set(),
            f'Locked PII pattern(s) without a positive test: '
            f'{sorted(missing)}. Add ``test_<name>_match`` for each.',
        )

    def test_pattern_names_are_locked(self):
        # The canonical, extensive set. Adding to PII_PATTERN_NAMES
        # without adding a representative test above (or vice versa)
        # fails here — that's the point.
        self.assertEqual(
            PII_PATTERN_NAMES,
            _EXPECTED_PATTERN_NAMES,
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
