"""PII pattern detector — single source of truth for the workspace.

Parallel to ``credential_patterns`` (credential_patterns hunts
vendor-issued secrets; this module hunts personal data). Every
PII-scanning helper across the workspace — ``helpers/pii_scan`` for
text streams, ``helpers/pii_scrub`` for structured payloads, the chat
service's tool-result sanitizer in ``ob-love-admin-backend`` — pulls
its pattern set from here. There is no second copy in
``llm-core-lib``; the structural defense over there (``LLMView``,
``to_llm_payload``) enforces *types*, while regex-level PII detection
lives here.

The set is deliberately broad — false positives are acceptable (the
runtime scrubber and the audit-log helper both tolerate them; the test
suite uses :class:`PIIDetectedError` to lock the contract); false
negatives are not. When in doubt, add a pattern. The named families
below are an attempt at "don't forget a single thing":

  * **Contact** — email, phone (US + international E.164-ish), URL
    (URLs routinely carry PII in path/query), social-media handles
    (Twitter/Mastodon ``@handle``, labelled Skype).
  * **Government IDs (US)** — SSN, ITIN, EIN, passport, driver's
    license, Medicare beneficiary id.
  * **Government IDs (intl)** — UK / CA / AU / ES / DE passport, UK NI
    number, UK UTR (tax reference), Canadian SIN, Australian TFN,
    German Steueridentifikationsnummer, Indian Aadhaar, Indian PAN,
    Brazilian CPF, Brazilian CNPJ, Spanish NIF / NIE, Singapore
    FIN/NRIC, Polish PESEL (keyword-anchored), UK NHS
    (keyword-anchored), Australian Medicare (space-grouped form),
    Indian GSTIN, Italian Codice Fiscale, Indian Voter ID, Swedish
    personnummer / organisationsnummer (shared dashed format),
    Finnish personal identity code, US NPI (keyword), Australian
    ABN / ACN (keyword), Singapore UEN (keyword), Thai TNIN
    (keyword), Turkish national ID (keyword).
  * **Financial** — credit card (13–19 digits), CVV-in-context,
    IBAN, SWIFT/BIC, US routing number, US bank account, bitcoin
    address.
  * **Postal** — US ZIP, US ZIP+4, UK postcode, CA postcode, NL
    postcode.
  * **Network / device** — IPv4, IPv6, MAC address.
  * **Session / token** — JWT (the ``eyJ`` three-part shape).
  * **Geolocation** — GPS coordinate pairs (lat/lon with at least
    four decimal places of precision — bounded by valid lat/lon
    ranges so plain comma-separated numbers don't false-positive).
  * **Vehicle** — VIN, US license plate.
  * **Address** — US street-address shape (number + street + suffix);
    best-effort, regex can't catch every postal shape so the
    *primary* address defense is the typed-view allowlist in
    ``llm-core-lib`` (``LLMView`` subclasses simply don't declare an
    address field unless the value has already been scrubbed).
  * **Temporal** — date-of-birth shapes (ISO, US, EU).

Address detection is intentionally regex-supported even though the
allowlist is the real defense — the reviewer's note "make it
extensive, don't forget a single thing" trumps the regex-purity
argument; a noisy street-address pattern that flags
``742 Evergreen Terrace`` is a net win over silently missing it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable, List, Tuple


@dataclass(frozen=True)
class PIIPatternFinding(object):
    """One match of a named PII pattern; the full matched value is never returned."""

    pattern_name: str
    redacted_preview: str


# Prior-art note — surveyed (2025): Microsoft Presidio (regex+spaCy NER,
# heavy), scrubadub (Apache 2.0 but unmaintained since 2022 — read for
# patterns, do NOT pip install), CommonRegex (unmaintained 2021),
# pii-codex (severity-tier taxonomy borrowed below), datafog, Protect
# AI's pii-detection-anonymizer (DeBERTa, too heavy for inline scrub).
#
# Adopted: url / twitter_handle / skype_handle / instagram_handle /
# mastodon_handle (scrubadub), uk_utr (scrubadub),
# credit_card+SSN+IBAN+ABA+VIN checksums (Presidio), the per-state US
# driver's-license shape union (scrubadub), pii-codex severity tiers
# (see _PATTERN_CATEGORIES below), scrubadub-style per-pattern
# replacement strategy (see _PATTERN_REPLACEMENTS below).
#
# Documented gaps (need a new dep):
#   * phonenumbers-backed phone validation (kills the loose
#     phone regex's false-positive class).
#   * dateparser-backed bare DOB without keyword anchor.
#   * spaCy / TextBlob NER for names / orgs / locations.
#   * libpostal (pyap) for international address parsing.
#
# Re-evaluate Presidio out-of-process if/when free-text name NER lands.


# Second-pass validators registered in :data:`_PATTERN_VALIDATORS`
# below — each fires after the regex match and drops shape-valid but
# arithmetically-impossible candidates.


def _luhn_valid(match_text: str) -> bool:
    """Credit-card mod-10 (Luhn)."""
    digits = ''.join(ch for ch in match_text if ch.isdigit())
    if not 13 <= len(digits) <= 19:
        return False
    total = 0
    for index, char in enumerate(reversed(digits)):
        digit_value = int(char)
        if index % 2 == 1:
            digit_value *= 2
            if digit_value > 9:
                digit_value -= 9
        total += digit_value
    return total % 10 == 0


def _ssn_area_group_serial_valid(match_text: str) -> bool:
    """SSA reservation rules — rejects area 000/666/9xx, group 00, serial 0000."""
    digits_only = match_text.replace('-', '')
    if len(digits_only) != 9:
        return False
    area = digits_only[:3]
    group = digits_only[3:5]
    serial = digits_only[5:]
    if area in ('000', '666'):
        return False
    if area[0] == '9':
        return False
    if group == '00':
        return False
    if serial == '0000':
        return False
    return True


def _iban_mod97_valid(match_text: str) -> bool:
    """ISO 13616 mod-97."""
    compact = match_text.replace(' ', '').replace('-', '').upper()
    if len(compact) < 15:
        return False
    rearranged = compact[4:] + compact[:4]
    numeric_chars = []
    for char in rearranged:
        if char.isdigit():
            numeric_chars.append(char)
        elif 'A' <= char <= 'Z':
            numeric_chars.append(str(ord(char) - 55))
        else:
            return False
    return int(''.join(numeric_chars)) % 97 == 1


def _aba_routing_checksum_valid(match_text: str) -> bool:
    """Federal Reserve 3-7-1 weighted mod-10."""
    digits = ''.join(ch for ch in match_text if ch.isdigit())
    if len(digits) != 9:
        return False
    weights = (3, 7, 1, 3, 7, 1, 3, 7, 1)
    total = sum(int(digit) * weight for digit, weight in zip(digits, weights))
    return total % 10 == 0


# VIN character values and positional weights — NHTSA 49 CFR §565.
# I / O / Q are intentionally absent (the spec excludes them to avoid
# confusion with 1 / 0).
_VIN_CHAR_VALUES = {
    'A': 1, 'B': 2, 'C': 3, 'D': 4, 'E': 5, 'F': 6, 'G': 7, 'H': 8,
    'J': 1, 'K': 2, 'L': 3, 'M': 4, 'N': 5,
    'P': 7, 'R': 9,
    'S': 2, 'T': 3, 'U': 4, 'V': 5, 'W': 6, 'X': 7, 'Y': 8, 'Z': 9,
    **{str(digit): digit for digit in range(10)},
}
_VIN_POSITIONAL_WEIGHTS = (8, 7, 6, 5, 4, 3, 2, 10, 0, 9, 8, 7, 6, 5, 4, 3, 2)


def _vin_check_digit_valid(match_text: str) -> bool:
    """NHTSA 49 CFR §565 mod-11 check digit at position 9."""
    candidate = match_text.upper()
    if len(candidate) != 17:
        return False
    weighted_sum = 0
    for position, char in enumerate(candidate):
        if char not in _VIN_CHAR_VALUES:
            return False
        weighted_sum += _VIN_CHAR_VALUES[char] * _VIN_POSITIONAL_WEIGHTS[position]
    check_remainder = weighted_sum % 11
    expected_check_char = 'X' if check_remainder == 10 else str(check_remainder)
    return candidate[8] == expected_check_char


def _il_id_check_digit_valid(match_text: str) -> bool:
    """Israeli teudat zehut — Luhn-like check digit, legacy 5-8 digit forms
    left-padded to 9."""
    digits_only = ''.join(ch for ch in match_text if ch.isdigit())
    if not 5 <= len(digits_only) <= 9:
        return False
    padded = digits_only.zfill(9)
    total = 0
    for index, char in enumerate(padded):
        digit_value = int(char)
        if index % 2 == 1:
            digit_value *= 2
            if digit_value > 9:
                digit_value -= 9
        total += digit_value
    return total % 10 == 0


# CN resident ID — 18-char number; first 17 digits weighted by
# (2^i mod 11) descending, last char is mod-11 result ('X' = 10).
_CN_RESIDENT_ID_WEIGHTS = (7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2)
_CN_RESIDENT_ID_CHECK_CHARS = ('1', '0', 'X', '9', '8', '7', '6', '5', '4', '3', '2')


def _cn_resident_id_check_valid(match_text: str) -> bool:
    """CN resident ID — 18 chars with mod-11 check digit at position 18."""
    candidate = match_text.replace(' ', '').upper()
    if len(candidate) != 18:
        return False
    if not candidate[:17].isdigit():
        return False
    weighted_sum = sum(
        int(candidate[i]) * _CN_RESIDENT_ID_WEIGHTS[i] for i in range(17)
    )
    return candidate[17] == _CN_RESIDENT_ID_CHECK_CHARS[weighted_sum % 11]


def _imei_luhn_valid(match_text: str) -> bool:
    """IMEI — 15 digits, Luhn mod-10 (same algorithm as credit cards)."""
    digits = ''.join(ch for ch in match_text if ch.isdigit())
    if len(digits) != 15:
        return False
    return _luhn_valid(digits)


def _iccid_luhn_valid(match_text: str) -> bool:
    """SIM ICCID — 19-20 digits, Luhn-checked.

    Inline because :func:`_luhn_valid` rejects anything outside the
    credit-card 13-19 length window.
    """
    digits = ''.join(ch for ch in match_text if ch.isdigit())
    if not 19 <= len(digits) <= 20:
        return False
    total = 0
    for index, char in enumerate(reversed(digits)):
        digit_value = int(char)
        if index % 2 == 1:
            digit_value *= 2
            if digit_value > 9:
                digit_value -= 9
        total += digit_value
    return total % 10 == 0


def _za_id_luhn_valid(match_text: str) -> bool:
    """South African ID — 13 digits, Luhn-style check digit."""
    digits = ''.join(ch for ch in match_text if ch.isdigit())
    if len(digits) != 13:
        return False
    return _luhn_valid(digits)


def _jp_my_number_check_valid(match_text: str) -> bool:
    """JP My Number — 12 digits, last is check digit.

    Algorithm: weight first 11 digits by ``[6,5,4,3,2,7,6,5,4,3,2]``
    (positions 1..11 reversed in the spec), check = 11 − (sum mod 11);
    if check >= 10, check = 0.
    """
    digits = ''.join(ch for ch in match_text if ch.isdigit())
    if len(digits) != 12:
        return False
    weights = (6, 5, 4, 3, 2, 7, 6, 5, 4, 3, 2)
    weighted_sum = sum(int(digits[i]) * weights[i] for i in range(11))
    remainder = weighted_sum % 11
    check_digit = 0 if remainder <= 1 else 11 - remainder
    return int(digits[11]) == check_digit


# MX CLABE — 18 digits; check digit is computed against the first 17.
_CLABE_WEIGHTS = (3, 7, 1, 3, 7, 1, 3, 7, 1, 3, 7, 1, 3, 7, 1, 3, 7)


def _mx_clabe_check_valid(match_text: str) -> bool:
    """MX CLABE — 18 digits, weighted 3-7-1 mod 10 check digit at position 18."""
    digits = ''.join(ch for ch in match_text if ch.isdigit())
    if len(digits) != 18:
        return False
    weighted_sum = sum(
        (int(digits[i]) * _CLABE_WEIGHTS[i]) % 10 for i in range(17)
    )
    check_digit = (10 - (weighted_sum % 10)) % 10
    return int(digits[17]) == check_digit


# ---------------------------------------------------------------------------
# Pattern aggregation
# ---------------------------------------------------------------------------
#
# Each category lives in its own ``_pii_<category>.py`` sibling module.
# The order below is significant: the scrubber's overlap resolver picks
# the first-declared span on a tie, so the URL pattern (in ``_pii_contact``)
# must come before the email pattern (also ``_pii_contact``) for an email
# embedded in a URL to redact as a URL. Inside each module the order is
# preserved literally; here we concatenate the per-category tuples.
from agent_core_lib.pii import (
    _pii_address,
    _pii_contact,
    _pii_crypto_long_tail,
    _pii_financial,
    _pii_government_ids_long_tail,
    _pii_healthcare_codes,
    _pii_intl_government_ids,
    _pii_network_device,
    _pii_postal,
    _pii_postal_long_tail,
    _pii_session_token,
    _pii_session_tokens_long_tail,
    _pii_social_long_tail,
    _pii_temporal,
    _pii_us_government_ids,
    _pii_vehicle,
    _pii_vehicle_long_tail,
)

_PII_PATTERNS: Tuple[Tuple[str, re.Pattern[str]], ...] = (
    # The order here matches the original single-file declaration
    # order. Don't reorder without checking the scrubber's overlap
    # tests (URL-before-email is the load-bearing one). Long-tail
    # batches are appended at the end of their category so they
    # don't shift the existing precedence.
    *_pii_contact.PATTERNS,
    *_pii_social_long_tail.PATTERNS,
    *_pii_us_government_ids.PATTERNS,
    *_pii_intl_government_ids.PATTERNS,
    *_pii_government_ids_long_tail.PATTERNS,
    *_pii_healthcare_codes.PATTERNS,
    *_pii_financial.PATTERNS,
    *_pii_crypto_long_tail.PATTERNS,
    *_pii_postal.PATTERNS,
    *_pii_postal_long_tail.PATTERNS,
    *_pii_network_device.PATTERNS,
    *_pii_session_token.PATTERNS,
    *_pii_session_tokens_long_tail.PATTERNS,
    *_pii_vehicle.PATTERNS,
    *_pii_vehicle_long_tail.PATTERNS,
    *_pii_address.PATTERNS,
    *_pii_temporal.PATTERNS,
)


PII_PATTERN_NAMES: frozenset = frozenset(name for name, _ in _PII_PATTERNS)


# Pattern name → second-pass validator. Patterns not listed are
# shape-only. The :func:`find_pii_patterns` / :mod:`pii_scrub` paths
# both consult this map and drop matches whose validator returns False.
_PATTERN_VALIDATORS = {
    'credit_card': _luhn_valid,
    'ssn': _ssn_area_group_serial_valid,
    'iban': _iban_mod97_valid,
    'us_routing_number': _aba_routing_checksum_valid,
    'vin': _vin_check_digit_valid,
    'il_id': _il_id_check_digit_valid,
    'cn_resident_id': _cn_resident_id_check_valid,
    'jp_my_number': _jp_my_number_check_valid,
    'za_id': _za_id_luhn_valid,
    'imei': _imei_luhn_valid,
    'iccid': _iccid_luhn_valid,
    'mx_clabe': _mx_clabe_check_valid,
}


# Severity tiers (pii-codex taxonomy) — every pattern is categorised
# so callers can apply per-tier policy without enumerating each name.
# ``test_every_locked_pattern_has_a_category`` enforces full coverage.
CATEGORY_CONTACT = 'contact'
CATEGORY_GOVERNMENT_ID = 'government_id'
CATEGORY_FINANCIAL = 'financial'
CATEGORY_POSTAL = 'postal'
CATEGORY_NETWORK_DEVICE = 'network_device'
CATEGORY_VEHICLE = 'vehicle'
CATEGORY_ADDRESS = 'address'
CATEGORY_TEMPORAL = 'temporal'
CATEGORY_CREDENTIAL = 'credential'

_PATTERN_CATEGORIES = {
    # contact
    'url': CATEGORY_CONTACT,
    'email': CATEGORY_CONTACT,
    'phone': CATEGORY_CONTACT,
    'twitter_handle': CATEGORY_CONTACT,
    'skype_handle': CATEGORY_CONTACT,
    'instagram_handle': CATEGORY_CONTACT,
    'mastodon_handle': CATEGORY_CONTACT,
    # US government IDs
    'ssn': CATEGORY_GOVERNMENT_ID,
    'itin': CATEGORY_GOVERNMENT_ID,
    'ein': CATEGORY_GOVERNMENT_ID,
    'us_passport': CATEGORY_GOVERNMENT_ID,
    'us_drivers_license': CATEGORY_GOVERNMENT_ID,
    'medicare_mbi': CATEGORY_GOVERNMENT_ID,
    # intl government IDs
    'uk_nino': CATEGORY_GOVERNMENT_ID,
    'uk_utr': CATEGORY_GOVERNMENT_ID,
    'uk_passport': CATEGORY_GOVERNMENT_ID,
    'ca_passport': CATEGORY_GOVERNMENT_ID,
    'au_passport': CATEGORY_GOVERNMENT_ID,
    'es_passport': CATEGORY_GOVERNMENT_ID,
    'de_passport': CATEGORY_GOVERNMENT_ID,
    'ca_sin': CATEGORY_GOVERNMENT_ID,
    'au_tfn': CATEGORY_GOVERNMENT_ID,
    'de_steuer_id': CATEGORY_GOVERNMENT_ID,
    'in_aadhaar': CATEGORY_GOVERNMENT_ID,
    'in_pan': CATEGORY_GOVERNMENT_ID,
    'br_cpf': CATEGORY_GOVERNMENT_ID,
    'br_cnpj': CATEGORY_GOVERNMENT_ID,
    'es_nif': CATEGORY_GOVERNMENT_ID,
    'sg_fin': CATEGORY_GOVERNMENT_ID,
    'pl_pesel': CATEGORY_GOVERNMENT_ID,
    'uk_nhs': CATEGORY_GOVERNMENT_ID,
    'au_medicare': CATEGORY_GOVERNMENT_ID,
    'in_gstin': CATEGORY_GOVERNMENT_ID,
    'it_fiscal_code': CATEGORY_GOVERNMENT_ID,
    'es_nie': CATEGORY_GOVERNMENT_ID,
    'se_personnummer': CATEGORY_GOVERNMENT_ID,
    'in_voter': CATEGORY_GOVERNMENT_ID,
    'fi_personal_identity_code': CATEGORY_GOVERNMENT_ID,
    'us_npi': CATEGORY_GOVERNMENT_ID,
    'au_abn': CATEGORY_GOVERNMENT_ID,
    'au_acn': CATEGORY_GOVERNMENT_ID,
    'sg_uen': CATEGORY_GOVERNMENT_ID,
    'th_tnin': CATEGORY_GOVERNMENT_ID,
    'tr_national_id': CATEGORY_GOVERNMENT_ID,
    'il_id': CATEGORY_GOVERNMENT_ID,
    # financial
    'credit_card': CATEGORY_FINANCIAL,
    'credit_card_cvv': CATEGORY_FINANCIAL,
    'iban': CATEGORY_FINANCIAL,
    'swift_bic': CATEGORY_FINANCIAL,
    'us_routing_number': CATEGORY_FINANCIAL,
    'us_bank_account': CATEGORY_FINANCIAL,
    'bitcoin_address': CATEGORY_FINANCIAL,
    # postal
    'us_zip': CATEGORY_POSTAL,
    'uk_postcode': CATEGORY_POSTAL,
    'ca_postcode': CATEGORY_POSTAL,
    'nl_postcode': CATEGORY_POSTAL,
    # network / device
    'ipv4': CATEGORY_NETWORK_DEVICE,
    'ipv6': CATEGORY_NETWORK_DEVICE,
    'mac_address': CATEGORY_NETWORK_DEVICE,
    # geolocation lumps into network_device (closest existing tier)
    'gps_coordinates': CATEGORY_NETWORK_DEVICE,
    # credential (session-bound token)
    'jwt': CATEGORY_CREDENTIAL,
    # vehicle
    'vin': CATEGORY_VEHICLE,
    'us_license_plate': CATEGORY_VEHICLE,
    # address
    'street_address_with_city': CATEGORY_ADDRESS,
    'street_address_with_unit': CATEGORY_ADDRESS,
    'street_address': CATEGORY_ADDRESS,
    'street_address_intl': CATEGORY_ADDRESS,
    'po_box': CATEGORY_ADDRESS,
    # temporal
    'date_of_birth': CATEGORY_TEMPORAL,
    # crypto wallets (financial)
    'ethereum_address': CATEGORY_FINANCIAL,
    'monero_address': CATEGORY_FINANCIAL,
    'solana_address': CATEGORY_FINANCIAL,
    'litecoin_address': CATEGORY_FINANCIAL,
    # additional postal codes
    'de_postcode': CATEGORY_POSTAL,
    'fr_postcode': CATEGORY_POSTAL,
    'it_postcode': CATEGORY_POSTAL,
    'es_postcode': CATEGORY_POSTAL,
    'au_postcode': CATEGORY_POSTAL,
    'jp_postcode': CATEGORY_POSTAL,
    'br_cep': CATEGORY_POSTAL,
    'in_pincode': CATEGORY_POSTAL,
    'il_postcode': CATEGORY_POSTAL,
    'se_postcode': CATEGORY_POSTAL,
    'dk_postcode': CATEGORY_POSTAL,
    'no_postcode': CATEGORY_POSTAL,
    'fi_postcode': CATEGORY_POSTAL,
    'ch_postcode': CATEGORY_POSTAL,
    # additional government IDs
    'cn_resident_id': CATEGORY_GOVERNMENT_ID,
    'jp_my_number': CATEGORY_GOVERNMENT_ID,
    'kr_rrn': CATEGORY_GOVERNMENT_ID,
    'ru_inn': CATEGORY_GOVERNMENT_ID,
    'mx_curp': CATEGORY_GOVERNMENT_ID,
    'mx_rfc': CATEGORY_GOVERNMENT_ID,
    'ar_cuil_cuit': CATEGORY_GOVERNMENT_ID,
    'za_id': CATEGORY_GOVERNMENT_ID,
    'nz_ird': CATEGORY_GOVERNMENT_ID,
    'us_dea': CATEGORY_GOVERNMENT_ID,
    # device identifiers (network/device tier)
    'imei': CATEGORY_NETWORK_DEVICE,
    'imsi': CATEGORY_NETWORK_DEVICE,
    'iccid': CATEGORY_NETWORK_DEVICE,
    'android_id': CATEGORY_NETWORK_DEVICE,
    'ios_udid': CATEGORY_NETWORK_DEVICE,
    # additional social handles (contact)
    'linkedin_url': CATEGORY_CONTACT,
    'github_url': CATEGORY_CONTACT,
    'discord_id': CATEGORY_CONTACT,
    'telegram_handle': CATEGORY_CONTACT,
    'tiktok_handle': CATEGORY_CONTACT,
    # general identifiers (network/device — they're system-bound IDs)
    'uuid_v4': CATEGORY_NETWORK_DEVICE,
    'aws_instance_id': CATEGORY_NETWORK_DEVICE,
    # additional bank identifiers (financial)
    'in_ifsc': CATEGORY_FINANCIAL,
    'au_bsb': CATEGORY_FINANCIAL,
    'mx_clabe': CATEGORY_FINANCIAL,
    'jp_zengin': CATEGORY_FINANCIAL,
    # healthcare
    'medical_record_number': CATEGORY_GOVERNMENT_ID,
    # long-tail crypto wallets (financial)
    'tron_address': CATEGORY_FINANCIAL,
    'cardano_address': CATEGORY_FINANCIAL,
    'polkadot_address': CATEGORY_FINANCIAL,
    'cosmos_address': CATEGORY_FINANCIAL,
    'ripple_address': CATEGORY_FINANCIAL,
    # long-tail government IDs
    'eg_national_id': CATEGORY_GOVERNMENT_ID,
    'pk_cnic': CATEGORY_GOVERNMENT_ID,
    'bd_nid': CATEGORY_GOVERNMENT_ID,
    'vn_national_id': CATEGORY_GOVERNMENT_ID,
    'id_ktp': CATEGORY_GOVERNMENT_ID,
    'ph_tin': CATEGORY_GOVERNMENT_ID,
    'sa_nin': CATEGORY_GOVERNMENT_ID,
    'ng_nin': CATEGORY_GOVERNMENT_ID,
    'ke_id': CATEGORY_GOVERNMENT_ID,
    'gh_ghana_card': CATEGORY_GOVERNMENT_ID,
    # long-tail postcodes
    'za_postcode': CATEGORY_POSTAL,
    'nz_postcode': CATEGORY_POSTAL,
    'ru_postcode': CATEGORY_POSTAL,
    'kr_postcode': CATEGORY_POSTAL,
    'th_postcode': CATEGORY_POSTAL,
    'tw_postcode': CATEGORY_POSTAL,
    'hk_postcode': CATEGORY_POSTAL,
    'sg_postcode': CATEGORY_POSTAL,
    # long-tail social handles (contact)
    'snapchat_handle': CATEGORY_CONTACT,
    'whatsapp_number': CATEGORY_CONTACT,
    'signal_handle': CATEGORY_CONTACT,
    'slack_user_id': CATEGORY_CONTACT,
    'bluesky_handle': CATEGORY_CONTACT,
    # long-tail session / auth tokens (credential)
    'oauth_bearer': CATEGORY_CREDENTIAL,
    'php_session_id': CATEGORY_CREDENTIAL,
    'jsession_id': CATEGORY_CREDENTIAL,
    'csrf_token': CATEGORY_CREDENTIAL,
    # long-tail vehicle license plates
    'uk_license_plate': CATEGORY_VEHICLE,
    'eu_license_plate': CATEGORY_VEHICLE,
    'ca_license_plate': CATEGORY_VEHICLE,
    # healthcare codes
    'clia': CATEGORY_GOVERNMENT_ID,
    'ndc_drug_code': CATEGORY_GOVERNMENT_ID,
    'icd10_code': CATEGORY_GOVERNMENT_ID,
}


def category_for(pattern_name: str):
    """Return the severity-tier category for ``pattern_name``, or ``None``."""
    return _PATTERN_CATEGORIES.get(pattern_name)


# Per-pattern replacement strategies. Default (no entry) → full
# redaction ``[redacted:<name>]``. Each strategy must produce a
# replacement that does NOT re-match its own pattern (the round-trip
# ``scrub_pii → assert_no_pii`` flow depends on this).
#
#   * ``credit_card``: ``[redacted:credit_card:****1234]`` (last 4)
#   * ``phone``:       ``[redacted:phone:+1]`` (country code only)
#   * ``email``:       ``[redacted:email:host=example.com]`` (host, no ``@``)
#   * ``gps_coordinates``: ``[redacted:gps_coordinates:37.4,-122.1]``
#     (1-decimal precision — ~11 km, region-scale).


def _mask_credit_card_last_four(matched_text: str) -> str:
    digits = ''.join(ch for ch in matched_text if ch.isdigit())
    last_four = digits[-4:] if len(digits) >= 4 else digits
    return f'[redacted:credit_card:****{last_four}]'


def _mask_phone_country_code(matched_text: str) -> str:
    stripped = matched_text.lstrip()
    if stripped.startswith('+'):
        country_digits = []
        for char in stripped[1:]:
            if char.isdigit() and len(country_digits) < 3:
                country_digits.append(char)
            elif char.isdigit():
                break
            elif country_digits:
                break
        if country_digits:
            return f'[redacted:phone:+{"".join(country_digits)}]'
    return '[redacted:phone]'


def _mask_email_host(matched_text: str) -> str:
    # ``@`` deliberately dropped so the replacement doesn't re-match the
    # email regex on a second pass.
    at_index = matched_text.rfind('@')
    if at_index == -1:
        return '[redacted:email]'
    return f'[redacted:email:host={matched_text[at_index + 1:]}]'


def _mask_gps_low_precision(matched_text: str) -> str:
    coordinate_match = re.match(
        r'\s*(-?\d+\.\d+)\s*,\s*(-?\d+\.\d+)', matched_text,
    )
    if not coordinate_match:
        return '[redacted:gps_coordinates]'
    latitude = float(coordinate_match.group(1))
    longitude = float(coordinate_match.group(2))
    return f'[redacted:gps_coordinates:{latitude:.1f},{longitude:.1f}]'


_PATTERN_REPLACEMENTS = {
    'credit_card': _mask_credit_card_last_four,
    'phone': _mask_phone_country_code,
    'email': _mask_email_host,
    'gps_coordinates': _mask_gps_low_precision,
}


def replacement_for(pattern_name: str, matched_text: str) -> str:
    """Return the scrubber replacement for one match.

    Per-pattern strategy from :data:`_PATTERN_REPLACEMENTS`; default is
    ``[redacted:<pattern_name>]``.
    """
    strategy = _PATTERN_REPLACEMENTS.get(pattern_name)
    if strategy is None:
        return f'[redacted:{pattern_name}]'
    return strategy(matched_text)


def _redact(matched_text: str) -> str:
    prefix_len = min(4, len(matched_text))
    return f'{matched_text[:prefix_len]}…[REDACTED, len={len(matched_text)}]'


def find_pii_patterns(text: str) -> List[PIIPatternFinding]:
    """Return every named PII pattern matched in ``text``.

    The raw matched value is never returned — callers receive only the
    pattern name and a redacted preview that is safe to log. Pattern
    order is fixed (declaration order), so cross-test assertions on
    ``findings[0]`` stay stable.
    """
    if not text or not isinstance(text, str):
        return []
    findings: List[PIIPatternFinding] = []
    for pattern_name, regex in _PII_PATTERNS:
        validator = _PATTERN_VALIDATORS.get(pattern_name)
        for match in regex.finditer(text):
            matched_text = match.group(0)
            if validator is not None and not validator(matched_text):
                continue
            findings.append(PIIPatternFinding(
                pattern_name=pattern_name,
                redacted_preview=_redact(matched_text),
            ))
    return findings


def summarize_pii_findings(findings: Iterable[PIIPatternFinding]) -> str:
    """Return an operator-facing summary without raw matched values."""
    by_name: dict[str, list[PIIPatternFinding]] = {}
    for finding in findings:
        by_name.setdefault(finding.pattern_name, []).append(finding)
    if not by_name:
        return 'no pii patterns detected'
    parts: list[str] = []
    for pattern_name, group in by_name.items():
        first = group[0].redacted_preview
        if len(group) == 1:
            parts.append(f'{pattern_name}={first}')
        else:
            parts.append(f'{pattern_name}={first} (+{len(group) - 1} more)')
    return '; '.join(parts)


def iter_pattern_names_and_regexes() -> Iterable[Tuple[str, re.Pattern[str]]]:
    """Expose the underlying ``(name, regex)`` pairs for callers that
    need to scrub text in place (see :mod:`pii_scrub`). Iteration order
    is the declaration order, which the scrubber relies on for
    deterministic output."""
    return _PII_PATTERNS


def get_validator_for(pattern_name: str):
    """Return the second-pass validator for ``pattern_name``, or ``None``.

    Used by the scrubber to gate matches the same way
    :func:`find_pii_patterns` does.
    """
    return _PATTERN_VALIDATORS.get(pattern_name)


def find_pii_strict(
    text: str,
    *,
    phone_region: str = 'US',
    include_ner: bool = False,
) -> List[PIIPatternFinding]:
    """Run every detector — regex + library-backed strict detectors.

    Combines :func:`find_pii_patterns` (the regex set),
    :func:`agent_core_lib.pii._pii_strict_phone.find_strict_phone`
    (``phonenumbers``-validated phones), and
    :func:`agent_core_lib.pii._pii_strict_dob.find_strict_dob`
    (``dateparser`` plausibility-checked DOBs).

    Pass ``include_ner=True`` to additionally run
    :func:`agent_core_lib.pii._pii_ner.find_ner_pii` (spaCy names
    / orgs / locations). NER is off by default because the spaCy model
    isn't a hard dependency and the load cost is significant.
    """
    from agent_core_lib.pii._pii_strict_dob import find_strict_dob
    from agent_core_lib.pii._pii_strict_phone import find_strict_phone

    findings = list(find_pii_patterns(text))
    findings.extend(find_strict_phone(text, default_region=phone_region))
    findings.extend(find_strict_dob(text))
    if include_ner:
        from agent_core_lib.pii._pii_ner import find_ner_pii
        findings.extend(find_ner_pii(text))
    return findings
