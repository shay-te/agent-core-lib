"""Financial PII patterns (cards / banks / IBAN / crypto wallets).

Aggregated into the public ``_PII_PATTERNS`` tuple by
:mod:`agent_core_lib.pii.pii_patterns`. Declaration
order matters (overlap resolver in the scrubber picks the
first-declared span on a tie); the order inside this file
feeds the aggregator in the same sequence.
"""
from __future__ import annotations

import re


PATTERNS = (
    # --- financial ----------------------------------------------------
    # 13–19 digit card numbers, with optional space or dash separators.
    # Doesn't validate the Luhn checksum — that's a job for the
    # scrubber's caller, not the detector.
    ('credit_card', re.compile(r'\b(?:\d[ \-]?){13,19}\b')),
    # CVV in obvious context: "cvv 123", "cvc: 1234", "security code 123".
    ('credit_card_cvv', re.compile(
        r'\b(?:cvv|cvc|security\s+code)\s*[:=]?\s*\d{3,4}\b',
        re.IGNORECASE,
    )),
    # IBAN: 2-letter country + 2-digit check + 11-30 alphanumerics.
    # The canonical printed form groups characters in 4-char blocks
    # separated by whitespace (``GB82 WEST 1234 5698 7654 32``); accept
    # optional whitespace anywhere inside the alphanumeric body so both
    # the printed and machine forms match.
    ('iban', re.compile(
        r'\b[A-Z]{2}\d{2}(?:\s?[A-Z0-9]){11,32}\b'
    )),
    # SWIFT / BIC: 4 letters + 2 letters + 2 alphanumeric +
    # optional 3 alphanumeric.
    ('swift_bic', re.compile(r'\b[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}(?:[A-Z0-9]{3})?\b')),
    # US ABA routing number: 9 digits, usually whitespace-separated.
    ('us_routing_number', re.compile(r'\b\d{9}\b')),
    # US bank account: 4-17 digits, usually labelled. Match labelled form.
    ('us_bank_account', re.compile(
        r'\b(?:account|acct)[\s#:]*\d{4,17}\b',
        re.IGNORECASE,
    )),
    # Bitcoin address: legacy (1...), p2sh (3...), bech32 (bc1...).
    ('bitcoin_address', re.compile(
        r'\b(?:bc1[a-zA-HJ-NP-Z0-9]{25,87}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b'
    )),

    # --- crypto wallets -----------------------------------------------
    # Ethereum address — ``0x`` + 40 hex chars (case-insensitive; EIP-55
    # mixed-case checksums are accepted but not validated).
    ('ethereum_address', re.compile(r'\b0x[a-fA-F0-9]{40}\b')),
    # Monero mainnet — base58, 95 chars starting with ``4``.
    ('monero_address', re.compile(r'\b4[1-9A-HJ-NP-Za-km-z]{94}\b')),
    # Solana — base58, 32-44 chars; loosely bounded since base58 has
    # ambiguous shape vs. other bare alphanumerics. Keyword-anchored
    # to avoid collision with random IDs.
    ('solana_address', re.compile(
        r'\b(?:solana|SOL)\s*[:=]?\s*[1-9A-HJ-NP-Za-km-z]{32,44}\b',
        re.IGNORECASE,
    )),
    # Litecoin — L / M / 3 prefix + 26-33 base58 chars.
    ('litecoin_address', re.compile(r'\b[LM3][a-km-zA-HJ-NP-Z1-9]{25,33}\b')),

    # --- additional bank identifiers ----------------------------------
    # IN IFSC — 4 letters + ``0`` + 6 alphanumeric chars.
    ('in_ifsc', re.compile(r'\b[A-Z]{4}0[A-Z0-9]{6}\b')),
    # AU BSB — XXX-XXX, keyword anchor.
    ('au_bsb', re.compile(r'\bBSB\s*[:=]?\s*\d{3}-?\d{3}\b', re.IGNORECASE)),
    # MX CLABE — 18 digits, keyword anchor, checksum-validated.
    ('mx_clabe', re.compile(r'\bCLABE\s*[:=]?\s*\d{18}\b', re.IGNORECASE)),
    # JP zengin code — 4-digit bank + 3-digit branch + 7-digit account,
    # keyword anchor.
    ('jp_zengin', re.compile(
        r'\b(?:zengin|銀行コード)\s*[:=]?\s*\d{4}-?\d{3}-?\d{7}\b',
        re.IGNORECASE,
    )),

)
