"""Long-tail cryptocurrency wallet patterns.

TRON / Cardano / Polkadot / Cosmos / Ripple-XRP — the chains beyond
the Bitcoin/Ethereum/Monero/Solana/Litecoin set already in
``_pii_financial``. Aggregated into the public ``_PII_PATTERNS`` tuple
by :mod:`agent_core_lib.pii.pii_patterns`.
"""
from __future__ import annotations

import re


PATTERNS = (
    # TRON — base58, 34 chars starting with ``T``.
    ('tron_address', re.compile(r'\bT[1-9A-HJ-NP-Za-km-z]{33}\b')),
    # Cardano Shelley — bech32, ``addr1`` prefix + ~98 chars.
    ('cardano_address', re.compile(r'\baddr1[02-9ac-hj-np-z]{50,100}\b')),
    # Polkadot — base58, 47-48 chars, often starts with ``1``.
    ('polkadot_address', re.compile(
        r'\b(?:dot|polkadot)\s*[:=]?\s*1[1-9A-HJ-NP-Za-km-z]{46,47}\b',
        re.IGNORECASE,
    )),
    # Cosmos — bech32, ``cosmos1`` prefix + 38 chars.
    ('cosmos_address', re.compile(r'\bcosmos1[02-9ac-hj-np-z]{38}\b')),
    # Ripple XRP — base58, ``r`` prefix + 24-34 chars.
    ('ripple_address', re.compile(
        r'\b(?:XRP|ripple)\s*[:=]?\s*r[1-9A-HJ-NP-Za-km-z]{24,34}\b',
        re.IGNORECASE,
    )),
)
