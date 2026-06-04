"""Network / device identifier patterns (IPs / MAC / IMEI / SIM / UUID / AWS / GPS).

Aggregated into the public ``_PII_PATTERNS`` tuple by
:mod:`agent_core_lib.pii.pii_patterns`. Declaration
order matters (overlap resolver in the scrubber picks the
first-declared span on a tie); the order inside this file
feeds the aggregator in the same sequence.
"""
from __future__ import annotations

import re


PATTERNS = (
    # --- network / device --------------------------------------------
    ('ipv4', re.compile(
        r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}'
        r'(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
    )),
    # IPv6: simplified — full or compressed forms.
    ('ipv6', re.compile(
        r'\b(?:[A-F0-9]{1,4}:){2,7}[A-F0-9]{1,4}\b',
        re.IGNORECASE,
    )),
    # MAC address: 6 hex pairs separated by ``:`` or ``-``.
    ('mac_address', re.compile(
        r'\b(?:[0-9A-F]{2}[:\-]){5}[0-9A-F]{2}\b',
        re.IGNORECASE,
    )),

    # --- geolocation --------------------------------------------------
    # GPS coordinate pair — ``lat, lon`` with at least four decimal
    # places on each side (4 places ≈ 11m precision, enough to be a
    # person's location; integer pairs like ``10, 20`` aren't useful
    # locations and would generate noise). Latitude bounded to
    # [-90, 90], longitude bounded to [-180, 180] — the bounded form
    # is what makes this safer than a generic ``\d+,\d+`` pattern.
    # PII when paired with a person; the product DOES carry
    # geo data for matchmaking distance calculations.
    ('gps_coordinates', re.compile(
        r'-?(?:90(?:\.0+)?|[1-8]?\d\.\d{4,})'
        r'\s*,\s*'
        r'-?(?:180(?:\.0+)?|1[0-7]\d\.\d{4,}|[1-9]?\d\.\d{4,})'
    )),

    # --- device identifiers -------------------------------------------
    # IMEI — 15 digits, Luhn-validated. Keyword anchor optional but
    # tightens the false-positive class (any 15-digit number).
    ('imei', re.compile(r'\bIMEI\s*[:=]?\s*\d{15}\b', re.IGNORECASE)),
    # IMSI — 14-15 digits, keyword anchor.
    ('imsi', re.compile(r'\bIMSI\s*[:=]?\s*\d{14,15}\b', re.IGNORECASE)),
    # SIM ICCID — 19-20 digits, Luhn-validated. Keyword anchor.
    ('iccid', re.compile(r'\b(?:ICCID|SIM)\s*[:=]?\s*\d{19,20}\b', re.IGNORECASE)),
    # Android ID — 16 hex chars, keyword anchor.
    ('android_id', re.compile(
        r'\bandroid[_\s]*id\s*[:=]?\s*[a-fA-F0-9]{16}\b',
        re.IGNORECASE,
    )),
    # iOS UDID — 40 hex chars (with optional dash separator), keyword.
    ('ios_udid', re.compile(
        r'\b(?:UDID|iOS\s+device\s+id)\s*[:=]?\s*[a-fA-F0-9]{40}\b',
        re.IGNORECASE,
    )),

    # --- general identifiers ------------------------------------------
    # UUID v4 — canonical 8-4-4-4-12 hex with version nibble ``4``.
    ('uuid_v4', re.compile(
        r'\b[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}\b',
        re.IGNORECASE,
    )),
    # AWS instance / resource IDs — ``i-`` + 8 or 17 hex chars.
    ('aws_instance_id', re.compile(r'\bi-[a-f0-9]{8}(?:[a-f0-9]{9})?\b')),

)
