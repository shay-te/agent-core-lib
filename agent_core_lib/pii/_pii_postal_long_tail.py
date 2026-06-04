"""Long-tail postcode patterns — ZA / NZ / RU / KR / TH / TW / HK / SG.

All keyword-anchored because the bare digit shapes collide with the
shorter European postcodes already declared and with order ids.
"""
from __future__ import annotations

import re


PATTERNS = (
    # ZA postcode — 4 digits, keyword.
    ('za_postcode', re.compile(
        r'\b(?:postcode|posbus)\s*[:=]?\s*\d{4}\b',
        re.IGNORECASE,
    )),
    # NZ postcode — 4 digits, keyword.
    ('nz_postcode', re.compile(
        r'\b(?:NZ\s+postcode|post\s*code)\s*[:=]?\s*\d{4}\b',
        re.IGNORECASE,
    )),
    # RU postcode — 6 digits, keyword (English or Russian).
    ('ru_postcode', re.compile(
        r'\b(?:индекс|почтовый\s+индекс|RU-)\s*[:=]?\s*\d{6}\b',
        re.IGNORECASE,
    )),
    # KR postcode — 5 digits, keyword (English or Korean).
    ('kr_postcode', re.compile(
        r'\b(?:우편번호|postcode|KR-)\s*[:=]?\s*\d{5}\b',
        re.IGNORECASE,
    )),
    # TH postcode — 5 digits, keyword (English or Thai).
    ('th_postcode', re.compile(
        r'\b(?:รหัสไปรษณีย์|postcode|TH-)\s*[:=]?\s*\d{5}\b',
        re.IGNORECASE,
    )),
    # TW postcode — 3-, 5- or 6-digit forms; keyword anchor.
    ('tw_postcode', re.compile(
        r'\b(?:郵遞區號|TW-)\s*[:=]?\s*\d{3}(?:-?\d{2,3})?\b',
        re.IGNORECASE,
    )),
    # HK postcode — non-existent in practice, but the form ``999077``
    # is used for international mail; keyword-anchored.
    ('hk_postcode', re.compile(
        r'\b(?:HK\s+postcode|香港郵遞)\s*[:=]?\s*\d{6}\b',
        re.IGNORECASE,
    )),
    # SG postcode — 6 digits.
    ('sg_postcode', re.compile(
        r'\b(?:Singapore\s+postcode|SG-)\s*[:=]?\s*\d{6}\b',
        re.IGNORECASE,
    )),
)
