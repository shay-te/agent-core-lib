"""Long-tail national-ID patterns — countries not in the original set.

EG / PK / BD / VN / ID / PH / SA / NG / KE / GH. All keyword-anchored
because the bare digit shapes collide with phone fragments, order ids,
and the other countries' formats.
"""
from __future__ import annotations

import re


PATTERNS = (
    # EG national ID — 14 digits, keyword (English or Arabic).
    ('eg_national_id', re.compile(
        r'\b(?:national\s+id|الرقم\s+القومي)\s*[:=]?\s*\d{14}\b',
        re.IGNORECASE,
    )),
    # PK CNIC — XXXXX-XXXXXXX-X.
    ('pk_cnic', re.compile(r'\bCNIC\s*[:=]?\s*\d{5}-\d{7}-\d\b', re.IGNORECASE)),
    # BD NID — 10 / 13 / 17 digit forms, keyword-anchored.
    ('bd_nid', re.compile(
        r'\bNID\s*[:=]?\s*(?:\d{10}|\d{13}|\d{17})\b',
        re.IGNORECASE,
    )),
    # VN national ID — 12 digits, keyword (English or Vietnamese).
    ('vn_national_id', re.compile(
        r'\b(?:CCCD|căn\s+cước\s+công\s+dân)\s*[:=]?\s*\d{12}\b',
        re.IGNORECASE,
    )),
    # ID KTP — 16 digits.
    ('id_ktp', re.compile(r'\bKTP\s*[:=]?\s*\d{16}\b', re.IGNORECASE)),
    # PH TIN — XXX-XXX-XXX-XXX (12-digit grouped).
    ('ph_tin', re.compile(
        r'\bTIN\s*[:=]?\s*\d{3}-\d{3}-\d{3}-\d{3}\b',
        re.IGNORECASE,
    )),
    # SA NIN/Iqama — 10 digits starting with 1 or 2.
    ('sa_nin', re.compile(
        r'\b(?:NIN|Iqama|الهوية)\s*[:=]?\s*[12]\d{9}\b',
        re.IGNORECASE,
    )),
    # NG NIN — 11 digits, keyword.
    ('ng_nin', re.compile(r'\bNIN\s*[:=]?\s*\d{11}\b', re.IGNORECASE)),
    # KE national ID — 7-8 digit serial, keyword.
    ('ke_id', re.compile(
        r'\b(?:Kenya\s+ID|HUDUMA)\s*[:=]?\s*\d{7,8}\b',
        re.IGNORECASE,
    )),
    # GH Ghana Card — ``GHA-XXXXXXXXX-X`` shape.
    ('gh_ghana_card', re.compile(r'\bGHA-\d{9}-\d\b', re.IGNORECASE)),
)
