"""Long-tail vehicle license plate patterns — UK / EU / CA.

The US plate pattern stays in ``_pii_vehicle.py``. Each new plate
shape is keyword-anchored because the bare shapes collide with
short alphanumeric codes (e.g., a bare UK plate ``AB12CDE`` looks
like a SKU).
"""
from __future__ import annotations

import re


PATTERNS = (
    # UK 2001-current — 2 letters + 2 digits + 3 letters; the optional
    # space between digit pair and trailing letters is common.
    ('uk_license_plate', re.compile(
        r'\b(?:UK\s+plate|reg(?:istration)?\s+number?)\s*[:=]?\s*[A-Z]{2}\d{2}\s?[A-Z]{3}\b',
        re.IGNORECASE,
    )),
    # EU plate — generic ``country + 1-4 letters + 1-4 digits +
    # optional 1-3 letters``. Keyword-anchored.
    ('eu_license_plate', re.compile(
        r'\bEU\s+plate\s*[:=]?\s*[A-Z]{1,4}[\s\-]?\d{1,4}[\s\-]?[A-Z]{0,3}\b',
        re.IGNORECASE,
    )),
    # CA per-province — variable; keyword anchor and broad shape.
    ('ca_license_plate', re.compile(
        r'\b(?:CA\s+plate|Canadian\s+plate)\s*[:=]?\s*[A-Z0-9]{2,4}[\s\-]?[A-Z0-9]{2,4}\b',
        re.IGNORECASE,
    )),
)
