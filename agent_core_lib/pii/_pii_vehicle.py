"""Vehicle identifier patterns (VIN / US license plate).

Aggregated into the public ``_PII_PATTERNS`` tuple by
:mod:`agent_core_lib.pii.pii_patterns`. Declaration
order matters (overlap resolver in the scrubber picks the
first-declared span on a tie); the order inside this file
feeds the aggregator in the same sequence.
"""
from __future__ import annotations

import re


PATTERNS = (
    # --- vehicle ------------------------------------------------------
    # VIN: 17 alphanumerics, no I/O/Q.
    ('vin', re.compile(r'\b[A-HJ-NPR-Z0-9]{17}\b')),
    # US license plate: very loose — 5-8 alphanumerics with at least
    # one digit. Best-effort; tighten per-state if false positives bite.
    ('us_license_plate', re.compile(
        r'\b(?=[A-Z0-9 \-]{5,8}\b)[A-Z0-9]+[ \-]?[A-Z0-9]+\b'
    )),

)
