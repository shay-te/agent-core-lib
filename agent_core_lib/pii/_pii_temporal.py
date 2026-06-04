"""Temporal PII (date-of-birth) patterns.

Aggregated into the public ``_PII_PATTERNS`` tuple by
:mod:`agent_core_lib.pii.pii_patterns`. Declaration
order matters (overlap resolver in the scrubber picks the
first-declared span on a tie); the order inside this file
feeds the aggregator in the same sequence.
"""
from __future__ import annotations

import re


PATTERNS = (
    # --- temporal -----------------------------------------------------
    # Date-of-birth in obvious context: "dob 1990-01-01", "date of birth 01/01/1990".
    ('date_of_birth', re.compile(
        r'\b(?:dob|date\s+of\s+birth|birthday|born)\s*[:=]?\s*'
        r'(?:\d{4}[-/]\d{1,2}[-/]\d{1,2}|\d{1,2}[-/]\d{1,2}[-/]\d{2,4})\b',
        re.IGNORECASE,
    )),

)
