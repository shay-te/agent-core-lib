"""Session / opaque-token patterns (JWT).

Aggregated into the public ``_PII_PATTERNS`` tuple by
:mod:`agent_core_lib.pii.pii_patterns`. Declaration
order matters (overlap resolver in the scrubber picks the
first-declared span on a tie); the order inside this file
feeds the aggregator in the same sequence.
"""
from __future__ import annotations

import re


PATTERNS = (
    # --- session / token ----------------------------------------------
    # JWT — three base64url segments joined by dots. The first segment
    # always begins with ``eyJ`` because it's the base64 encoding of
    # ``{"`` (the JSON header's opening). That prefix makes JWTs
    # distinctive enough to flag without the false-positive risk of a
    # bare ``segment.segment.segment`` shape. Length floors of 10 per
    # segment keep us from matching short ``a.b.c`` text-fragments that
    # happen to start with ``eyJ``. Tokens routinely encode user id,
    # email, tenant id, and roles in the payload segment — even though
    # they're "credential material" they're PII shape from the model's
    # perspective and we want them out.
    ('jwt', re.compile(
        r'\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b'
    )),

)
