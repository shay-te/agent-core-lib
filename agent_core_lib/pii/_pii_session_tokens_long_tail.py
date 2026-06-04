"""Long-tail session / authentication token patterns.

OAuth bearer tokens, PHPSESSID / JSESSIONID cookies, CSRF tokens —
the credential-shaped strings that aren't full JWTs (the JWT pattern
in ``_pii_session_token.py`` covers the ``eyJ`` 3-part shape).
"""
from __future__ import annotations

import re


PATTERNS = (
    # OAuth 2.0 bearer header / value — ``Bearer <token>`` (whitespace-
    # tolerant). The token value can be any URL-safe string >= 16 chars.
    ('oauth_bearer', re.compile(
        r'\bBearer\s+[A-Za-z0-9._\-/+=]{16,}\b',
    )),
    # Classic PHP session cookie value.
    ('php_session_id', re.compile(
        r'\bPHPSESSID\s*[:=]\s*[A-Za-z0-9,\-]{22,}\b',
    )),
    # Java servlet session cookie value.
    ('jsession_id', re.compile(
        r'\bJSESSIONID\s*[:=]\s*[A-Za-z0-9._\-]{16,}\b',
    )),
    # CSRF token — header (``X-CSRF-TOKEN``) or named form field.
    ('csrf_token', re.compile(
        r'\b(?:X-CSRF-TOKEN|csrf[_\-]token)\s*[:=]\s*[A-Za-z0-9._\-+/=]{16,}\b',
        re.IGNORECASE,
    )),
)
