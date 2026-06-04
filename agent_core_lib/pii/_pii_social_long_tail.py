"""Long-tail social handle / messaging patterns.

Snapchat / WhatsApp / Signal / Slack / Bluesky — the platforms not in
the original contact set.
"""
from __future__ import annotations

import re


PATTERNS = (
    # Snapchat — keyword-anchored handle.
    ('snapchat_handle', re.compile(
        r'\bsnapchat\s*[:=@]?\s*@?[A-Za-z][A-Za-z0-9._\-]{2,14}\b',
        re.IGNORECASE,
    )),
    # WhatsApp — wa.me URL OR keyword + E.164 phone.
    ('whatsapp_number', re.compile(
        r'\bhttps?://wa\.me/\+?\d{6,15}\b'
        r'|\bwhatsapp\s*[:=]?\s*\+?\d{6,15}\b',
        re.IGNORECASE,
    )),
    # Signal — signal.me URL OR keyword + phone-shape.
    ('signal_handle', re.compile(
        r'\bhttps?://signal\.me/#[A-Za-z0-9+/=_\-]{10,}\b'
        r'|\bsignal\s*[:=]?\s*\+?\d{6,15}\b',
        re.IGNORECASE,
    )),
    # Slack user ID — ``<@U[A-Z0-9]+>`` mention OR keyword.
    ('slack_user_id', re.compile(
        r'<@U[A-Z0-9]{8,}>'
        r'|\bslack\s+user\s*[:=]?\s*U[A-Z0-9]{8,}\b',
        re.IGNORECASE,
    )),
    # Bluesky — ``@user.bsky.social``. ``\b`` doesn't bind before
    # ``@`` (both non-word), so use the same lookbehind shape as
    # ``twitter_handle`` in ``_pii_contact``.
    ('bluesky_handle', re.compile(
        r'(?:^|(?<=[ \t\n\r(\[,;:"\']))'
        r'@[A-Za-z0-9_\-]+\.bsky\.social\b'
    )),
)
