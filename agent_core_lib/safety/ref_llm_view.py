"""ID-only views for the MODEL boundary.

The LLM only ever receives ``{id: int}``. Real data lives in the DB and
is fetched live at render time via the hydration path; the model never
sees PII. ``RefLLMView`` is the single shared id-only view across every
entity type. Per-type views exist ONLY when the model legitimately needs
a non-PII signal (e.g. a match score) to reason on.

Type is carried by the CALLER in the ``refs`` index it emits alongside
the payload — never by adding a ``type`` field to ``RefLLMView`` itself.
"""
from __future__ import annotations

import enum
from typing import Any, Dict, Iterable, List, Optional

from pydantic import ConfigDict

from agent_core_lib.safety.llm_view import LLMView
from llm_core_lib.safety.llm_view import RefLLMView as _TransportRefLLMView


class RefType(str, enum.Enum):
    """Entity types the render path knows how to hydrate.

    Values are stable wire strings — the persistence layer stores them
    in the ``refs`` jsonb column and the render path keys hydration
    batches on them.
    """
    USER = 'user'
    ADMIN_USER = 'admin_user'
    ORGANIZATION = 'organization'
    CONVERSATION = 'conversation'
    CONVERSATION_MESSAGE = 'conversation_message'
    TASK = 'task'
    PACKAGE = 'package'
    PACKAGE_ITEM = 'package_item'
    EVENT = 'event'
    EVENT_TICKET = 'event_ticket'
    WORKFLOW = 'workflow'
    FORM = 'form'
    FORM_SUBMISSION = 'form_submission'
    CUSTOM_FIELD = 'custom_field'
    USER_COMMENT = 'user_comment'
    MATCH_EXPLANATION = 'match_explanation'


class RefLLMView(_TransportRefLLMView, LLMView):
    """Shared id-only view for the MODEL boundary.

    Inherits ``_TransportRefLLMView`` so the payload-gate's
    ``isinstance`` check passes; inherits ``LLMView`` for the Pydantic
    ``model_dump`` + allowlist contract. The model emits and consumes
    only ids; type tagging happens in the caller's ``refs`` index.
    """
    id: int
    model_config = ConfigDict(extra='forbid', frozen=True)


class ActionResultRefLLMView(RefLLMView):
    """Action / status result for non-entity tool returns.

    Used by write-side tools whose return is "did it succeed?" rather
    than "here is an entity". ``id`` is 0 when the action is not tied
    to a single entity (e.g. bulk introduce). ``reason`` is a short
    enum-like code (``'not_found'``, ``'no_permission'``,
    ``'service_unavailable'``) — NEVER user-facing free text and NEVER
    contains names/emails.
    """
    id: int = 0
    success: bool
    reason: Optional[str] = None


class StatsRefLLMView(RefLLMView):
    """Aggregate / non-PII numeric stats payload.

    For dashboard tools that return counts, distributions, or
    time-series rows. ``stats`` is opaque numeric/aggregate data — the
    caller MUST ensure no PII (names, emails, free text) is embedded.
    ``id`` is 0 (stats are not entity-scoped).
    """
    id: int = 0
    stats: Any


def build_ref(ref_type: RefType, id_: int) -> Dict[str, Any]:
    """Build one ``refs`` index entry.

    Returns the persistence shape the render path keys on:
    ``{'type': '<RefType.value>', 'id': <int>}``. Use this helper at
    every tool callsite so the wire format stays consistent.
    """
    return {'type': ref_type.value, 'id': int(id_)}


def build_refs(ref_type: RefType, ids: Iterable[int]) -> List[Dict[str, Any]]:
    """Build a list of ``refs`` entries from an iterable of ids.

    Duplicates are removed in input order so the render path's per-type
    hydration batch is naturally minimal.
    """
    seen = set()
    out: List[Dict[str, Any]] = []
    for raw in ids:
        if raw is None:
            continue
        i = int(raw)
        if i in seen:
            continue
        seen.add(i)
        out.append({'type': ref_type.value, 'id': i})
    return out


def merge_refs(*ref_lists: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Flatten + dedupe several ``refs`` lists for a single message row.

    Keying on ``(type, id)`` — the render path's hydration batch key.
    """
    seen = set()
    out: List[Dict[str, Any]] = []
    for refs in ref_lists:
        for ref in refs or ():
            key = (ref.get('type'), ref.get('id'))
            if key in seen:
                continue
            seen.add(key)
            out.append({'type': ref['type'], 'id': ref['id']})
    return out
