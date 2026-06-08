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

from typing import Any, Dict, Iterable, List, NewType, Optional, Union

from pydantic import ConfigDict

from agent_core_lib.safety.llm_view import LLMView
from llm_core_lib.safety.llm_view import RefLLMView as _TransportRefLLMView


RefType = NewType('RefType', str)
"""Wire-string entity-type tag carried in the ``refs`` index.

Agent-core-lib is domain-agnostic — it does NOT enumerate which entity
types exist. Consumers (the admin/backend layer) define their own enum
or set of constants whose ``.value`` (or string itself) is what the
helpers below see.
"""


def _coerce_ref_type(value: Union[RefType, str, Any]) -> str:
    raw = getattr(value, 'value', value)
    return str(raw)


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


def build_ref(ref_type: Union[RefType, str], id_: int) -> Dict[str, Any]:
    """Build one ``refs`` index entry.

    Returns the persistence shape the render path keys on:
    ``{'type': <str>, 'id': <int>}``. Use this helper at every tool
    callsite so the wire format stays consistent. ``ref_type`` is
    accepted as either a plain string or any object with a ``.value``
    attribute (e.g. a consumer-defined ``str`` Enum).
    """
    return {'type': _coerce_ref_type(ref_type), 'id': int(id_)}


def build_refs(ref_type: Union[RefType, str], ids: Iterable[int]) -> List[Dict[str, Any]]:
    """Build a list of ``refs`` entries from an iterable of ids.

    Duplicates are removed in input order so the render path's per-type
    hydration batch is naturally minimal.
    """
    type_str = _coerce_ref_type(ref_type)
    seen = set()
    out: List[Dict[str, Any]] = []
    for raw in ids:
        if raw is None:
            continue
        i = int(raw)
        if i in seen:
            continue
        seen.add(i)
        out.append({'type': type_str, 'id': i})
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
