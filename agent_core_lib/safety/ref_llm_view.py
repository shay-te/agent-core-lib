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


RefType = NewType('RefType', int)
"""Wire-int entity-type tag carried in the ``refs`` index.

Agent-core-lib is domain-agnostic — it does NOT enumerate which entity
types exist. Consumers (the admin/backend layer) define their own
``IntEnum`` whose ``.value`` (or a bare int) is what the helpers below
see. Int is the wire format because jsonb storage + render-path lookups
are O(N-refs) per turn — every byte / hash op compounds.
"""


def _coerce_ref_type(value: Union[RefType, int, Any]) -> int:
    raw = getattr(value, 'value', value)
    return int(raw)


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


def build_refs(ref_type: Union[RefType, int, Any], ids: Iterable[int]) -> List[Dict[str, Any]]:
    """Build a list of ``refs`` entries from an iterable of ids.

    Duplicates are removed in input order so the render path's per-type
    hydration batch is naturally minimal.
    """
    type_id = _coerce_ref_type(ref_type)
    seen = set()
    out: List[Dict[str, Any]] = []
    for raw in ids:
        if raw is None:
            continue
        i = int(raw)
        if i in seen:
            continue
        seen.add(i)
        out.append({'type': type_id, 'id': i})
    return out
