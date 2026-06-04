"""LLM-view concrete base — Pydantic v2.

This is the class **tool authors actually subclass**. It carries the
:class:`pydantic.BaseModel` machinery + the
``ConfigDict(extra='forbid', frozen=True)`` enforcement that makes
the declared field list a real allowlist.

Two-layer structure (why):

* :class:`llm_core_lib.safety.llm_view.LLMView` (stdlib ABC, no Pydantic
  dep) is what :func:`llm_core_lib.safety.payload_gate.to_llm_payload`
  ``isinstance``-checks against. It lives in the transport layer so
  the gate has a name to assert against without
  :mod:`llm_core_lib` having to depend on :mod:`agent_core_lib` (the
  existing ``test_boundary.py`` rule forbids that direction).
* :class:`agent_core_lib.safety.llm_view.LLMView` — *this class* —
  inherits from both the transport ABC and Pydantic's ``BaseModel``,
  so it satisfies ``isinstance(view, LLMView)`` for the gate AND
  carries the Pydantic ``ConfigDict`` enforcement. ``model_dump`` is
  Pydantic's; the abstract method on the ABC is named to match.

The Pydantic dependency lives in this repo's ``requirements.txt``
(not in ``llm-core-lib``'s) because the data-shape contract for tool
returns is an agent-layer concern, not a transport-layer one. See
the architecture note in ``architecture.md``.
"""
from __future__ import annotations

from typing import Any, Dict

from pydantic import BaseModel, ConfigDict

from llm_core_lib.safety.llm_view import LLMView as _TransportLLMView


class LLMView(_TransportLLMView, BaseModel):
    """Concrete LLM-view base. Subclass this in tool-result types.

    Concrete subclasses declare every field the LLM is permitted to
    see — anything not on the field list is rejected at construction
    by Pydantic's ``extra='forbid'`` rule. Example:

    .. code-block:: python

        class UserLLMView(LLMView):
            id: str
            display_name: str

        # Raises pydantic.ValidationError — `email` isn't on the allowlist.
        UserLLMView(id='u1', display_name='Jane', email='jane@example.com')

    Two flags together give the safety layer the guarantees it needs:

    * ``extra='forbid'`` — construction with an unknown field raises
      :class:`pydantic.ValidationError`; the declared field list IS
      the complete allowlist of what the LLM will see.
    * ``frozen=True`` — post-init assignment is rejected, so nothing
      downstream can splice a raw email / address onto an
      already-built view.
    """

    model_config = ConfigDict(extra='forbid', frozen=True)

    def to_dict(self) -> Dict[str, Any]:
        """Thin alias of ``model_dump()`` — preserved for call sites
        that prefer the name. The choke point reaches for
        ``model_dump`` directly (that's the abstract-method name on
        the transport ABC); this exists for ergonomics.
        """
        return self.model_dump()

    @classmethod
    def allowed_field_names(cls) -> frozenset:
        """Return the set of field names this view will expose to the LLM.

        Used by ``test_*_view_fields_are_locked`` style tests so a
        reviewer can codify the allowlist and the test fails the
        moment someone widens it without updating the test.
        """
        return frozenset(cls.model_fields.keys())

    @classmethod
    def project(cls, data):
        """Build an instance from a dict by filtering to the declared allowlist.

        The reverse of ``model_dump`` — given a raw upstream dict (an
        ORM row that's been ``ResultToDict``'d, an Elasticsearch hit,
        an arbitrary service return) drop every key that isn't on
        this view's declared field list, then construct the view
        from what's left. This is the idiomatic adapter when
        migrating an existing tool: instead of refactoring the
        upstream service to return a view, the tool's last line
        projects what it already has.

        ``None`` data returns ``None`` so callers don't have to add
        a guard at every call site. Non-mapping inputs that look
        attribute-shaped (``getattr`` returns a value for the field
        names) are also supported — that lets ORM rows / SimpleNamespace
        objects flow through the same gate without a manual dict-cast.
        """
        if data is None:
            return None
        allowed = cls.model_fields.keys()
        if hasattr(data, 'get'):
            kwargs = {name: data.get(name) for name in allowed if name in data}
        else:
            kwargs = {
                name: getattr(data, name)
                for name in allowed
                if hasattr(data, name)
            }
        return cls(**kwargs)

    @classmethod
    def project_list(cls, items):
        """Project a list / tuple / iterable of dicts into a list of views.

        ``None`` or empty inputs return ``[]`` so the caller can pass
        the gate output straight through without a None-guard.
        Anything that isn't iterable falls through to a single-item
        projection — that absorbs the common case where an upstream
        service returns either a list or a single dict depending on
        count.
        """
        if items is None:
            return []
        if isinstance(items, (list, tuple)):
            return [cls.project(item) for item in items if item is not None]
        return [cls.project(items)]
