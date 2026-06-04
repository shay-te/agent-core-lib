"""Pydantic v2 concrete LLMView. Subclass this in tool-result types.

Inherits from both the transport marker
:class:`llm_core_lib.safety.llm_view.LLMView` (so the gate's
``isinstance`` check passes) and Pydantic's ``BaseModel`` (so
``ConfigDict(extra='forbid', frozen=True)`` enforces the allowlist).
Pydantic is this repo's dep; ``llm-core-lib`` stays Pydantic-free
behind the marker.
"""
from __future__ import annotations

from typing import Any, Dict

from pydantic import BaseModel, ConfigDict

from llm_core_lib.safety.llm_view import LLMView as _TransportLLMView


class LLMView(_TransportLLMView, BaseModel):
    """Concrete LLM-view base.

    Example::

        class UserLLMView(LLMView):
            id: str
            display_name: str

        # Raises pydantic.ValidationError — ``email`` is not on the allowlist.
        UserLLMView(id='u1', display_name='Jane', email='jane@example.com')
    """

    model_config = ConfigDict(extra='forbid', frozen=True)

    def to_dict(self) -> Dict[str, Any]:
        """Alias of ``model_dump()`` for call sites that prefer the name."""
        return self.model_dump()

    @classmethod
    def allowed_field_names(cls) -> frozenset:
        """Return the field names this view exposes to the LLM."""
        return frozenset(cls.model_fields.keys())

    @classmethod
    def project(cls, data):
        """Build an instance from a dict / attribute-shaped object by
        filtering to the declared allowlist.

        The idiomatic adapter when migrating an existing tool: instead
        of refactoring the upstream service to return a view, the
        tool's last line projects whatever it already has. Returns
        ``None`` for ``None`` input so callers don't need a guard.
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
        """Project an iterable of dicts into a list of views.

        ``None`` / empty inputs return ``[]``. A non-list input
        (single dict / attribute-shaped object) is promoted to a
        one-element list.
        """
        if items is None:
            return []
        if isinstance(items, (list, tuple)):
            return [cls.project(item) for item in items if item is not None]
        return [cls.project(items)]
