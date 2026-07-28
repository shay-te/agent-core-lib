"""Adversarial tests for the Pydantic-backed :class:`LLMView`.

These probes attack the **concrete** allowlist enforcement —
``ConfigDict(extra='forbid', frozen=True)`` and the field declarations
on the Pydantic v2 ``BaseModel`` base. Subclass tricks that a tool
author could (accidentally or deliberately) use to slip data past the
allowlist:

* :class:`TestBypassConfigDictOverride` — a subclass overrides
  ``model_config`` and drops ``extra='forbid'`` (or ``frozen=True``).
  Pydantic v2 does NOT merge ``model_config`` across the MRO; the
  child wins. A future change could either freeze the base's
  ``model_config`` via a metaclass or require every subclass to inherit
  via a class-decorator that re-applies the contract.
* :class:`TestBypassComputedFieldLeaks` — a subclass adds a
  ``@computed_field`` that derives data outside the declared field
  list. ``model_dump`` exposes it; ``model_fields`` doesn't see it.
  Two-API drift.
* :class:`TestBypassAnyTypedNestedDict` — a field typed ``dict`` or
  ``Any`` accepts arbitrary content that survives ``model_dump()``
  verbatim. The gate only enforces the OUTER type; per-field type
  walking would be needed to catch this.
* :class:`TestBypassFrozenViaObjectSetattr` — ``object.__setattr__``
  bypasses Pydantic's frozen check. Python's data model has no way
  to defend against this; the bypass is documented as a known
  limitation.

The transport-layer gate-behavior probes (refuses str/int/tuple/set,
generic envelope shape, run_tool wrapper) live in
``llm-core-lib/llm_core_lib/tests/test_safety_adversarial.py``.
"""
from __future__ import annotations

import unittest
from typing import Any, Dict

from pydantic import BaseModel, ConfigDict, ValidationError, computed_field

from agent_core_lib.safety.llm_view import LLMView


class _UserView(LLMView):
    id: str
    display_name: str


# ===========================================================================
# BYPASS — subclass overrides ``model_config``
# ===========================================================================


class TestBypassConfigDictOverride(unittest.TestCase):
    """Documented limitation: Pydantic v2 does NOT merge ``model_config``
    across the MRO. A subclass that redeclares ``model_config`` and
    drops ``extra='forbid'`` or ``frozen=True`` weakens the contract
    silently. Lock the current behavior so a future hardening (a
    metaclass that re-merges, or a class-decorator that re-applies)
    has a regression test to point at."""

    def test_subclass_dropping_extra_forbid_accepts_unknown_fields(self):
        class _LooseView(LLMView):
            id: str
            model_config = ConfigDict(extra='allow')  # SAFETY DROPPED

        # The subclass now accepts unknown fields and dumps them.
        view = _LooseView(id='u1', email='leak@example.com')
        # Pydantic accepts both — the leak path is the dump:
        self.assertIn('email', view.model_dump())

    def test_subclass_dropping_frozen_allows_post_init_mutation(self):
        class _MutableView(LLMView):
            id: str
            model_config = ConfigDict(extra='forbid', frozen=False)

        view = _MutableView(id='u1')
        view.id = 'mutated'  # NOT rejected — frozen was dropped
        self.assertEqual(view.id, 'mutated')

    def test_subclass_keeping_both_flags_remains_safe(self):
        # The opposite case — a subclass that redeclares ``model_config``
        # but keeps both flags is fine. Lock that the contract still
        # holds in that branch.
        class _StillSafeView(LLMView):
            id: str
            model_config = ConfigDict(extra='forbid', frozen=True)

        with self.assertRaises(ValidationError):
            _StillSafeView(id='u1', email='leak@example.com')


# ===========================================================================
# BYPASS — computed fields
# ===========================================================================


class TestBypassComputedFieldLeaks(unittest.TestCase):
    """A ``@computed_field`` derives a value at dump time that is NOT
    in ``model_fields``. The declared allowlist misses it; ``model_dump``
    exposes it. The two APIs drift — lock so a future "scan computed
    fields too" hardening has a regression test."""

    def test_computed_field_exposes_data_not_in_allowlist(self):
        class _DerivedView(LLMView):
            id: str
            display_name: str

            @computed_field
            @property
            def email_domain(self) -> str:
                # Derived from internal state — not declared as a field.
                return 'example.com'

        view = _DerivedView(id='u1', display_name='Jane')
        # ``model_fields`` (allowlist) misses it...
        self.assertNotIn('email_domain', _DerivedView.model_fields.keys())
        # ...but ``model_dump`` exposes it.
        self.assertIn('email_domain', view.model_dump())


# ===========================================================================
# BYPASS — ``Any`` / ``dict`` -typed nested content
# ===========================================================================


class TestBypassAnyTypedNestedDict(unittest.TestCase):
    """A field typed ``dict`` / ``Any`` accepts whatever the caller
    hands it. ``model_dump`` returns the dict verbatim. The gate's
    outer ``isinstance`` check doesn't recurse into the field
    contents — the only defense is "tools must not declare ``Any``
    -typed fields"."""

    def test_any_field_smuggles_raw_dict(self):
        class _SmugglerView(LLMView):
            id: str
            payload: Any

        view = _SmugglerView(id='u1', payload={'email': 'leak@example.com'})
        dumped = view.model_dump()
        self.assertEqual(dumped['payload'], {'email': 'leak@example.com'})

    def test_dict_field_smuggles_list_of_dicts(self):
        class _ListSmugglerView(LLMView):
            id: str
            payload: Dict[str, Any]

        view = _ListSmugglerView(
            id='u1',
            payload={'users': [{'email': 'a@b.com'}]},
        )
        dumped = view.model_dump()
        self.assertEqual(dumped['payload']['users'][0]['email'], 'a@b.com')

    def test_nested_non_llmview_basemodel_field(self):
        # A field typed as another (non-LLMView) BaseModel — Pydantic
        # validates the nested model's fields, but if the nested model
        # itself doesn't carry ``extra='forbid'``, it accepts extras.
        class _RawNested(BaseModel):
            id: str
            # No model_config — defaults to ``extra='ignore'``, which
            # silently drops unknown fields rather than rejecting.

        class _ContainerView(LLMView):
            id: str
            nested: _RawNested

        # The raw nested model silently drops the unknown field.
        nested = _RawNested(id='n1', email='dropped@example.com')
        view = _ContainerView(id='u1', nested=nested)
        # Email is dropped (not preserved on the nested) — but the
        # nested itself is fine. Lock the current behavior so a future
        # "every nested model must itself be an LLMView" rule has a
        # test to enforce.
        self.assertEqual(view.model_dump()['nested'], {'id': 'n1'})


# ===========================================================================
# BYPASS — ``object.__setattr__`` against frozen
# ===========================================================================


class TestBypassFrozenViaObjectSetattr(unittest.TestCase):
    def test_object_setattr_circumvents_frozen(self):
        view = _UserView(id='u1', display_name='Jane')
        # Pydantic's frozen check intercepts ``view.id = 'x'`` —
        # ``object.__setattr__`` bypasses it. Python's data model
        # offers no defense; documented as a known limitation.
        object.__setattr__(view, 'id', 'mutated')
        self.assertEqual(view.id, 'mutated')


# ===========================================================================
# KNOWN-LIMITATIONS CATALOG
# ===========================================================================


class TestKnownLimitationsCatalog(unittest.TestCase):
    """The bypass families above are documented limitations of
    Pydantic's allowlist guarantees. This test exists so the catalog
    is itself locked — a reviewer can grep for the limitation names
    and see them enumerated in one place. Adding a new known
    limitation requires updating both the catalog and the bypass
    tests above.
    """

    _KNOWN_LIMITATIONS = frozenset({
        'subclass_overrides_model_config_dropping_extra_forbid',
        'subclass_overrides_model_config_dropping_frozen',
        'computed_field_exposes_data_outside_allowlist',
        'any_typed_field_smuggles_arbitrary_content',
        'object_setattr_circumvents_frozen',
    })

    def test_catalog_is_locked(self):
        self.assertEqual(len(self._KNOWN_LIMITATIONS), 5)


if __name__ == '__main__':
    unittest.main()
