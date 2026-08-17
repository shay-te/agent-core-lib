"""Tests for :mod:`agent_core_lib.safety.ref_llm_view`.

``RefLLMView`` is the single id-only contract the LLM ever sees. Lock:

1. ``model_dump`` is exactly ``{'id': N}`` (no smuggled fields).
2. ``extra='forbid'`` blocks unknown init kwargs.
3. ``frozen=True`` blocks post-init mutation.
4. ``project`` / ``project_list`` filter to the declared allowlist.
5. ``build_refs`` produces the wire-stable ``{type, id}`` shape with
   deduping so the persistence layer's ``refs`` index stays consistent.
"""
from __future__ import annotations

import unittest

from pydantic import ValidationError

from agent_core_lib.safety.ref_llm_view import RefLLMView, build_refs


_FAKE_TYPE_A = 101


class TestRefLLMViewWireShape(unittest.TestCase):
    """The exact bytes the gate dumps to the LLM."""

    def test_model_dump_is_id_only(self):
        self.assertEqual(RefLLMView(id=1).model_dump(), {'id': 1})

    def test_rejects_extra_field(self):
        with self.assertRaises(ValidationError):
            RefLLMView(id=1, extra='X')

    def test_frozen_blocks_post_init_mutation(self):
        view = RefLLMView(id=1)
        with self.assertRaises(ValidationError):
            view.id = 999


class TestRefLLMViewProjection(unittest.TestCase):
    """The ``project`` / ``project_list`` adapters filter upstream
    rows to the declared allowlist — every display / PII field on the
    input is silently dropped."""

    def test_project_filters_to_allowlist(self):
        view = RefLLMView.project({
            'id': 1,
            'display_name': 'Jane',
            'email': 'jane@example.com',
        })
        self.assertEqual(view.model_dump(), {'id': 1})

    def test_project_none_returns_none(self):
        self.assertIsNone(RefLLMView.project(None))

    def test_project_list_filters_nones(self):
        out = RefLLMView.project_list([
            {'id': 1, 'display_name': 'A'},
            None,
            {'id': 2, 'email': 'b@x.com'},
        ])
        self.assertEqual([v.model_dump() for v in out], [{'id': 1}, {'id': 2}])


class TestBuildRefsHelper(unittest.TestCase):
    """The ``refs`` index emitted by the persistence layer is keyed
    ``(type, id)``; this helper makes every callsite produce the same
    shape so the render path's hydration batch can deduplicate."""

    def test_dedupes_preserving_first_seen_order(self):
        self.assertEqual(
            build_refs(_FAKE_TYPE_A, [10, 10, 20]),
            [{'type': _FAKE_TYPE_A, 'id': 10},
             {'type': _FAKE_TYPE_A, 'id': 20}],
        )

    def test_drops_none_entries(self):
        self.assertEqual(
            build_refs(_FAKE_TYPE_A, [10, None, 20]),
            [{'type': _FAKE_TYPE_A, 'id': 10},
             {'type': _FAKE_TYPE_A, 'id': 20}],
        )

    def test_accepts_enum_like_with_value(self):
        # Consumer-defined IntEnums expose ``.value`` — coerced
        # transparently so callers can stay typed.
        import enum

        class _Consumer(int, enum.Enum):
            X = 7

        self.assertEqual(
            build_refs(_Consumer.X, [42]),
            [{'type': 7, 'id': 42}],
        )


if __name__ == '__main__':
    unittest.main()
