"""Tests for :mod:`agent_core_lib.safety.ref_llm_view`.

``RefLLMView`` is the single id-only contract the LLM ever sees. Lock
the five behaviors that make it a real safety boundary:

1. Construction + ``model_dump`` round-trip — the wire shape is
   exactly ``{'id': N}`` (no smuggled fields).
2. ``extra='forbid'`` blocks unknown init kwargs — the allowlist is
   real.
3. ``frozen=True`` blocks post-init mutation — a malicious caller
   can't slip a field in after the gate accepted the view.
4. ``project`` / ``project_list`` filter to the declared allowlist —
   the upstream dict's display / PII fields are silently dropped.
5. ``build_ref`` / ``build_refs`` / ``merge_refs`` produce the
   wire-stable ``{type, id}`` shape with deduping, so the persistence
   layer's ``refs`` index is consistent across tool callsites.

Per the workspace-wide "one TestCase per file" guideline this file
groups the related cases under a small number of TestCase classes
that each lock one behavior.
"""
from __future__ import annotations

import unittest

from pydantic import ValidationError

from agent_core_lib.safety.ref_llm_view import (
    RefLLMView,
    RefType,
    build_ref,
    build_refs,
    merge_refs,
)


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


class TestBuildRefHelpers(unittest.TestCase):
    """The ``refs`` index the persistence layer emits is keyed
    ``(type, id)``; these helpers make every callsite produce the
    same shape so the render path's hydration batch can deduplicate."""

    def test_build_ref_returns_canonical_wire_shape(self):
        self.assertEqual(
            build_ref(RefType.USER, 10), {'type': 'user', 'id': 10},
        )

    def test_build_refs_dedupes_preserving_first_seen_order(self):
        self.assertEqual(
            build_refs(RefType.USER, [10, 10, 20]),
            [{'type': 'user', 'id': 10}, {'type': 'user', 'id': 20}],
        )

    def test_build_refs_drops_none_entries(self):
        self.assertEqual(
            build_refs(RefType.USER, [10, None, 20]),
            [{'type': 'user', 'id': 10}, {'type': 'user', 'id': 20}],
        )

    def test_merge_refs_dedupes_by_type_id_pair(self):
        merged = merge_refs(
            [{'type': 'user', 'id': 10}],
            [{'type': 'user', 'id': 10}, {'type': 'task', 'id': 5}],
        )
        self.assertEqual(
            merged,
            [{'type': 'user', 'id': 10}, {'type': 'task', 'id': 5}],
        )

    def test_merge_refs_handles_none_lists(self):
        self.assertEqual(merge_refs(None, [{'type': 'user', 'id': 1}]),
                         [{'type': 'user', 'id': 1}])


if __name__ == '__main__':
    unittest.main()
