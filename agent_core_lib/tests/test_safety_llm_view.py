"""Tests for :class:`agent_core_lib.safety.llm_view.LLMView`.

The Pydantic-backed concrete view. ``ConfigDict(extra='forbid',
frozen=True)`` is what makes the declared field list a real allowlist.
Three layers of coverage:

1. The two ConfigDict flags are set on the base.
2. ``extra='forbid'`` raises ``pydantic.ValidationError`` on unknown
   init kwargs; ``frozen=True`` raises on post-init mutation.
3. The ``project`` / ``project_list`` helpers behave as documented.

The transport-layer marker (no Pydantic) is tested separately in
``llm-core-lib/llm_core_lib/tests/test_safety_llm_view.py``. The
adversarial Pydantic-bypass probes live in
``agent_core_lib/tests/test_safety_adversarial.py`` next to this file.
"""
from __future__ import annotations

import unittest

from pydantic import ValidationError

from agent_core_lib.safety.llm_view import LLMView
from llm_core_lib.safety.llm_view import LLMView as TransportLLMView


class _UserLLMView(LLMView):
    id: str
    display_name: str


class _OrderLLMView(LLMView):
    id: str
    total_cents: int


class TestLLMViewIsTransportSubclass(unittest.TestCase):
    """The concrete view MUST inherit from the transport marker so the
    gate's ``isinstance(item, TransportLLMView)`` check passes."""

    def test_concrete_is_subclass_of_transport_marker(self):
        self.assertTrue(issubclass(LLMView, TransportLLMView))

    def test_concrete_instance_passes_transport_isinstance(self):
        view = _UserLLMView(id='u1', display_name='Jane')
        self.assertIsInstance(view, TransportLLMView)


class TestLLMViewConfigDictContract(unittest.TestCase):
    """Lock the two flags that make the allowlist real."""

    def test_extra_is_forbid(self):
        self.assertEqual(LLMView.model_config.get('extra'), 'forbid')

    def test_frozen_is_true(self):
        self.assertTrue(LLMView.model_config.get('frozen'))


class TestLLMViewRejectsUnknownFields(unittest.TestCase):
    def test_unknown_init_kwarg_raises_validation_error(self):
        with self.assertRaises(ValidationError):
            _UserLLMView(id='u1', display_name='Jane', email='jane@example.com')

    def test_post_init_assignment_raises_validation_error(self):
        view = _UserLLMView(id='u1', display_name='Jane')
        with self.assertRaises(ValidationError):
            view.display_name = 'somebody else'


class TestLLMViewProject(unittest.TestCase):
    def test_drops_keys_not_on_allowlist(self):
        raw = {'id': 'u1', 'display_name': 'Jane', 'email': 'jane@example.com'}
        view = _UserLLMView.project(raw)
        self.assertEqual(view.model_dump(), {'id': 'u1', 'display_name': 'Jane'})

    def test_none_input_returns_none(self):
        self.assertIsNone(_UserLLMView.project(None))

    def test_missing_allowlisted_key_raises(self):
        with self.assertRaises(ValidationError):
            _UserLLMView.project({'id': 'u1'})

    def test_attribute_shaped_input_is_supported(self):
        class _Row(object):
            id = 'u1'
            display_name = 'Jane'
            email = 'jane@example.com'  # not on the allowlist

        view = _UserLLMView.project(_Row())
        self.assertEqual(view.model_dump(), {'id': 'u1', 'display_name': 'Jane'})


class TestLLMViewProjectList(unittest.TestCase):
    def test_empty_or_none_returns_empty_list(self):
        self.assertEqual(_UserLLMView.project_list(None), [])
        self.assertEqual(_UserLLMView.project_list([]), [])

    def test_each_item_is_projected(self):
        raws = [
            {'id': 'u1', 'display_name': 'Jane', 'email': 'jane@example.com'},
            {'id': 'u2', 'display_name': 'John', 'phone': '+1 555 1234'},
        ]
        views = _UserLLMView.project_list(raws)
        self.assertEqual(len(views), 2)
        self.assertEqual(views[0].model_dump(), {'id': 'u1', 'display_name': 'Jane'})
        self.assertEqual(views[1].model_dump(), {'id': 'u2', 'display_name': 'John'})

    def test_single_item_input_is_promoted_to_list(self):
        views = _UserLLMView.project_list({'id': 'u1', 'display_name': 'Jane'})
        self.assertEqual(len(views), 1)

    def test_none_items_inside_list_are_skipped(self):
        views = _UserLLMView.project_list([
            {'id': 'u1', 'display_name': 'Jane'},
            None,
            {'id': 'u2', 'display_name': 'John'},
        ])
        self.assertEqual(len(views), 2)


if __name__ == '__main__':
    unittest.main()
