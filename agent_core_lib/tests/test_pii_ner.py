"""Tests for :func:`agent_core_lib.pii._pii_ner.find_ner_pii`.

NER is the only PII path that requires a heavy optional dep (spaCy +
``en_core_web_sm``). The tests below skip cleanly when the model
isn't available so a contributor without spaCy installed can still
run the rest of the suite.
"""
from __future__ import annotations

import unittest

from agent_core_lib.pii._pii_ner import (
    SpacyNotInstalledError,
    find_ner_pii,
)


def _spacy_model_available():
    """Return True iff spaCy + ``en_core_web_sm`` are both importable."""
    try:
        import spacy
    except ImportError:
        return False
    try:
        spacy.load('en_core_web_sm')
    except OSError:
        return False
    return True


_SPACY_AVAILABLE = _spacy_model_available()


@unittest.skipUnless(
    _SPACY_AVAILABLE,
    'spaCy + en_core_web_sm not installed in this environment',
)
class TestNerDetector(unittest.TestCase):
    def test_person_name_match(self):
        findings = find_ner_pii('Jane Smith joined the team')
        names = [f.pattern_name for f in findings]
        self.assertIn('person_name', names)

    def test_organization_match(self):
        findings = find_ner_pii('Acme Corp acquired the startup')
        names = [f.pattern_name for f in findings]
        self.assertIn('organization_name', names)

    def test_location_match(self):
        findings = find_ner_pii('she moved to Berlin last week')
        names = [f.pattern_name for f in findings]
        self.assertIn('location', names)

    def test_demographic_group_match(self):
        findings = find_ner_pii('an American citizen filed today')
        names = [f.pattern_name for f in findings]
        self.assertIn('demographic_group', names)

    def test_empty_text_returns_empty(self):
        self.assertEqual(find_ner_pii(''), [])
        self.assertEqual(find_ner_pii(None), [])  # type: ignore[arg-type]

    def test_clean_text_returns_no_findings(self):
        findings = find_ner_pii('the result was processed quickly')
        # No proper nouns → no entities → no findings.
        self.assertEqual(findings, [])

    def test_redacted_preview_never_carries_full_value(self):
        findings = find_ner_pii('Jane Smith joined the team')
        person_findings = [f for f in findings if f.pattern_name == 'person_name']
        self.assertGreaterEqual(len(person_findings), 1)
        self.assertNotIn('Jane Smith', person_findings[0].redacted_preview)
        self.assertIn('REDACTED', person_findings[0].redacted_preview)


class TestNerLoaderFailurePaths(unittest.TestCase):
    """The two failure branches in ``_load_spacy_model`` — ``ImportError``
    on ``import spacy`` and ``OSError`` on ``spacy.load(...)``. We
    exercise them via ``mock.patch`` so the suite runs whether or not
    spaCy is actually installed."""

    def setUp(self):
        # Reset the module-level cache so the loader re-runs.
        import agent_core_lib.pii._pii_ner as ner_module
        ner_module._LOADED_NLP = None

    def test_missing_spacy_raises_clear_error(self):
        import builtins
        import agent_core_lib.pii._pii_ner as ner_module
        real_import = builtins.__import__

        def patched_import(name, *args, **kwargs):
            if name == 'spacy':
                raise ImportError('simulated missing spacy')
            return real_import(name, *args, **kwargs)

        with unittest.mock.patch('builtins.__import__', side_effect=patched_import):
            with self.assertRaises(SpacyNotInstalledError):
                ner_module._load_spacy_model()

    def test_missing_model_raises_clear_error(self):
        import agent_core_lib.pii._pii_ner as ner_module
        try:
            import spacy
        except ImportError:
            self.skipTest('spaCy not installed; load-path test is N/A')
        with unittest.mock.patch.object(
            spacy, 'load', side_effect=OSError('simulated missing model'),
        ):
            with self.assertRaises(SpacyNotInstalledError):
                ner_module._load_spacy_model()


# Import ``unittest.mock`` here (kept off the top so the regular tests
# don't pay an import cost they don't need).
import unittest.mock  # noqa: E402


if __name__ == '__main__':
    unittest.main()
