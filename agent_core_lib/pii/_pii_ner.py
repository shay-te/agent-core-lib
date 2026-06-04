"""NER-based PII detection — names / organisations / locations.

Powered by spaCy. The library is an *optional* extra (not in
``requirements.txt``) because the English model adds ~12MB and most
chat-tool flows don't need free-text name detection. Callers that
do want it install via ``pip install 'agent-core-lib[ner]'`` (the
extra is wired in ``setup.py``) and call :func:`find_ner_pii`.

If spaCy isn't installed, :func:`find_ner_pii` raises
:class:`SpacyNotInstalledError` at first call — the import is lazy so
the dependency is only required when the function is actually used.
"""
from __future__ import annotations

from typing import List

from agent_core_lib.pii.pii_patterns import PIIPatternFinding


class SpacyNotInstalledError(RuntimeError):
    """spaCy / its English model isn't available in this environment.

    Install with ``pip install spacy`` and download the model:
    ``python -m spacy download en_core_web_sm``.
    """


# Cache the loaded model — spaCy load is ~1-3 seconds and the model
# is read-only after that, so one process-wide instance is fine.
_LOADED_NLP = None

# Map spaCy entity labels → our pattern names. Only the entity types
# that are clearly PII are exposed; we deliberately drop ``DATE`` /
# ``TIME`` / ``CARDINAL`` / ``ORDINAL`` / ``PERCENT`` / ``MONEY`` /
# ``QUANTITY`` because those carry no identity signal on their own
# (a date is only PII when it's a DOB — covered by ``dob_strict`` —
# and money / percent / etc. are not PII at all).
_ENTITY_TO_PATTERN = {
    'PERSON': 'person_name',
    'ORG': 'organization_name',
    'GPE': 'location',   # countries, cities, states
    'LOC': 'location',   # non-GPE places (mountain ranges, water bodies)
    'NORP': 'demographic_group',  # nationalities, religions, political groups
}


def _redact(matched_text: str) -> str:
    prefix_len = min(4, len(matched_text))
    return f'{matched_text[:prefix_len]}…[REDACTED, len={len(matched_text)}]'


def _load_spacy_model():
    """Lazy spaCy + ``en_core_web_sm`` loader.

    Raises :class:`SpacyNotInstalledError` if either piece is missing.
    """
    global _LOADED_NLP
    if _LOADED_NLP is not None:
        return _LOADED_NLP
    try:
        import spacy
    except ImportError as exc:
        raise SpacyNotInstalledError(
            'spaCy is not installed. Install with `pip install spacy`.'
        ) from exc
    try:
        _LOADED_NLP = spacy.load('en_core_web_sm')
    except OSError as exc:
        raise SpacyNotInstalledError(
            "spaCy model 'en_core_web_sm' is not downloaded. Run "
            "`python -m spacy download en_core_web_sm`."
        ) from exc
    return _LOADED_NLP


def find_ner_pii(text: str) -> List[PIIPatternFinding]:
    """Return every NER-detected PII entity in ``text``.

    Maps spaCy's entity labels to our pattern names:
    ``PERSON`` → ``person_name``, ``ORG`` → ``organization_name``,
    ``GPE`` / ``LOC`` → ``location``, ``NORP`` → ``demographic_group``.

    Findings carry the per-entity ``pattern_name``.
    """
    if not text or not isinstance(text, str):
        return []
    nlp = _load_spacy_model()
    doc = nlp(text)
    findings: List[PIIPatternFinding] = []
    for entity in doc.ents:
        pattern_name = _ENTITY_TO_PATTERN.get(entity.label_)
        if pattern_name is None:
            continue
        findings.append(PIIPatternFinding(
            pattern_name=pattern_name,
            redacted_preview=_redact(entity.text),
        ))
    return findings
