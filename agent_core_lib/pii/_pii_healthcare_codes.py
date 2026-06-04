"""Healthcare code patterns — CLIA / NDC drug code / ICD-10 diagnosis.

These are *identifiers*, not narrative diagnoses; NER for narrative
medical conditions lives in ``_pii_ner.py`` (spaCy-backed).
"""
from __future__ import annotations

import re


PATTERNS = (
    # CLIA — Clinical Laboratory Improvement Amendments number.
    # 2 digits (state) + ``D`` + 7 alphanumeric. Keyword-anchored.
    ('clia', re.compile(
        r'\bCLIA\s*[:=]?\s*\d{2}D[A-Z0-9]{7}\b',
        re.IGNORECASE,
    )),
    # NDC drug code — XXXX-XXXX-XX, XXXXX-XXX-XX, or XXXXX-XXXX-X.
    # Keyword anchor ``NDC`` to avoid order-id collision.
    ('ndc_drug_code', re.compile(
        r'\bNDC\s*[:=]?\s*'
        r'(?:\d{4}-\d{4}-\d{2}|\d{5}-\d{3}-\d{2}|\d{5}-\d{4}-\d)\b',
        re.IGNORECASE,
    )),
    # ICD-10-CM diagnosis code — 1 letter + 2 digits + optional
    # ``.<1-4 alphanumerics>``. Keyword anchor.
    ('icd10_code', re.compile(
        r'\bICD-?10\s*[:=]?\s*[A-Z]\d{2}(?:\.[A-Z0-9]{1,4})?\b',
        re.IGNORECASE,
    )),
)
