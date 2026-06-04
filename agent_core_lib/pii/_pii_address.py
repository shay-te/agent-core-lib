"""Street-address / PO-box patterns.

Aggregated into the public ``_PII_PATTERNS`` tuple by
:mod:`agent_core_lib.pii.pii_patterns`. Declaration
order matters (overlap resolver in the scrubber picks the
first-declared span on a tie); the order inside this file
feeds the aggregator in the same sequence.
"""
from __future__ import annotations

import re


PATTERNS = (
    # --- address ------------------------------------------------------
    # Five regex families cover the address-shape space we care about
    # (per UNA-2727 review: the product DOES carry an address field, so
    # the regex needs to be smarter — multiple patterns are explicitly
    # OK). Order matters: more specific patterns first so the scrubber's
    # overlap resolver keeps the longest / most-informative span.
    #
    # 1. ``street_address_with_city`` — the canonical US "full line":
    #    ``100 Main St, Springfield, IL 12345``. Catches anything that
    #    looks like number + street + suffix + (comma|whitespace) +
    #    city + (state|country) + optional zip. Borrowed shape from
    #    Presidio's address recognizer test corpus.
    ('street_address_with_city', re.compile(
        r'\b\d{1,6}[A-Za-z]?\s+(?:[A-Za-z0-9.\-\']+\s+){0,5}'
        r'(?:Street|St|Avenue|Ave|Boulevard|Blvd|Road|Rd|Lane|Ln|'
        r'Drive|Dr|Court|Ct|Place|Pl|Way|Parkway|Pkwy|Terrace|Ter|'
        r'Circle|Cir|Square|Sq|Trail|Trl|Highway|Hwy|Loop|Path|Walk|'
        r'Crescent|Cres|Mews|Row|Close)\b\.?'
        r'[,\s]+[A-Z][A-Za-z\.\-\' ]{1,40}'
        r'(?:[,\s]+(?:[A-Z]{2}|[A-Z][a-z]+))?'
        r'(?:[,\s]+\d{4,5}(?:-\d{4})?)?',
        re.IGNORECASE,
    )),
    # 2. ``street_address_with_unit`` — apartment / suite / unit / #
    #    modifier between the number and the street, or trailing the
    #    suffix. Examples: ``100 Main St Apt 5``,
    #    ``100 Main St Suite 200``, ``100 Main St #5``,
    #    ``Apt 5 100 Main St``. Borrowed from CommonRegex2's modifier
    #    list (Apt|Apartment|Suite|Ste|Unit|Rm|Room|Floor|Fl|#).
    ('street_address_with_unit', re.compile(
        r'\b(?:'
        r'\d{1,6}\s+(?:[A-Za-z0-9.\-\']+\s+){0,5}'
        r'(?:Street|St|Avenue|Ave|Boulevard|Blvd|Road|Rd|Lane|Ln|'
        r'Drive|Dr|Court|Ct|Place|Pl|Way|Parkway|Pkwy|Terrace|Ter|'
        r'Circle|Cir|Square|Sq|Trail|Trl|Highway|Hwy|Loop|Path|Walk|'
        r'Crescent|Cres|Mews|Row|Close)\b\.?'
        r'[,\s]+(?:Apt|Apartment|Suite|Ste|Unit|Rm|Room|Floor|Fl|#)\.?\s*[A-Za-z0-9\-]+'
        r'|'
        r'(?:Apt|Apartment|Suite|Ste|Unit|Rm|Room|Floor|Fl|#)\.?\s*[A-Za-z0-9\-]+'
        r'[,\s]+\d{1,6}\s+(?:[A-Za-z0-9.\-\']+\s+){0,5}'
        r'(?:Street|St|Avenue|Ave|Boulevard|Blvd|Road|Rd|Lane|Ln|'
        r'Drive|Dr|Court|Ct|Place|Pl|Way|Parkway|Pkwy|Terrace|Ter|'
        r'Circle|Cir|Square|Sq|Trail|Trl|Highway|Hwy|Loop|Path|Walk|'
        r'Crescent|Cres|Mews|Row|Close)\b\.?'
        r')',
        re.IGNORECASE,
    )),
    # 3. ``street_address`` — the original US shape: number + words +
    #    common suffix. Kept for backwards compatibility with the
    #    existing test corpus and as the fallback when neither
    #    the city-line nor the unit-modifier shape is present.
    ('street_address', re.compile(
        r'\b\d{1,6}[A-Za-z]?\s+(?:[A-Za-z0-9.\-\']+\s+){0,5}'
        r'(?:Street|St|Avenue|Ave|Boulevard|Blvd|Road|Rd|Lane|Ln|'
        r'Drive|Dr|Court|Ct|Place|Pl|Way|Parkway|Pkwy|Terrace|Ter|'
        r'Circle|Cir|Square|Sq|Trail|Trl|Highway|Hwy|Loop|Path|Walk|'
        r'Crescent|Cres|Mews|Row|Close)\b\.?',
        re.IGNORECASE,
    )),
    # 4. ``street_address_intl`` — European number-trails-street order:
    #    ``Hauptstraße 12``, ``Rue de la Paix 5``, ``Via Roma 10``,
    #    ``Calle Mayor 23``. The suffix is implicit in the street-name
    #    prefix (-straße / Rue / Via / Calle / Avenida / Plaza /
    #    Piazza), so we anchor on those keywords rather than a
    #    trailing English suffix. Unicode-aware (``ß`` is in the
    #    character class).
    ('street_address_intl', re.compile(
        r'\b(?:'
        # German: Straße / Strasse / Allee / Platz / Weg / Gasse / Ring.
        # Two shapes — compound single-word (``Hauptstraße``) and
        # multi-word (``Mittlerer Ring``, ``Unter den Linden``). The
        # multi-word arm allows up to 3 capitalized words before the
        # standalone suffix keyword.
        r'(?:'
        r'[A-ZÄÖÜ][A-Za-zÄÖÜäöüß\-]*?'
        r'(?:stra(?:ß|ss)e|allee|platz|weg|gasse|ring|damm)'
        r'|'
        r'(?:[A-ZÄÖÜ][A-Za-zÄÖÜäöüß\-]+\s+){1,3}'
        r'(?:Straße|Strasse|Allee|Platz|Weg|Gasse|Ring|Damm|Ufer)'
        r')'
        r'|'
        # Romance: Rue / Via / Calle / Avenida / Plaza / Piazza / Avenue (FR)
        # followed by street-name words then number.
        r'(?:Rue|Via|Calle|Avenida|Avinguda|Plaza|Plaça|Piazza|Largo|Corso|Viale)'
        r'(?:\s+(?:de|du|del|de\s+la|della|delle|dei|degli|d[\'’]))?'
        r'(?:\s+[A-Za-zÀ-ÿ\-\'’]+){1,5}'
        r')'
        r'\s+\d{1,5}[A-Za-z]?\b',
        re.UNICODE,
    )),
    # 5. ``po_box`` — kept as-is.
    ('po_box', re.compile(r'\bP\.?\s*O\.?\s*Box\s+\d+\b', re.IGNORECASE)),

)
