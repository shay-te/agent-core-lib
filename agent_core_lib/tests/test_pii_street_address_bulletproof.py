"""Bulletproof corpus for the address regex family.

Per UNA-2727 review: the product CARRIES an address field, so the
regex needs to be smart. Five regex families ship in
``pii_patterns.py`` (see prior-art note + the ``--- address ---``
block):

  * ``street_address_with_city`` — full US line
    (``100 Main St, Springfield, IL 12345``).
  * ``street_address_with_unit`` — apt/suite/# modifiers.
  * ``street_address`` — original numbered-street US shape.
  * ``street_address_intl`` — European number-trails-street order
    (German Straße, French Rue, Italian Via, Spanish Calle, …).
  * ``po_box``.

Test inputs borrowed from:

  * scrubadub_address / pyap test fixtures (US, CA, UK).
  * faker.providers.address.en_US (``faker.Faker().address()``-style
    outputs) for synthetic US addresses.
  * CommonRegex2's address pattern test set.
  * Real-world German / French / Italian / Spanish postal samples.

Per the workspace-wide "one TestCase per file" rule (see
``architecture.md`` and the matching note in each project's
``AGENTS.md``), this file owns exactly one TestCase. Each
sub-test covers a different family so a regex regression points at
exactly which family broke.
"""
from __future__ import annotations

import unittest

from agent_core_lib.pii.pii_patterns import find_pii_patterns
from agent_core_lib.pii.pii_scrub import find_pii_in_payload


_ANY_ADDRESS_PATTERN_NAMES = frozenset({
    'street_address_with_city',
    'street_address_with_unit',
    'street_address',
    'street_address_intl',
    'po_box',
})


def _any_address_fired(text: str) -> bool:
    return any(
        f.pattern_name in _ANY_ADDRESS_PATTERN_NAMES
        for f in find_pii_patterns(text)
    )


def _any_address_fired_in(payload) -> bool:
    return any(
        f.pattern_name in _ANY_ADDRESS_PATTERN_NAMES
        for f in find_pii_in_payload(payload)
    )


# ---- US numbered-street form (the original shape) -----------------------
_US_NUMBERED_POSITIVES = (
    '742 Evergreen Terrace',
    '1234 Main St',
    '1 Infinite Loop',
    '350 5th Ave',
    '4059 Mt Lee Dr',
    '1600 Pennsylvania Avenue',
    '1 Microsoft Way',
    '10 Downing Street',
    '221B Baker Street',  # the B is on the number
    '500 W 41st St',
    # narrative
    'ship to 1234 Main St please',
    'pickup from 350 5th Ave',
    # multiple separators
    "5300 Mt Hood Hwy",
    "100 N. Main Street",
    "100 East Main Road",
)


# ---- US with unit modifier ----------------------------------------------
_US_WITH_UNIT_POSITIVES = (
    '100 Main St Apt 5',
    '100 Main Street Apartment 5',
    '100 Main St Suite 200',
    '100 Main Street Ste. 200',
    '100 Main St Unit 12',
    '100 Main Street #5',
    '100 Main St, Apt 5',
    '100 Main St, Suite 200',
    '100 Main St, Unit 12',
    '100 Main St, # 12',
    '500 W 41st St Apt 3B',
    # apt-before-street
    'Apt 5, 100 Main St',
    'Suite 200, 100 Main Street',
    # Rm / Floor variants
    '100 Main St Rm 5',
    '100 Main St Floor 3',
    '100 Main St Room 12A',
    # narrative
    'ship to 100 Main St Apt 5 please',
    'address: 500 W 41st St Suite 200',
)


# ---- US full line with city ---------------------------------------------
_US_WITH_CITY_POSITIVES = (
    '100 Main St, Springfield, IL 12345',
    '742 Evergreen Terrace, Springfield, IL',
    '1 Infinite Loop, Cupertino, CA 95014',
    '1600 Pennsylvania Avenue, Washington, DC 20500',
    '1 Microsoft Way, Redmond, WA 98052',
    '350 5th Ave, New York, NY 10118',
    # zip+4
    '100 Main St, Springfield, IL 12345-6789',
    # without state, just city
    '100 Main Street, Springfield',
)


# ---- International (Europe — number trails street) ----------------------
_INTL_POSITIVES = (
    # German Straße / Strasse
    'Hauptstraße 12',
    'Bahnhofstrasse 5',
    'Friedrichstraße 100',
    # German -allee / -platz / -weg / -gasse / -ring / -damm
    'Lindenallee 4',
    'Marktplatz 7',
    'Mühlweg 23',
    'Holzgasse 14',
    'Mittlerer Ring 99',
    'Kurfürstendamm 200',
    # Romance Rue / Via / Calle / etc.
    'Rue de la Paix 5',
    'Via Roma 10',
    'Calle Mayor 23',
    'Avenida de la Constitución 42',
    'Plaza Mayor 1',
    'Piazza San Marco 1',
    'Largo Argentina 10',
    'Corso Vittorio Emanuele 100',
    # narrative
    'Lieferadresse: Hauptstraße 12 in Berlin',
    'adresse: Rue de la Paix 5 à Paris',
)


# ---- PO Box ---------------------------------------------------------------
_PO_BOX_POSITIVES = (
    'P.O. Box 1234',
    'PO Box 1234',
    'P. O. Box 1234',
    'p.o. box 1234',
    'POBox 1234',  # also matches — dots and spaces between P, O, Box are optional
    # narrative
    'mail to P.O. Box 1234 today',
    'use PO Box 999 for billing',
)


# ---- Negatives (no address) ---------------------------------------------
_NEGATIVES = (
    # bare year
    '2024',
    # bare phone
    '555-1234',
    # bare email
    'jane@example.com',
    # plain narrative
    'we shipped 100 packages today',
    # number without street suffix
    'I have 5 cats and 3 dogs',
    # version string
    'v1.2.3',
    # time
    'meeting at 12:34',
    # plain currency
    '$100.00',
)


_JSON_PAYLOADS = (
    {'address': '100 Main St, Springfield, IL 12345'},
    {'shipping': {'street': '742 Evergreen Terrace'}},
    {'billing': {'address_line_1': '100 Main St Apt 5'}},
    [{'order': 1, 'address': '1 Infinite Loop, Cupertino, CA'}],
    {'profile': {'addresses': ['Hauptstraße 12', 'Rue de la Paix 5']}},
    {'note': 'ship to 100 Main St Apt 5 by Friday'},
    {'po_box': 'P.O. Box 1234'},
    {'comment': 'returned to sender at 100 Main St Suite 200'},
    {'tags': ['urgent', '100 Main St, Springfield, IL']},
    {'nested': {'deep': {'addr': 'Bahnhofstrasse 5'}}},
)


# ---- verbatim third-party corpora ---------------------------------------
# scrubadub's address fixtures use UK shapes whose "suffix" words
# (``views``, ``branch``, ``keys``, ``mall``, ``stravenue``, ``overpass``)
# aren't in our suffix list — so the street pattern misses them. But
# they all carry a UK postcode that we DO match, so as a PII-scrub
# outcome (something gets redacted) they're caught. Locked both ways
# so a regex change in either direction is visible.

# scrubadub: tests/test_filth_address.py.
_ADDR_SCRUBADUB_FIXTURES_NON_ENGLISH_SUFFIX = (
    '4 Paula views\nLake Howardburgh\nN7U 2FQ',
    '79 Miller branch\nJordantown\nW1F 3LB',
    '78 Joseph keys\nEast Patricktown\nEN6 2SD',
    '93 Hall overpass\nNashbury\nTA2W 9XP',
    'Flat 98R\nNatasha fall\nLake Rosie\nB73 8PJ',
    '8 Roberts stravenue\nElliottville\nSY18 2YP',
    '784 Knowles mall\nJunetown\nIM20 2PG',
)

# CommonRegex: test.py — street_addresses sub-corpus.
_ADDR_COMMONREGEX_STREET_POSITIVES = (
    'checkout the new place at 101 main st.',
    '504 parkwood drive',
    '3 elm boulevard',
    '500 elm street ',
)

# CommonRegex po_boxes + zip_codes sub-corpus.
_ADDR_COMMONREGEX_POBOX_POSITIVES = (
    'PO Box 123456',
    'hey p.o. box 234234 hey',
)


class TestStreetAddressBulletproofCorpus(unittest.TestCase):
    """Address detection across all five regex families — comprehensive
    bulletproof corpus per the UNA-2727 reviewer's "we must be bullet-
    proof" bar."""

    def test_us_numbered_street_corpus(self):
        failures = [
            text for text in _US_NUMBERED_POSITIVES
            if not _any_address_fired(text)
        ]
        self.assertEqual(failures, [], f'US numbered street missed: {failures}')

    def test_us_with_unit_corpus(self):
        failures = [
            text for text in _US_WITH_UNIT_POSITIVES
            if not _any_address_fired(text)
        ]
        self.assertEqual(failures, [], f'US with unit missed: {failures}')

    def test_us_with_city_corpus(self):
        failures = [
            text for text in _US_WITH_CITY_POSITIVES
            if not _any_address_fired(text)
        ]
        self.assertEqual(failures, [], f'US with city missed: {failures}')

    def test_intl_european_corpus(self):
        failures = [
            text for text in _INTL_POSITIVES
            if not _any_address_fired(text)
        ]
        self.assertEqual(
            failures, [],
            f'international (number-trails-street) missed: {failures}',
        )

    def test_po_box_corpus(self):
        failures = [
            text for text in _PO_BOX_POSITIVES
            if not _any_address_fired(text)
        ]
        self.assertEqual(failures, [], f'PO box missed: {failures}')

    def test_negative_corpus(self):
        failures = [
            text for text in _NEGATIVES
            if _any_address_fired(text)
        ]
        self.assertEqual(failures, [], f'false-positive: {failures}')

    def test_scrubadub_addresses_caught_via_postcode_not_street(self):
        # The street-suffix mismatch is real but our UK postcode
        # pattern still catches the embedded postcode, so the practical
        # outcome (something redacts) is preserved. Lock both shapes:
        # we assert postcode fires AND street_address doesn't.
        street_fires = []
        postcode_misses = []
        for text in _ADDR_SCRUBADUB_FIXTURES_NON_ENGLISH_SUFFIX:
            names = {f.pattern_name for f in find_pii_patterns(text)}
            if names & _ANY_ADDRESS_PATTERN_NAMES:
                street_fires.append(text)
            if 'uk_postcode' not in names:
                postcode_misses.append(text)
        self.assertEqual(
            street_fires, [],
            f'street regex started matching scrubadub fixtures — was a '
            f'non-English suffix (views/branch/keys/mall/stravenue) '
            f'added? {street_fires}',
        )
        self.assertEqual(
            postcode_misses, [],
            f'UK postcode no longer firing on scrubadub fixtures — the '
            f'postcode regex regressed: {postcode_misses}',
        )

    def test_commonregex_street_corpus(self):
        failures = [
            text for text in _ADDR_COMMONREGEX_STREET_POSITIVES
            if not _any_address_fired(text)
        ]
        self.assertEqual(failures, [], f'CommonRegex street missed: {failures}')

    def test_commonregex_pobox_corpus(self):
        failures = [
            text for text in _ADDR_COMMONREGEX_POBOX_POSITIVES
            if not _any_address_fired(text)
        ]
        self.assertEqual(failures, [], f'CommonRegex po_box missed: {failures}')

    def test_address_in_json_payload(self):
        failures = [
            payload for payload in _JSON_PAYLOADS
            if not _any_address_fired_in(payload)
        ]
        self.assertEqual(failures, [], f'missed in JSON: {failures}')


if __name__ == '__main__':
    unittest.main()
