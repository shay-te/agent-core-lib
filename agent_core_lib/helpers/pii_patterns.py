"""PII pattern detector — single source of truth for the workspace.

Parallel to ``credential_patterns`` (credential_patterns hunts
vendor-issued secrets; this module hunts personal data). Every
PII-scanning helper across the workspace — ``helpers/pii_scan`` for
text streams, ``helpers/pii_scrub`` for structured payloads, the chat
service's tool-result sanitizer in ``ob-love-admin-backend`` — pulls
its pattern set from here. There is no second copy in
``llm-core-lib``; the structural defense over there (``LLMView``,
``to_llm_payload``) enforces *types*, while regex-level PII detection
lives here.

The set is deliberately broad — false positives are acceptable (the
runtime scrubber and the audit-log helper both tolerate them; the test
suite uses :class:`PIIDetectedError` to lock the contract); false
negatives are not. When in doubt, add a pattern. The named families
below are an attempt at "don't forget a single thing":

  * **Contact** — email, phone (US + international E.164-ish), URL
    (URLs routinely carry PII in path/query), social-media handles
    (Twitter/Mastodon ``@handle``, labelled Skype).
  * **Government IDs (US)** — SSN, ITIN, EIN, passport, driver's
    license, Medicare beneficiary id.
  * **Government IDs (intl)** — UK / CA / AU / ES / DE passport, UK NI
    number, UK UTR (tax reference), Canadian SIN, Australian TFN,
    German Steueridentifikationsnummer, Indian Aadhaar, Indian PAN,
    Brazilian CPF, Brazilian CNPJ, Spanish NIF / NIE, Singapore
    FIN/NRIC, Polish PESEL (keyword-anchored), UK NHS
    (keyword-anchored), Australian Medicare (space-grouped form),
    Indian GSTIN, Italian Codice Fiscale, Indian Voter ID, Swedish
    personnummer / organisationsnummer (shared dashed format),
    Finnish personal identity code, US NPI (keyword), Australian
    ABN / ACN (keyword), Singapore UEN (keyword), Thai TNIN
    (keyword), Turkish national ID (keyword).
  * **Financial** — credit card (13–19 digits), CVV-in-context,
    IBAN, SWIFT/BIC, US routing number, US bank account, bitcoin
    address.
  * **Postal** — US ZIP, US ZIP+4, UK postcode, CA postcode, NL
    postcode.
  * **Network / device** — IPv4, IPv6, MAC address.
  * **Session / token** — JWT (the ``eyJ`` three-part shape).
  * **Geolocation** — GPS coordinate pairs (lat/lon with at least
    four decimal places of precision — bounded by valid lat/lon
    ranges so plain comma-separated numbers don't false-positive).
  * **Vehicle** — VIN, US license plate.
  * **Address** — US street-address shape (number + street + suffix);
    best-effort, regex can't catch every postal shape so the
    *primary* address defense is the typed-view allowlist in
    ``llm-core-lib`` (``LLMView`` subclasses simply don't declare an
    address field unless the value has already been scrubbed).
  * **Temporal** — date-of-birth shapes (ISO, US, EU).

Address detection is intentionally regex-supported even though the
allowlist is the real defense — the reviewer's note "make it
extensive, don't forget a single thing" trumps the regex-purity
argument; a noisy street-address pattern that flags
``742 Evergreen Terrace`` is a net win over silently missing it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable, List, Tuple


@dataclass(frozen=True)
class PIIPatternFinding(object):
    """One match of a named PII pattern; the full matched value is never returned."""

    pattern_name: str
    redacted_preview: str


# ---------------------------------------------------------------------------
# Prior-art note — open-source PII detection landscape (2025 survey)
# ---------------------------------------------------------------------------
#
# Before extending this file (especially before adding a new dependency for
# PII), read this. We deliberately kept the implementation as a hand-rolled
# regex set + structured scrubber rather than depending on a third-party
# library. Below is what we evaluated and what's worth borrowing.
#
# Projects surveyed (all permissive licenses, all Python):
#
#   * Microsoft Presidio (github.com/microsoft/presidio, MIT, ~4.5k stars,
#     actively maintained). Hybrid regex + NER (spaCy by default), pluggable
#     ``RecognizerRegistry``, context-word boosting, confidence scoring,
#     anonymizer "operators" (replace / mask / hash / encrypt / redact),
#     checksum validators (Luhn / IBAN mod-97 / ABA). Heavy: spaCy + language
#     model balloons install to ~500MB-1.5GB and cold-start is ~1-3s. Wrong
#     tradeoff for a per-tool-call boundary — the gate must be cheap.
#   * scrubadub — https://github.com/LeapBeyond/scrubadub  (Apache 2.0,
#     ~1.9k stars, **EFFECTIVELY UNMAINTAINED — last release 2022, open
#     issues + PRs sitting**). Do NOT take this as a runtime dependency;
#     even if we wanted to, the project is parked. But the design and
#     several of its built-in detectors are worth borrowing — see the
#     "borrow from scrubadub" subsection below for the specific list of
#     things it catches that we currently miss.
#   * CommonRegex (github.com/madisonmay/CommonRegex, MIT, ~1.7k stars,
#     unmaintained since 2021). Pure-regex grab-bag. Not a library to
#     adopt — mine its US-street-address and time-of-day patterns to
#     cross-check ours.
#   * pii-codex (github.com/EdyVision/pii-codex, BSD-3, ~150 stars). Thin
#     wrapper over Presidio that adds a PII taxonomy / severity tiering
#     layer (financial / health / government-ID / contact). Inherits
#     Presidio's weight; not worth adopting, but the tiering idea is.
#   * datafog (MIT, ~250 stars, newer). Presidio-style hybrid, lighter,
#     async-friendly — too small a community to bet on yet.
#   * Protect AI's pii-detection-anonymizer (transformer-based, DeBERTa).
#     Higher recall on names / locations, but a transformer in the inline
#     scrub path is the wrong place — too heavy.
#
# Borrow from scrubadub — concrete detector + design gaps
# ---------------------------------------------------------
#
# Scrubadub is unmaintained but its 2022-era detector set still covers
# things our regex tuple does NOT. Each item below is a real
# false-negative class we could close as a follow-up; the source-of-truth
# for the underlying patterns is scrubadub's ``scrubadub/detectors/``
# directory at the URL above.
#
# Detector-level gaps (things scrubadub flags that we miss today):
#
#   * **URLs** — scrubadub's ``UrlDetector``. **ADOPTED in this PR** as
#     pattern ``url`` (``https?://[^\s<>"']+``). URLs routinely carry
#     PII in path/query (``/user/123/email/jane@example.com``,
#     ``?reset_token=...``) and the overlap resolver in
#     ``pii_scrub._scrub_string`` keeps the URL span when an email is
#     embedded, since ``url`` is declared before ``email``.
#   * **Social-media handles** — scrubadub has ``TwitterDetector`` and
#     ``SkypeDetector``. **ADOPTED in this PR** as ``twitter_handle``
#     (with a negative lookbehind so it never clips email hosts) and
#     ``skype_handle`` (keyword-anchored on ``skype`` to avoid
#     false-positives on random identifiers). ``instagram_handle`` /
#     ``mastodon_handle`` follow the same shape if added later — the
#     same negative lookbehind protects them from the email collision.
#   * **Login/password credential pairs** — scrubadub's
#     ``CredentialDetector`` finds ``username: foo, password: bar``
#     shapes. Not adopted yet. Adjacent to our existing
#     credential-pattern set in ``credential_patterns.py``; lives
#     better as an extension there than in PII (it's secret material,
#     not PII proper). Follow-up.
#   * **``phonenumbers``-backed phone validation** — scrubadub's
#     ``PhoneDetector`` uses Google's ``phonenumbers`` library and
#     parses + validates international shapes properly. Our
#     ``phone`` regex is loose (matches many false positives — order
#     ids, timestamps). Not adopted in this PR because it adds a
#     dependency; the two-stage "regex matches → ``phonenumbers``
#     validates" pass would kill the false-positive class with one
#     thin dep (``phonenumbers`` is small and pure-Python). Follow-up
#     if the false-positive rate from ``phone`` becomes a real problem.
#   * **Date-of-birth without trigger word** — scrubadub's
#     ``DateOfBirthDetector`` uses ``dateparser`` to recognize many
#     date formats and only flags them when context (recent past +
#     plausible age range) suggests a birthday. Ours requires the
#     literal ``dob``/``date of birth``/``born`` keyword; we miss bare
#     dates that are clearly DOBs by context. Same two-stage pattern:
#     regex matches → ``dateparser`` confirms + age plausibility.
#     Not adopted yet (also a dep). Follow-up.
#   * **Per-US-state driver's license formats** — scrubadub's
#     ``DriversLicenceDetector`` carries per-state formats (e.g., CA
#     is 1 letter + 7 digits; NY is 9 digits; FL has its own shape).
#     Our single broad ``us_drivers_license`` pattern false-positives
#     on any 8 digits and false-negatives on states with letters
#     in non-leading positions. Not adopted yet — a per-state table
#     is significantly bigger than the four quick wins in this PR.
#     Follow-up.
#   * **UK tax reference (UTR)** — scrubadub's ``TaxReferenceNumberDetector``.
#     **ADOPTED in this PR** as ``uk_utr`` (10 digits, optional ``K``
#     suffix, keyword-anchored on ``UTR`` because the bare shape
#     collides with too many ids/timestamps).
#   * **Names via lightweight NER** — scrubadub ships a
#     ``NameDetector`` that uses TextBlob (smaller than spaCy, faster
#     cold-start). Names cannot be regex'd. Not adopted — NER doesn't
#     belong in this layer regardless of the choice of library. If we
#     ever need name detection without taking on Presidio, TextBlob
#     is the cheaper option to evaluate first.
#   * **Real international address parsing** — scrubadub ships a
#     separate ``scrubadub_address`` package (also Apache 2.0, also
#     stale) that wraps ``pyap`` (a libpostal port). Catches USPS /
#     CA / UK address shapes our regex misses (anything without a
#     "Street/Ave/Blvd"-style suffix, anything with the street
#     number trailing — much of Europe / Latin America). Not adopted
#     because libpostal is a C dependency and pyap inherits its
#     install pain; addresses also remain best-handled at the
#     allowlist layer (``LLMView`` simply doesn't carry an address
#     field) so the gap is small in practice. Worth knowing the
#     library exists if we ever need to scrub address-shaped strings
#     out of free-text comments at scale.
#   * **Known-term redaction (``KnownFilthItem``)** — scrubadub lets
#     callers register a known list of strings (customer names, org
#     names, internal codename project ids) for case-/whitespace-
#     tolerant exact-match redaction. We don't have an equivalent
#     today; the closest is the structural defense (those names just
#     don't end up as fields on an ``LLMView``). Worth borrowing the
#     *shape* the day we need to redact known-string lists in
#     free-text — a per-tenant set of strings + a fast normalize-
#     and-compare pass would slot in next to ``_PII_PATTERNS`` as a
#     parallel detector family.
#
# Design-level patterns from scrubadub that complement Presidio's:
#
#   * **Typed ``Filth`` records** — already in our roadmap below
#     (item 3 of "Recommendation"). Scrubadub's shape:
#     ``Filth(beg, end, type, locale, detector_name, replacement_string)``.
#   * **``PostProcessor`` chain** — composable pass after detection:
#     scrubadub ships ``FilthReplacer`` (apply replacement strings)
#     and ``PrefixSuffixReplacer`` (wrap markers in ``{{ }}``). Our
#     ``_scrub_string`` is monolithic; lifting it into a postprocessor
#     chain would let us add per-tier policies (item 4 below) as
#     plug-in stages.
#   * **Per-type replacement strategy** — each ``Filth`` subclass
#     declares its own ``salt`` + ``hash`` policy. Ours uses one
#     placeholder format for everything (``[redacted:<name>]``).
#     Per-type would let us hash credit cards (so an admin can
#     correlate across log lines without seeing the number) while
#     fully redacting SSNs.
#   * **Locale awareness (``en_US``, ``en_GB``)** — switchable rule
#     sets per locale. Today our set is implicitly US-centric (zip
#     vs. postcode, ABA vs. sort code). A locale dimension would let
#     us tighten patterns per-region without bloating the global tuple.
#
# Note on scrubadub stale-ness: even though the design and patterns
# above are still valuable references, the project's PyPI release
# pins old versions of ``phonenumbers``, ``textblob``, and ``nltk``,
# which conflicts with current downstream stacks. Don't ``pip install
# scrubadub`` — read the source on GitHub and re-implement the
# patterns we want against current versions of any deps we adopt.
#
# Recommendation — keep the hand-rolled approach, borrow four techniques
# as small follow-up improvements (not blocking this PR):
#
#   1. **Checksum validators behind the patterns that have them** —
#      Luhn for credit cards, mod-97 for IBAN, ABA routing checksum, VIN
#      check digit, SSN area-number exclusions. Kills the bulk of regex
#      false positives at near-zero runtime cost. Presidio does this; the
#      pattern is "regex matches, then a validator function on the match
#      group decides keep/drop". Easy to bolt on per-pattern here without
#      restructuring the tuple.
#   2. **Context-word boosting / confidence scoring** — a 9-digit match
#      near "SSN", "social", "tax id" is high-confidence; isolated, it's
#      borderline. Today every match fires equally; a confidence score per
#      finding would let the choke point distinguish "definitely PII"
#      (assert/raise) from "probably PII" (scrub-and-log). Presidio's idea.
#   3. **scrubadub's ``Filth`` typed-detector shape** — each detector
#      yields ``(span, type, confidence, detector_name)``. Our scrubber
#      already collects spans for non-overlapping replacement (see
#      ``_scrub_string`` in pii_scrub.py); promoting that to a typed
#      ``Filth`` record would let the resolver use confidence in addition
#      to (start, length) when picking among overlapping matches.
#   4. **pii-codex severity tiers** — tag each pattern family with a
#      category (``government_id``, ``financial``, ``contact``, ``network``,
#      ``address``, ``temporal``) so the payload gate can apply different
#      policies per tier (e.g., never log a ``government_id`` match even
#      in DEBUG; allow ``contact`` matches in admin-confirming views like
#      ``LLMSendEmailResultView``). Conceptual change to the tuple shape,
#      not regex changes.
#
# Re-evaluate Presidio specifically if/when we need NER for free-text
# names / orgs / locations — those simply can't be regex'd and Presidio
# is the mature answer. Run it out-of-process if we go there, so the
# spaCy load cost doesn't sit on every chat tool call.
#
# Deeper scan — Microsoft Presidio recognizer code (2025 re-survey)
# ---------------------------------------------------------------------
#
# Presidio is the most mature project in the space; we don't depend on
# it but its recognizers (``presidio-analyzer/presidio_analyzer/predefined_recognizers/``)
# are the closest thing to a workspace-shared canonical set. Things we
# adopted from a deeper read of their code:
#
#   * **CreditCardRecognizer** — they validate Luhn checksum AFTER regex
#     match. Their regex is ``\b(?:\d[ -]*?){13,16}\b`` (very similar to
#     ours; ``[ -]*?`` is slightly more permissive than our ``[ -]?``).
#     Borrowed for the ``credit_card_bulletproof`` test corpus:
#     Visa 16-digit ``4111-1111-1111-1111``, Mastercard 16
#     ``5500 0000 0000 0004``, Amex 15 ``3400 0000 0000 009``,
#     Discover ``6011 0000 0000 0004``, JCB ``3528 0000 0000 0007``,
#     Diners 14 ``3000 000000 0004``. Luhn validation is the right
#     follow-up (item 1 of "Recommendation").
#   * **UsSsnRecognizer** — Presidio rejects SSN area numbers ``000``,
#     ``666``, ``900-999`` (those are never issued) AND group ``00`` AND
#     serial ``0000``. Borrowed for the negative corpus in
#     ``test_ssn_bulletproof``. Our pattern doesn't yet exclude
#     these; documented as a checksum-validator follow-up.
#   * **UsBankRecognizer** — uses context words (``account``, ``routing``,
#     ``ABA``) at distance ≤ 5 tokens. We hard-anchor (``\b(?:account|acct)``
#     directly preceding) which is stricter but misses
#     ``"the account number 12345678"`` (extra word between).
#     Borrowed: 9-digit ABA checksum (3×first + 7×second + first
#     digits — sum mod 10 == 0). Follow-up.
#   * **IbanRecognizer** — checks mod-97 == 1 over the rearranged digit
#     representation. We use a shape-only regex; their full
#     country-prefix table is the canonical reference. Borrowed: real
#     IBAN test vectors (`GB82 WEST 1234 5698 7654 32`,
#     `DE89 3704 0044 0532 0130 00`, `FR1420041010050500013M02606`,
#     `NL91ABNA0417164300`) for ``test_iban_bulletproof``.
#   * **EmailRecognizer** — RFC 5322 dialect close to ours; the test
#     corpus in ``tests/test_recognizers/test_email_recognizer.py``
#     includes hard cases we borrowed: ``"name+tag@sub.example.co.uk"``,
#     ``"j.doe@example-host.com"``, ``"user_123@e.x.a.m.p.l.e.com"``.
#     Also the negative cases: ``"@example.com"`` (no local),
#     ``"user@"`` (no host), ``"user@.com"`` (empty subdomain).
#   * **PhoneRecognizer** — wraps Google's ``phonenumbers`` library; the
#     positive corpus borrowed for ``test_phone_bulletproof`` covers:
#     US ``+1 (212) 555-1234``, UK ``+44 7700 900123``,
#     DE ``+49 30 12345678``, FR ``+33 1 23 45 67 89``,
#     IN ``+91 98765 43210``, JP ``+81 3-1234-5678``.
#   * **UrlRecognizer** — Presidio uses TLDExtract to validate the
#     domain has a known suffix; we use a simpler shape regex. The
#     positive corpus for ``test_url_bulletproof`` borrowed from their
#     tests includes query-string PII (``?reset_token=...``,
#     ``?email=jane@example.com``), unicode TLDs (``example.中国``),
#     and IDN domains (``xn--bcher-kva.example``).
#   * **DomainRecognizer** — flags bare domains like ``example.com``
#     without a scheme. We don't have this today; would be a real
#     false-negative class for tool-result text that quotes URLs
#     without ``http://``. Follow-up — would need a confidence-tier
#     mechanism so we don't redact every ``foo.bar`` mention.
#
# Additional libraries surveyed in this round
# ---------------------------------------------------------
#
#   * **commonregex2** (github.com/brianwhitman/commonregex2, MIT,
#     unmaintained). Fork of CommonRegex with a tighter US address
#     regex that handles ``apt`` / ``suite`` / ``#`` modifiers
#     inline. Borrowed the modifier handling for our expanded
#     ``street_address_with_unit`` pattern.
#   * **scrubadub_address** (separate package) — already documented
#     above. Per the operator's note: "our product DOES have an
#     address field" — so we need address regex parity now, not just
#     the allowlist defense. This PR adds three additional address
#     patterns (see below) to close the most common gaps:
#     ``street_address_with_unit`` (apt/suite/unit modifiers),
#     ``street_address_intl`` (European number-trails-street order:
#     ``Hauptstraße 12``, ``Rue de la Paix 5``), and
#     ``street_address_with_city`` (``100 Main St, Springfield, IL
#     12345`` — the canonical US line-after-the-street shape).
#   * **datafog** (github.com/datafog/datafog-python, MIT, ~250 stars).
#     Newer, lighter; uses spaCy small-model + regex. Their regex
#     set is a superset of Presidio's. No new patterns we don't
#     already have.
#   * **faker** (github.com/joke2k/faker, MIT, ~17k stars). Not a
#     detector — a *generator*. We mine it for adversarial test
#     inputs: ``faker.Faker().address()`` produces realistic
#     synthetic addresses across locales that probe our regex.
#     Several test inputs in ``test_street_address_bulletproof``
#     are faker-style outputs.
#   * **piiranha** (github.com/iliashmaster/piiranha) — abandoned
#     prototype, no useful test corpus. Skipped.
#   * **opnsource/redact-pii** (Node.js, MIT) — different language
#     but their test fixtures include real-world chat transcripts
#     with mixed PII; the *shape* of those fixtures (one input,
#     multiple expected PII types) informed our
#     ``test_*_in_json_payload`` shape.
#
# Bottom line: writing our own regex set is still the right call for
# the inline gate (Presidio's NER is too heavy; scrubadub is dead;
# datafog is too young). But every checksum validator Presidio runs is
# a follow-up we should land — credit_card Luhn, IBAN mod-97, ABA
# routing checksum, VIN check digit, SSN area-number exclusions —
# because they kill the bulk of regex false positives at near-zero
# cost. Tracked in the "Recommendation" section above.
#
# Expansion pass — closing the per-country and session-token gaps
# ---------------------------------------------------------------------
#
# The reviewer's follow-up ("make sure we support all the unsupported
# data") drove a second pass that closes the documented gaps that DON'T
# need a new dependency. Adopted in this expansion:
#
#   * **Canadian SIN** (``ca_sin``) — 3-3-3 hyphenated; distinguished
#     from US SSN (3-2-4) and phone (3-3-4) by digit grouping alone, so
#     no keyword anchor.
#   * **Australian TFN** (``au_tfn``) — keyword-anchored on ``TFN``
#     (the bare 8-9 digit shape is too noisy).
#   * **German Steuer-ID** (``de_steuer_id``) — keyword-anchored on
#     ``Steuer-ID`` / ``Steueridentifikationsnummer`` (the bare 11
#     digits collide with phone numbers and order ids).
#   * **Indian Aadhaar** (``in_aadhaar``) — 12 digits in 4-4-4 grouping;
#     distinctive enough to flag without a keyword.
#   * **Indian PAN** (``in_pan``) — ``AAAAA9999A`` layout; unique.
#   * **Brazilian CPF / CNPJ** (``br_cpf`` / ``br_cnpj``) — distinctive
#     printed forms ``000.000.000-00`` and ``00.000.000/0000-00``.
#   * **Netherlands postcode** (``nl_postcode``) — ``1011 AB`` shape;
#     the digit-then-letter ordering is unusual enough that no keyword
#     anchor is needed.
#   * **JWT** (``jwt``) — three base64url segments joined by dots, with
#     the distinctive ``eyJ`` prefix (base64 of ``{"`` from the JSON
#     header). Tokens carry user id / email / tenant / roles in the
#     payload segment, so they're PII-shape from the model's
#     perspective even though they're technically credential material.
#   * **GPS coordinates** (``gps_coordinates``) — lat/lon decimal pairs
#     with ≥4 decimal places of precision, bounded to valid ranges
#     ([-90, 90] lat, [-180, 180] lon). Required precision filters out
#     integer-pair noise (``10, 20`` etc. aren't useful locations).
#     The product carries geo data for matchmaking distance —
#     mandatory coverage, not optional.
#
# Second wave — close the remaining standalone ``_PRESIDIO_*_UNSUPPORTED``
# lockdowns. Each one had its own test method asserting the type-name
# didn't fire; the closeable ones below are now flipped to positive
# assertions against the original Presidio corpora:
#
#   * **es_passport** — 3 letters + 6 digits; case-insensitive because
#     Presidio's corpus includes lowercase and mixed-case forms.
#   * **es_nif** — 7-8 digits + optional dash + check letter. Trailing
#     letter is what distinguishes it from generic account numbers.
#   * **de_passport** — restricted letter prefix
#     (``C F G H J K L M N P R T V W X Y Z``) + 8 alphanumeric. Covers
#     DE ID card too (same BSI format, same regex). The restricted
#     letter set is what keeps this from over-matching every 9-char
#     alphanumeric.
#   * **sg_fin** — prefix letter from ``S T F G M`` + 7 digits + check
#     letter. The restricted prefix is the keep-out for false
#     positives.
#   * **pl_pesel** — 11 digits, keyword-anchored on ``PESEL`` (bare
#     11-digit shape over-matches with phone / de_steuer_id / other
#     11-digit IDs).
#   * **uk_nhs** — 10 digits in 3-3-4 grouping, keyword-anchored on
#     ``NHS`` (the bare 3-3-4 shape is structurally identical to a
#     US/CA phone; phone still flags it so coverage isn't lost).
#   * **au_medicare** — 10 digits in 4-5-1 grouping (space-grouped
#     only); the 4-5-1 layout is distinctive enough not to need a
#     keyword. Bare-digit Medicare is intentionally NOT matched —
#     Presidio uses a checksum validator for that case (a follow-up).
#
# Third wave — close everything realistic from the catalog block
# (the ``_UNSUPPORTED_TYPE_CORPORA`` map in
# ``tests/test_pii_third_party_corpora.py``). The reviewer asked
# ("what ever can go out of the unsupported. let's put a dedicated
# test for it with many challenging test data") for maximum coverage.
# Adopted in this wave:
#
#   * **in_gstin** — 15 chars, fully deterministic layout
#     (``\d{2}[A-Z]{5}\d{4}[A-Z]\d[A-Z]\d``). No anchor needed.
#   * **it_fiscal_code** — 16 chars, fully deterministic layout
#     (``[A-Z]{6}\d{2}[A-Z]\d{2}[A-Z]\d{3}[A-Z]``). No anchor.
#   * **es_nie** — ``[XYZ]\d{7,8}-?[A-Z]``. Distinct from NIF (digits
#     first) and from passport (3 letters first).
#   * **se_personnummer** — ``\d{6,8}[-+]\d{4}``. Single regex closes
#     both the personnummer (``871220-2384``) and the
#     organisationsnummer (``556703-7485``) catalog entries; the two
#     share the dashed format and Presidio distinguishes them via
#     checksum, which we don't have. Bare-digit forms are
#     intentionally not matched.
#   * **in_voter** — ``[A-Z]{3}\d{7}``. The 3-letter prefix is what
#     keeps this from colliding with ``us_drivers_license`` (1 letter
#     + 7 digits).
#   * **fi_personal_identity_code** — ``\d{6}[-+A]\d{3}[A-Z0-9]``.
#     Distinctive enough not to need an anchor.
#   * **us_npi / au_abn / au_acn / sg_uen / th_tnin / tr_national_id**
#     — keyword-anchored because the underlying digit/letter shape
#     is too generic to flag without a label (each would otherwise
#     collide with phones / order ids / other national IDs).
#   * **Widened de_passport** to case-insensitive — Presidio's
#     ``de_id_card`` corpus includes lowercase forms.
#   * **Widened de_steuer_id** to also accept ``IdNr.`` as a
#     keyword alias — closes the
#     ``_UNSUPPORTED_TYPE_CORPORA['de_tax_id']`` catalog entry.
#
# After this wave the remaining catalog entries are only:
#
#   * **it_drivers_license / in_vehicle / tr_license_plate** — varied
#     per-region formats; the regex would be a wide union with too
#     many false positives.
#   * **uk_drivers_license** — 16-char alphanumeric with embedded
#     surname + DOB; high false-positive risk without the embedded-
#     DOB validator Presidio uses.
#
# Plus the "next-step follow-up" items below that need a new
# dependency or a confidence-tier mechanism.
#
# Still deferred (require a new dependency, a much larger table, or a
# confidence-tier mechanism):
#
#   * **Per-US-state DL formats** — table of ~50 per-state regexes.
#   * **UK driving license** — 16-char alphanumeric with embedded
#     surname + DOB; same checksum-driven recognizer Presidio uses.
#     High false-positive risk without the embedded-DOB validator.
#   * **Bare-domain detector** (Presidio's ``DomainRecognizer``) —
#     needs a confidence tier; today every match fires equally and a
#     bare ``foo.bar`` mention would generate noise.
#   * **Date-of-birth without keyword** — needs ``dateparser`` to filter
#     date-shaped strings down to plausibly-DOB ones.
#   * **``phonenumbers``-backed phone validation** — adds a small dep
#     but kills most of ``phone``'s false positives.
#   * **NER-driven name / org / location detection** — Presidio or
#     TextBlob; out of regex scope.
#   * **Real international address parsing** — libpostal / pyap; C dep.
#   * **Known-term redaction** (per-tenant string lists) — out of
#     regex scope; the structural defense covers this today.
#   * **Long-tail national IDs catalogued in
#     ``_UNSUPPORTED_TYPE_CORPORA``** (au_abn, au_acn, in_voter,
#     in_gstin, in_vehicle, es_nie, de_id_card,
#     it_fiscal_code, it_drivers_license, se_personnummer,
#     se_organisationsnummer, sg_uen, th_tnin, tr_*, fi_*, ph_*).
#     Adoption is a per-pattern judgment call (some are 1-letter
#     prefix + digits, some need checksum validators, some have
#     keyword-only realistic context). Each has been left in the
#     documented gap catalog so the next expansion has a punch list.
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Checksum validators — second-pass filters that reject shape-valid but
# arithmetically-impossible matches.
#
# Closes the "Recommendation item 1" follow-up in the prior-art block
# above: kill regex false positives at near-zero runtime cost by gating
# each match on the standard checksum the issuer publishes. Pattern
# names that appear in :data:`_PATTERN_VALIDATORS` are run through the
# matching validator after the regex fires; matches that fail are
# dropped from the finding list.
#
# Every validator is pure stdlib and short by design — the long-form
# upstream rules live in Presidio / the issuer specs; what we capture
# here is the minimum check that flips an over-match into a clean miss.
# ---------------------------------------------------------------------------


def _luhn_valid(match_text: str) -> bool:
    """Luhn-checksum validator for credit-card-shaped strings.

    Strips space and dash separators, then computes the standard
    mod-10 check (double every second digit from the right, add the
    digit sums, sum mod 10 == 0). The bare-shape regex fires on every
    13-19 digit sequence; this filter drops the ones whose check
    digit doesn't match what the issuer would have stamped.
    """
    digits = ''.join(ch for ch in match_text if ch.isdigit())
    if not 13 <= len(digits) <= 19:
        return False
    total = 0
    for index, char in enumerate(reversed(digits)):
        digit_value = int(char)
        if index % 2 == 1:
            digit_value *= 2
            if digit_value > 9:
                digit_value -= 9
        total += digit_value
    return total % 10 == 0


def _ssn_area_group_serial_valid(match_text: str) -> bool:
    """Reject SSN area/group/serial values the SSA never issues.

    Mirrors Presidio's ``UsSsnRecognizer`` reservation rules:
      * area number ``000`` is never issued
      * area number ``666`` is never issued
      * area numbers ``900-999`` are reserved for the ITIN range
      * group number ``00`` is never issued
      * serial number ``0000`` is never issued
    Lifts the shape-only regex up to a real SSN check at the cost of
    one tuple unpack.
    """
    digits_only = match_text.replace('-', '')
    if len(digits_only) != 9:
        return False
    area = digits_only[:3]
    group = digits_only[3:5]
    serial = digits_only[5:]
    if area in ('000', '666'):
        return False
    if area[0] == '9':
        return False
    if group == '00':
        return False
    if serial == '0000':
        return False
    return True


def _iban_mod97_valid(match_text: str) -> bool:
    """Mod-97 checksum validator for IBANs (ISO 13616).

    The published algorithm: move the four leading chars to the end,
    map each letter to its A=10..Z=35 number, interpret the resulting
    digit string as an integer, return ``integer % 97 == 1``. Catches
    every transposition and check-digit error the regex shape alone
    can't see.
    """
    compact = match_text.replace(' ', '').replace('-', '').upper()
    if len(compact) < 15:
        return False
    rearranged = compact[4:] + compact[:4]
    numeric_chars = []
    for char in rearranged:
        if char.isdigit():
            numeric_chars.append(char)
        elif 'A' <= char <= 'Z':
            numeric_chars.append(str(ord(char) - 55))
        else:
            return False
    return int(''.join(numeric_chars)) % 97 == 1


def _aba_routing_checksum_valid(match_text: str) -> bool:
    """ABA routing-number checksum (Federal Reserve published rule).

    9-digit weighted sum: ``3,7,1,3,7,1,3,7,1`` × the digits, mod 10
    must be 0. The bare 9-digit regex collides with phone fragments,
    timestamps, and SSN-without-dashes; the checksum kills the vast
    majority of those.
    """
    digits = ''.join(ch for ch in match_text if ch.isdigit())
    if len(digits) != 9:
        return False
    weights = (3, 7, 1, 3, 7, 1, 3, 7, 1)
    total = sum(int(digit) * weight for digit, weight in zip(digits, weights))
    return total % 10 == 0


_VIN_CHAR_VALUES = {
    'A': 1, 'B': 2, 'C': 3, 'D': 4, 'E': 5, 'F': 6, 'G': 7, 'H': 8,
    'J': 1, 'K': 2, 'L': 3, 'M': 4, 'N': 5,
    'P': 7, 'R': 9,
    'S': 2, 'T': 3, 'U': 4, 'V': 5, 'W': 6, 'X': 7, 'Y': 8, 'Z': 9,
    **{str(digit): digit for digit in range(10)},
}
_VIN_POSITIONAL_WEIGHTS = (8, 7, 6, 5, 4, 3, 2, 10, 0, 9, 8, 7, 6, 5, 4, 3, 2)


def _vin_check_digit_valid(match_text: str) -> bool:
    """North-American VIN check-digit (NHTSA published rule, 49 CFR §565).

    Position 9 is a check digit computed as ``Σ value(char) × weight``
    mod 11. Result 10 is encoded as ``X``; anything else is a literal
    digit. Drops the shape-valid VINs that aren't real VINs (about
    10/11 of random 17-char strings that pass the shape regex).
    """
    candidate = match_text.upper()
    if len(candidate) != 17:
        return False
    weighted_sum = 0
    for position, char in enumerate(candidate):
        if char not in _VIN_CHAR_VALUES:
            return False
        weighted_sum += _VIN_CHAR_VALUES[char] * _VIN_POSITIONAL_WEIGHTS[position]
    check_remainder = weighted_sum % 11
    expected_check_char = 'X' if check_remainder == 10 else str(check_remainder)
    return candidate[8] == expected_check_char


def _il_id_check_digit_valid(match_text: str) -> bool:
    """Israeli teudat zehut check-digit validator.

    9-digit number where the last digit is a Luhn-like checksum:
    multiply each digit by 1, 2, 1, 2... left-to-right; if the
    product is >= 10, sum its digits; the total mod 10 must be 0.
    Padded shorter numbers (some legacy holders carry 7 or 8 digits)
    are left-padded with zeros before the algorithm runs.
    """
    digits_only = ''.join(ch for ch in match_text if ch.isdigit())
    if not 5 <= len(digits_only) <= 9:
        return False
    padded = digits_only.zfill(9)
    total = 0
    for index, char in enumerate(padded):
        digit_value = int(char)
        if index % 2 == 1:
            digit_value *= 2
            if digit_value > 9:
                digit_value -= 9
        total += digit_value
    return total % 10 == 0


_PII_PATTERNS: Tuple[Tuple[str, re.Pattern[str]], ...] = (
    # --- contact ------------------------------------------------------
    # URL — borrowed from scrubadub's ``UrlDetector`` (see prior-art note
    # above). High-value because URLs routinely carry PII in path /
    # query (``/user/123/email/jane@example.com``, ``?reset_token=...``).
    # Restricted to http/https schemes on purpose: mailto: would
    # double-match the email pattern below and provide no extra value
    # over the existing email finding. Declared BEFORE ``email`` so the
    # scrubber's overlap resolver (first-declared wins on equal-start
    # spans, longer wins via the sort key) keeps the URL span when an
    # email is embedded in a URL (``https://host/u/jane@example.com``).
    # URL scheme is case-insensitive per RFC 3986 §3.1; path/query stay
    # case-sensitive but the regex doesn't need to distinguish that —
    # ``re.IGNORECASE`` only affects ASCII letter matching in the
    # scheme prefix here.
    ('url', re.compile(r'https?://[^\s<>"\']+', re.IGNORECASE)),
    ('email', re.compile(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}')),
    # E.164-ish phone numbers: optional leading +, 10+ digits with
    # optional separators. Tighter than the previous form so a card
    # number doesn't double-match here.
    ('phone', re.compile(r'\+?\d[\d \-().]{8,}\d')),
    # Twitter / Mastodon-style handle — borrowed from scrubadub's
    # ``TwitterDetector``. Positive predecessor list (string start or
    # ascii whitespace / punctuation) — a *negative* lookbehind would
    # incorrectly treat invisible Unicode separators (U+200B etc.) as
    # "not an email char" and silently misclassify zero-width-split
    # obscured emails (``jane<U+200B>@example.com``) as Twitter handles.
    # See ``test_pii_adversarial.test_miss_email_with_zero_width_split``.
    ('twitter_handle', re.compile(
        r'(?:^|(?<=[ \t\n\r(\[,;:]))@[A-Za-z0-9_]{3,15}\b'
    )),
    # Skype handle — borrowed from scrubadub's ``SkypeDetector``. The
    # unlabelled form would collide with too many random identifiers,
    # so we anchor on the ``skype`` keyword (case-insensitive,
    # whitespace/colon separator).
    ('skype_handle', re.compile(
        r'\bskype[\s:]+[A-Za-z][A-Za-z0-9.\-_]{5,31}\b',
        re.IGNORECASE,
    )),
    # Instagram handle — keyword-anchored ``@name``. The ``@`` is
    # required (a keyword alone with narrative text — e.g.
    # ``instagram is great`` — is not a handle). Length cap 1-30
    # matches Instagram's username spec. Declared after ``twitter_handle``
    # so a keyword-less ``@name`` falls to the Twitter detector.
    ('instagram_handle', re.compile(
        r'\b(?:instagram|insta|ig)[\s:@]+@[A-Za-z0-9_.]{1,30}\b',
        re.IGNORECASE,
    )),
    # Mastodon handle — ``@user@instance.example`` (two ``@`` signs,
    # the second separating the local part from the federated host).
    # The shape is distinct enough from email that the per-pattern
    # collision resolver in ``pii_scrub`` keeps the right span; we
    # still declare it AFTER ``email`` so a bare ``user@host`` is
    # treated as email rather than partial Mastodon. The lookbehind
    # set includes ``"`` and ``'`` so the handle still matches when
    # the surrounding payload was JSON-serialized.
    ('mastodon_handle', re.compile(
        r'(?:^|(?<=[ \t\n\r(\[,;:"\']))'
        r'@[A-Za-z0-9_]{1,30}@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}'
    )),

    # --- US government IDs --------------------------------------------
    ('ssn', re.compile(r'\b\d{3}-\d{2}-\d{4}\b')),
    # ITIN: 9XX-7X-XXXX or 9XX-8X-XXXX (the 4th digit is 7 or 8).
    ('itin', re.compile(r'\b9\d{2}-[78]\d-\d{4}\b')),
    # EIN: XX-XXXXXXX
    ('ein', re.compile(r'\b\d{2}-\d{7}\b')),
    # US passport book: 9 digits (newer issues), with optional leading letter.
    ('us_passport', re.compile(r'\b[A-Z]?\d{9}\b')),
    # US driver's license — varies wildly by state; flag the common
    # "1 letter + 7 digits" shape (CA, FL, etc.) and the "8 digit"
    # shape used by several states.
    ('us_drivers_license', re.compile(r'\b[A-Z]\d{7}\b|\b\d{8}\b')),
    # Medicare Beneficiary Identifier (MBI), post-2018 format:
    # 1 numeric + 1 alpha + 1 alphanumeric + 1 numeric + 1 alpha +
    # 1 alphanumeric + 1 numeric + 2 alpha + 2 numeric.
    ('medicare_mbi', re.compile(
        r'\b[1-9][A-Z][A-Z\d][\d]-?[A-Z][A-Z\d][\d]-?[A-Z]{2}\d{2}\b'
    )),

    # --- international government IDs ---------------------------------
    # UK National Insurance number.
    ('uk_nino', re.compile(
        r'\b[A-CEGHJ-PR-TW-Z][A-CEGHJ-NPR-TW-Z]\d{6}[A-D]\b'
    )),
    # UK Unique Tax Reference — borrowed from scrubadub's
    # ``TaxReferenceNumberDetector``. 10 digits, optional ``K`` suffix.
    # Keyword-anchored (UTR) because a bare 10-digit number false-
    # positives on too many ids/timestamps; UTRs in real text are
    # almost always labelled.
    ('uk_utr', re.compile(r'\bUTR\s*[:=]?\s*\d{10}K?\b', re.IGNORECASE)),
    # UK passport: 9 digits.
    ('uk_passport', re.compile(r'\b\d{9}\b')),
    # Canadian passport: 2 letters + 6 digits.
    ('ca_passport', re.compile(r'\b[A-Z]{2}\d{6}\b')),
    # Australian passport: 1 letter + 7 digits.
    ('au_passport', re.compile(r'\b[A-Z]\d{7}\b')),
    # Spanish passport — 3 letters + 6 digits (``AAA123456``).
    # Case-insensitive because Presidio's corpus includes lowercase
    # and mixed-case forms; the shape is distinctive enough not to
    # need a keyword anchor.
    ('es_passport', re.compile(r'\b[A-Z]{3}\d{6}\b', re.IGNORECASE)),
    # German passport / ID card (same regex covers both — they share
    # the BSI format, so this single pattern closes both the
    # standalone ``_PRESIDIO_DE_PASSPORT_UNSUPPORTED`` lockdown and
    # the ``_UNSUPPORTED_TYPE_CORPORA['de_id_card']`` catalog entry).
    # Allowed letter set is ``C F G H J K L M N P R T V W X Y Z`` (no
    # A/B/D/E/I/O/Q/S/U). Length is 9, alphanumeric after the leading
    # letter. The restricted letter set is what keeps this from
    # over-matching generic 9-char alphanumerics. Case-insensitive
    # because Presidio's corpus includes lowercase forms
    # (``l01x00t44``).
    ('de_passport', re.compile(
        r'\b[CFGHJKLMNPRTVWXYZ][CFGHJKLMNPRTVWXYZ0-9]{8}\b',
        re.IGNORECASE,
    )),
    # Spanish NIF (Número de Identificación Fiscal) — 7 or 8 digits
    # followed by an optional dash and a check letter. The trailing
    # letter is what distinguishes it from a bare account number; the
    # 7-or-8 digit width covers both old-style (7) and new-style (8)
    # NIFs.
    ('es_nif', re.compile(r'\b\d{7,8}-?[A-Z]\b')),
    # Singapore FIN / NRIC — prefix letter from ``S T F G M`` + 7
    # digits + check letter (``S2740116C``). The restricted prefix
    # letter set is what keeps this from over-matching every
    # ``[A-Z]\d{7}[A-Z]`` ID (which would collide with several other
    # countries' formats).
    ('sg_fin', re.compile(r'\b[STFGM]\d{7}[A-Z]\b')),
    # Polish PESEL — 11 digits, keyword-anchored on ``PESEL``. The
    # bare 11-digit shape over-matches with phone numbers, German
    # tax IDs (``de_steuer_id``), and several other 11-digit
    # identifiers, so we only flag the keyword-labelled form. The
    # anchor accepts a short connector word (``is`` / ``no`` /
    # ``number``) between the keyword and the digits so prose forms
    # like ``My pesel is 44051401458`` match in addition to the
    # field-name form ``PESEL: 44051401458``.
    ('pl_pesel', re.compile(
        r'\bPESEL\b\s*(?:number|no|is)?\s*[:=#]?\s*\d{11}\b',
        re.IGNORECASE,
    )),
    # UK NHS number — 10 digits in 3-3-4 grouping. Keyword-anchored
    # on ``NHS`` because the bare 3-3-4 form is structurally
    # indistinguishable from a US/CA phone number with a leading area
    # code; the production-relevant case (an explicit NHS reference)
    # is what the anchor matches. The phone pattern still fires on
    # the bare form so coverage of the bare 3-3-4 shape isn't lost.
    # ``NHS`` is allowed to be followed by an optional word
    # (``number``/``no``) — the Presidio corpus and realistic prose
    # both use ``NHS number 401-023-2137`` and ``NHS 401-023-2137``.
    ('uk_nhs', re.compile(
        r'\bNHS\s*(?:number|no)?\s*[:#=]?\s*'
        r'\d{3}[\s\-]?\d{3}[\s\-]?\d{4}\b',
        re.IGNORECASE,
    )),
    # Australian Medicare — 10 digits in 4-5-1 grouping
    # (``2123 45670 1``). The space-grouped 4-5-1 layout is what
    # distinguishes Medicare from generic 10-digit phone/account
    # numbers; the bare-digit form is intentionally not matched
    # because it would over-match (Presidio's recognizer uses a
    # checksum validator for that case — a follow-up).
    ('au_medicare', re.compile(r'\b\d{4}\s\d{5}\s\d\b')),
    # Canadian SIN (Social Insurance Number) — 9 digits, canonical
    # printed form ``000-000-000``. The 3-3-3 grouping distinguishes it
    # from US SSN (3-2-4) and from US/Canadian phone (3-3-4), so the
    # bare hyphenated shape is safe to flag without a keyword anchor.
    ('ca_sin', re.compile(r'\b\d{3}-\d{3}-\d{3}\b')),
    # Australian TFN (Tax File Number) — 8 or 9 digits, usually
    # written as ``123 456 782``. Keyword-anchored because the bare
    # digit shape is too noisy.
    ('au_tfn', re.compile(
        r'\bTFN\s*[:=]?\s*\d{3}\s?\d{3}\s?\d{2,3}\b',
        re.IGNORECASE,
    )),
    # German Steueridentifikationsnummer — 11 digits, keyword-anchored
    # (``Steuer-ID`` / ``Steueridentifikationsnummer`` / ``IdNr.`` —
    # the third alias covers the ``IdNr. 98765432106`` form Presidio's
    # corpus uses, closing the ``_UNSUPPORTED_TYPE_CORPORA['de_tax_id']``
    # catalog entry). The 11-digit bare shape would otherwise collide
    # with phone numbers and order ids.
    ('de_steuer_id', re.compile(
        r'\b(?:Steuer-?ID|Steueridentifikationsnummer|IdNr\.?)\s*[:=]?\s*'
        r'\d{2}\s?\d{3}\s?\d{3}\s?\d{3}\b',
        re.IGNORECASE,
    )),
    # Indian Aadhaar — 12 digits, canonical printed form
    # ``1234 5678 9012`` (4-4-4 grouped). The 12-digit shape is
    # distinctive enough to flag without a keyword anchor.
    ('in_aadhaar', re.compile(r'\b\d{4}\s\d{4}\s\d{4}\b')),
    # Indian PAN (Permanent Account Number) — 5 letters + 4 digits +
    # 1 letter = 10 chars. Distinctive layout, no anchor needed.
    ('in_pan', re.compile(r'\b[A-Z]{5}\d{4}[A-Z]\b')),
    # Brazilian CPF (Cadastro de Pessoas Físicas) — canonical printed
    # form ``000.000.000-00`` (11 digits with 3-3-3-2 punctuation).
    ('br_cpf', re.compile(r'\b\d{3}\.\d{3}\.\d{3}-\d{2}\b')),
    # Brazilian CNPJ (Cadastro Nacional da Pessoa Jurídica) — printed
    # form ``00.000.000/0000-00`` (14 digits with 2-3-3-4-2 punctuation).
    ('br_cnpj', re.compile(r'\b\d{2}\.\d{3}\.\d{3}/\d{4}-\d{2}\b')),

    # --- catalog-block close-outs (third wave) ------------------------
    # The patterns below close every documented gap in
    # ``_UNSUPPORTED_TYPE_CORPORA`` whose shape is distinctive enough
    # to flag without a new dependency or a confidence-tier mechanism.
    # See the prior-art note above ("Third wave — catalog close-out")
    # for which catalog keys were closed vs. which stayed deferred.

    # Indian GSTIN — 15 chars in a unique layout:
    # 2 digits (state code) + 5 letters (PAN-style entity) + 4 digits
    # + 1 letter (entity number) + 1 digit/letter + ``Z`` + 1 alphanum.
    ('in_gstin', re.compile(
        r'\b\d{2}[A-Z]{5}\d{4}[A-Z]\d[A-Z]\d\b'
    )),
    # Italian Codice Fiscale — 16 chars, fully deterministic layout:
    # 6 letters (surname/name initials) + 2 digits (year) + 1 letter
    # (month) + 2 digits (day, gender-offset) + 1 letter + 3 digits +
    # check letter. Highly distinctive.
    ('it_fiscal_code', re.compile(
        r'\b[A-Z]{6}\d{2}[A-Z]\d{2}[A-Z]\d{3}[A-Z]\b'
    )),
    # Spanish NIE (Número de Identidad de Extranjero) — foreigner ID:
    # prefix letter from ``X Y Z`` + 7-8 digits + optional dash +
    # check letter. Distinct from NIF (which has digits first).
    ('es_nie', re.compile(r'\b[XYZ]\d{7,8}-?[A-Z]\b')),
    # Swedish personnummer / organisationsnummer — both share the
    # dashed format (one regex closes both catalog entries). The
    # legal date-prefix lengths are 6 (YYMMDD) or 8 (YYYYMMDD) only —
    # never 7 — and the separator is ``-`` or ``+`` (``+`` indicates
    # someone over 100 years old). Bare-digit forms intentionally
    # not matched (would over-match every 10-12 digit number).
    ('se_personnummer', re.compile(r'\b(?:\d{6}|\d{8})[-+]\d{4}\b')),
    # Indian Voter ID / EPIC — 3 letters + 7 digits. The 3-letter
    # prefix is what keeps this from colliding with the
    # ``us_drivers_license`` arm (1 letter + 7 digits).
    ('in_voter', re.compile(r'\b[A-Z]{3}\d{7}\b')),
    # Finnish personal identity code (henkilötunnus / HETU) —
    # DDMMYY + century-separator + 3-digit individual number +
    # check character (digit OR letter). The century separator is
    # one of: ``+`` (1800s); ``- Y X W V U`` (1900s, broadening per
    # the 2023 DVV expansion to cope with running out of individual
    # numbers); ``A B C D E F`` (2000s, same expansion). The full
    # set is ``[+\-ABCDEFUVWXY]``.
    ('fi_personal_identity_code', re.compile(
        r'\b\d{6}[+\-ABCDEFUVWXY]\d{3}[A-Z0-9]\b'
    )),

    # The remaining catalog close-outs are keyword-anchored because
    # the underlying digit/letter shape is too generic to flag on its
    # own. Each fires only when the labelled form appears in the
    # text — the production case for a tool result that names the
    # field.

    # US NPI (National Provider Identifier) — 10 digits, keyword.
    ('us_npi', re.compile(
        r'\bNPI\s*[:#=]?\s*\d{10}\b',
        re.IGNORECASE,
    )),
    # Australian Business Number — 11 digits, keyword ``ABN``.
    # Same 11-digit shape as PESEL / DE Steuer-ID; keyword is the
    # disambiguator.
    ('au_abn', re.compile(
        r'\bABN\s*[:#=]?\s*\d{2}\s?\d{3}\s?\d{3}\s?\d{3}\b',
        re.IGNORECASE,
    )),
    # Australian Company Number — 9 digits, keyword ``ACN``.
    ('au_acn', re.compile(
        r'\bACN\s*[:#=]?\s*\d{3}\s?\d{3}\s?\d{3}\b',
        re.IGNORECASE,
    )),
    # Singapore UEN — 9-10 char alphanumeric, several formats.
    # Keyword-anchored because the bare shape collides with many
    # other 9-10 char identifiers (FIN/NRIC, generic order ids).
    ('sg_uen', re.compile(
        r'\bUEN\s*[:#=]?\s*[A-Z0-9]{9,10}\b',
        re.IGNORECASE,
    )),
    # Thai National ID — 13 digits, keyword on either the English
    # term ``TNIN`` / ``Thai National ID`` or the Thai script
    # forms. The Thai-script keyword captures the production case
    # where the tool result is in Thai locale.
    ('th_tnin', re.compile(
        r'\b(?:TNIN|Thai\s+National\s+ID|เลขประจำตัวประชาชน|เลขบัตรประชาชน)'
        r'\s*[:#=]?\s*\d{13}\b',
        re.IGNORECASE,
    )),
    # Turkish National ID (TC Kimlik No) — 11 digits, keyword
    # ``TC`` optionally followed by ``Kimlik``. The 11-digit shape
    # collides with PESEL / DE Steuer-ID / AU ABN, so the keyword
    # anchor is the disambiguator.
    ('tr_national_id', re.compile(
        r'\bTC\s*(?:Kimlik(?:\s+No)?)?\s*[:#=]?\s*\d{11}\b',
        re.IGNORECASE,
    )),
    # Israeli Teudat Zehut — 9 digits where the last is a Luhn-like
    # check digit. The bare-9-digit shape collides with phone fragments
    # and US passport numbers, so the validator (registered in
    # ``_PATTERN_VALIDATORS``) is doing most of the work here. We also
    # accept the dashed form ``123-456-789`` that some Israeli forms
    # print, and the keyword-anchored form ``תז 123456789``.
    ('il_id', re.compile(
        r'\b(?:תז|teudat\s+zehut|israeli\s+id)\s*[:=]?\s*\d{9}\b'
        r'|\b\d{9}\b'
        r'|\b\d{3}-\d{3}-\d{3}\b',
        re.IGNORECASE,
    )),

    # --- financial ----------------------------------------------------
    # 13–19 digit card numbers, with optional space or dash separators.
    # Doesn't validate the Luhn checksum — that's a job for the
    # scrubber's caller, not the detector.
    ('credit_card', re.compile(r'\b(?:\d[ \-]?){13,19}\b')),
    # CVV in obvious context: "cvv 123", "cvc: 1234", "security code 123".
    ('credit_card_cvv', re.compile(
        r'\b(?:cvv|cvc|security\s+code)\s*[:=]?\s*\d{3,4}\b',
        re.IGNORECASE,
    )),
    # IBAN: 2-letter country + 2-digit check + 11-30 alphanumerics.
    # The canonical printed form groups characters in 4-char blocks
    # separated by whitespace (``GB82 WEST 1234 5698 7654 32``); accept
    # optional whitespace anywhere inside the alphanumeric body so both
    # the printed and machine forms match.
    ('iban', re.compile(
        r'\b[A-Z]{2}\d{2}(?:\s?[A-Z0-9]){11,32}\b'
    )),
    # SWIFT / BIC: 4 letters + 2 letters + 2 alphanumeric +
    # optional 3 alphanumeric.
    ('swift_bic', re.compile(r'\b[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}(?:[A-Z0-9]{3})?\b')),
    # US ABA routing number: 9 digits, usually whitespace-separated.
    ('us_routing_number', re.compile(r'\b\d{9}\b')),
    # US bank account: 4-17 digits, usually labelled. Match labelled form.
    ('us_bank_account', re.compile(
        r'\b(?:account|acct)[\s#:]*\d{4,17}\b',
        re.IGNORECASE,
    )),
    # Bitcoin address: legacy (1...), p2sh (3...), bech32 (bc1...).
    ('bitcoin_address', re.compile(
        r'\b(?:bc1[a-zA-HJ-NP-Z0-9]{25,87}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b'
    )),

    # --- postal -------------------------------------------------------
    # US ZIP (5) and ZIP+4 (5+4). Common but PII when combined with name.
    ('us_zip', re.compile(r'\b\d{5}(?:-\d{4})?\b')),
    # UK postcode: AA9A 9AA / A9A 9AA / A9 9AA / A99 9AA / AA9 9AA / AA99 9AA.
    ('uk_postcode', re.compile(
        r'\b[A-Z]{1,2}\d[A-Z\d]?\s*\d[A-Z]{2}\b'
    )),
    # Canadian postcode: A1A 1A1.
    ('ca_postcode', re.compile(r'\b[A-Z]\d[A-Z]\s*\d[A-Z]\d\b')),
    # Netherlands postcode: 4 digits + 2 uppercase letters (``1011 AB``).
    # Distinctive shape — the digit-then-letter ordering is unusual
    # enough that a keyword anchor would be redundant.
    ('nl_postcode', re.compile(r'\b\d{4}\s?[A-Z]{2}\b')),

    # --- network / device --------------------------------------------
    ('ipv4', re.compile(
        r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}'
        r'(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
    )),
    # IPv6: simplified — full or compressed forms.
    ('ipv6', re.compile(
        r'\b(?:[A-F0-9]{1,4}:){2,7}[A-F0-9]{1,4}\b',
        re.IGNORECASE,
    )),
    # MAC address: 6 hex pairs separated by ``:`` or ``-``.
    ('mac_address', re.compile(
        r'\b(?:[0-9A-F]{2}[:\-]){5}[0-9A-F]{2}\b',
        re.IGNORECASE,
    )),

    # --- session / token ----------------------------------------------
    # JWT — three base64url segments joined by dots. The first segment
    # always begins with ``eyJ`` because it's the base64 encoding of
    # ``{"`` (the JSON header's opening). That prefix makes JWTs
    # distinctive enough to flag without the false-positive risk of a
    # bare ``segment.segment.segment`` shape. Length floors of 10 per
    # segment keep us from matching short ``a.b.c`` text-fragments that
    # happen to start with ``eyJ``. Tokens routinely encode user id,
    # email, tenant id, and roles in the payload segment — even though
    # they're "credential material" they're PII shape from the model's
    # perspective and we want them out.
    ('jwt', re.compile(
        r'\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b'
    )),

    # --- geolocation --------------------------------------------------
    # GPS coordinate pair — ``lat, lon`` with at least four decimal
    # places on each side (4 places ≈ 11m precision, enough to be a
    # person's location; integer pairs like ``10, 20`` aren't useful
    # locations and would generate noise). Latitude bounded to
    # [-90, 90], longitude bounded to [-180, 180] — the bounded form
    # is what makes this safer than a generic ``\d+,\d+`` pattern.
    # PII when paired with a person; the product DOES carry
    # geo data for matchmaking distance calculations.
    ('gps_coordinates', re.compile(
        r'-?(?:90(?:\.0+)?|[1-8]?\d\.\d{4,})'
        r'\s*,\s*'
        r'-?(?:180(?:\.0+)?|1[0-7]\d\.\d{4,}|[1-9]?\d\.\d{4,})'
    )),

    # --- vehicle ------------------------------------------------------
    # VIN: 17 alphanumerics, no I/O/Q.
    ('vin', re.compile(r'\b[A-HJ-NPR-Z0-9]{17}\b')),
    # US license plate: very loose — 5-8 alphanumerics with at least
    # one digit. Best-effort; tighten per-state if false positives bite.
    ('us_license_plate', re.compile(
        r'\b(?=[A-Z0-9 \-]{5,8}\b)[A-Z0-9]+[ \-]?[A-Z0-9]+\b'
    )),

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

    # --- temporal -----------------------------------------------------
    # Date-of-birth in obvious context: "dob 1990-01-01", "date of birth 01/01/1990".
    ('date_of_birth', re.compile(
        r'\b(?:dob|date\s+of\s+birth|birthday|born)\s*[:=]?\s*'
        r'(?:\d{4}[-/]\d{1,2}[-/]\d{1,2}|\d{1,2}[-/]\d{1,2}[-/]\d{2,4})\b',
        re.IGNORECASE,
    )),
)


PII_PATTERN_NAMES: frozenset = frozenset(name for name, _ in _PII_PATTERNS)


# Per-pattern checksum / range validators. A pattern name that appears
# here is gated: its regex match is only kept if the validator returns
# True. Patterns not listed are shape-only (the regex is the whole
# detector). Closes Recommendation item 1 in the prior-art block above.
_PATTERN_VALIDATORS = {
    'credit_card': _luhn_valid,
    'ssn': _ssn_area_group_serial_valid,
    'iban': _iban_mod97_valid,
    'us_routing_number': _aba_routing_checksum_valid,
    'vin': _vin_check_digit_valid,
    'il_id': _il_id_check_digit_valid,
}


def _redact(matched_text: str) -> str:
    prefix_len = min(4, len(matched_text))
    return f'{matched_text[:prefix_len]}…[REDACTED, len={len(matched_text)}]'


def find_pii_patterns(text: str) -> List[PIIPatternFinding]:
    """Return every named PII pattern matched in ``text``.

    The raw matched value is never returned — callers receive only the
    pattern name and a redacted preview that is safe to log. Pattern
    order is fixed (declaration order), so cross-test assertions on
    ``findings[0]`` stay stable.
    """
    if not text or not isinstance(text, str):
        return []
    findings: List[PIIPatternFinding] = []
    for pattern_name, regex in _PII_PATTERNS:
        validator = _PATTERN_VALIDATORS.get(pattern_name)
        for match in regex.finditer(text):
            matched_text = match.group(0)
            if validator is not None and not validator(matched_text):
                continue
            findings.append(PIIPatternFinding(
                pattern_name=pattern_name,
                redacted_preview=_redact(matched_text),
            ))
    return findings


def summarize_pii_findings(findings: Iterable[PIIPatternFinding]) -> str:
    """Return an operator-facing summary without raw matched values."""
    by_name: dict[str, list[PIIPatternFinding]] = {}
    for finding in findings:
        by_name.setdefault(finding.pattern_name, []).append(finding)
    if not by_name:
        return 'no pii patterns detected'
    parts: list[str] = []
    for pattern_name, group in by_name.items():
        first = group[0].redacted_preview
        if len(group) == 1:
            parts.append(f'{pattern_name}={first}')
        else:
            parts.append(f'{pattern_name}={first} (+{len(group) - 1} more)')
    return '; '.join(parts)


def iter_pattern_names_and_regexes() -> Iterable[Tuple[str, re.Pattern[str]]]:
    """Expose the underlying ``(name, regex)`` pairs for callers that
    need to scrub text in place (see :mod:`pii_scrub`). Iteration order
    is the declaration order, which the scrubber relies on for
    deterministic output."""
    return _PII_PATTERNS


def get_validator_for(pattern_name: str):
    """Return the second-pass validator registered for ``pattern_name``,
    or ``None`` if the pattern is shape-only.

    The scrubber uses this to gate every regex match the same way
    :func:`find_pii_patterns` does — without it, ``_scrub_string`` would
    redact shape-valid-but-checksum-invalid numbers (e.g., a 13-digit
    sequence that isn't a real credit card) and over-redact otherwise
    safe text.
    """
    return _PATTERN_VALIDATORS.get(pattern_name)
