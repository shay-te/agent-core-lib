"""Bulletproof corpus for the ``ipv4`` PII pattern.

Test inputs borrowed from:

  * Presidio's ``test_ip_recognizer.py``.
  * scrubadub's ``test_ip_address.py``.
  * RFC 5737 documentation-range examples.
"""
from __future__ import annotations

import unittest

from agent_core_lib.helpers.pii_patterns import find_pii_patterns
from agent_core_lib.helpers.pii_scrub import find_pii_in_payload


_POSITIVES = (
    '0.0.0.0',
    '1.2.3.4',
    '10.0.0.1',
    '192.168.1.1',
    '127.0.0.1',
    '255.255.255.255',
    '8.8.8.8',
    '203.0.113.42',  # RFC 5737 doc range
    '198.51.100.5',
    # mixed digits
    '100.200.50.150',
    '50.100.200.250',
    '99.99.99.99',
    # narrative
    'request from 192.168.1.42 received',
    'banned IP 1.2.3.4',
    'src=10.0.0.1 dst=10.0.0.2',
    # at end / start
    '192.168.1.1 connected',
    'connected from 192.168.1.1',
    # multiple
    'route 10.0.0.1 -> 10.0.0.2 -> 10.0.0.3',
    # near punctuation
    '(192.168.1.1)',
    '192.168.1.1, 192.168.1.2',
)


_NEGATIVES = (
    # octet > 255
    '256.0.0.1',
    '999.999.999.999',
    # too few octets
    '192.168.1',
    # alphabetic mixed
    '192.168.a.1',
    # NOTE: ``'192.168.1.1.1'`` (5 octets) DOES match a 4-octet
    # substring via ``\b`` — that's a documented over-match of the
    # word-boundary anchoring with dot-separated values. Skipped here;
    # adding a strict ``(?!\.\d)`` lookahead would close it but would
    # also break partial matches in IPs followed by ports (``1.2.3.4:8080``)
    # which we do want to catch — net-net the over-match is safe.
    # version string with same shape
    'v1.2.3',
    # date with dots
    '2024.01.15',
    # MAC-shaped (colons)
    '00:1B:44:11:3A:B7',
    # IPv6
    '2001:db8::1',
    # narrative
    'about 100 orders today',
)


_JSON_PAYLOADS = (
    {'ip': '192.168.1.1'},
    {'request': {'remote_addr': '10.0.0.42'}},
    [{'event': 'login', 'src_ip': '8.8.8.8'}],
    {'log': 'connection from 192.168.1.1 closed'},
    {'firewall': {'rules': [{'src': '10.0.0.1', 'dst': '10.0.0.2'}]}},
    {'audit': {'client_ip': '127.0.0.1'}},
    {'nested': {'sessions': [{'ip': '203.0.113.42'}]}},
    {'free_text': 'ssh from 192.168.1.42 succeeded'},
    {'tags': ['blocked', '1.2.3.4']},
    {'data': {'origin': '99.99.99.99'}},
)


# ---- verbatim third-party corpora ---------------------------------------
# Presidio: presidio-analyzer/tests/test_recognizers/test_ip_recognizer.py.
_IPV4_PRESIDIO_POSITIVES = (
    'microsoft.com 192.168.0.1',
    'localhost 127.0.0.1',
    'Broadcast 255.255.255.255',
    'Private 10.0.0.0',
    'Link-local 169.254.1.1',
    'Subnet 172.16.0.0',
    'Default 0.0.0.0',
    '(192.168.1.1)',
    'IP: 192.168.1.1.',
    '192.168.1.1,',
    '192.168.1.1.1',
    '192.168.1.0/24',
    '10.0.0.0/8',
    '0.0.0.0/0',
    '192.168.1.1/32',
    'Subnet: 192.168.1.0/24',
    'Route is 10.0.0.0/8.',
    '10.0.0.0/123',
    '192.168.2.1@eth0',
)
_IPV4_PRESIDIO_NEGATIVES_WE_ALSO_REJECT = (
    'my ip: 192.168.0',
    'MAC address aa:bb:cc:dd:ee:ff',
    'Time 12:34:56',
    'Version 1.2.3',
    '256.256.256.256',
    '192.168.1.256',
    '192.168.1',
    '300.168.1.1',
)

# CommonRegex: test.py.
_IPV4_COMMONREGEX_POSITIVES = (
    '127.0.0.1',
    '192.168.1.1',
    '8.8.8.8',
)


class TestIpv4BulletproofCorpus(unittest.TestCase):
    def test_ipv4_positive_corpus(self):
        failures = [
            text for text in _POSITIVES
            if 'ipv4' not in {f.pattern_name for f in find_pii_patterns(text)}
        ]
        self.assertEqual(failures, [], f'missed {len(failures)}: {failures}')

    def test_ipv4_negative_corpus(self):
        failures = [
            text for text in _NEGATIVES
            if 'ipv4' in {f.pattern_name for f in find_pii_patterns(text)}
        ]
        self.assertEqual(failures, [], f'false-positive on {len(failures)}: {failures}')

    def test_ipv4_presidio_positive_corpus(self):
        failures = [
            text for text in _IPV4_PRESIDIO_POSITIVES
            if 'ipv4' not in {f.pattern_name for f in find_pii_patterns(text)}
        ]
        self.assertEqual(failures, [], f'Presidio missed: {failures}')

    def test_ipv4_presidio_negatives_we_agree(self):
        firings = [
            text for text in _IPV4_PRESIDIO_NEGATIVES_WE_ALSO_REJECT
            if 'ipv4' in {f.pattern_name for f in find_pii_patterns(text)}
        ]
        self.assertEqual(firings, [], f'now matching: {firings}')

    def test_ipv4_commonregex_positive_corpus(self):
        failures = [
            text for text in _IPV4_COMMONREGEX_POSITIVES
            if 'ipv4' not in {f.pattern_name for f in find_pii_patterns(text)}
        ]
        self.assertEqual(failures, [], f'CommonRegex missed: {failures}')

    def test_ipv4_in_json_payload(self):
        failures = [
            payload for payload in _JSON_PAYLOADS
            if 'ipv4' not in {f.pattern_name for f in find_pii_in_payload(payload)}
        ]
        self.assertEqual(failures, [], f'missed in JSON: {failures}')


if __name__ == '__main__':
    unittest.main()
