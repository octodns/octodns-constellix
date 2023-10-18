#
#
#

import logging
import time
from os.path import dirname, join
from unittest import TestCase
from unittest.mock import Mock, PropertyMock, call

from requests import HTTPError
from requests_mock import ANY
from requests_mock import mock as requests_mock

from octodns.provider import SupportsException
from octodns.provider.yaml import YamlProvider
from octodns.record import Record
from octodns.zone import Zone

from octodns_constellix import (
    ConstellixAPI,
    ConstellixAPIBadRequest,
    ConstellixClient,
    ConstellixProvider,
)


class TestConstellixProvider(TestCase):
    def populate_expected(self, zone_name):
        expected = Zone(zone_name, [])
        source = YamlProvider('test', join(dirname(__file__), 'config'))
        source.populate(expected)

        # Constellix does not allow IP addresses for NS entries.
        # Add our NS record and remove the default test case.
        for record in list(expected.records):
            if record.name == 'sub' and record._type == 'NS':
                expected._remove_record(record)
            if record.name == '' and record._type == 'NS':
                expected._remove_record(record)
        expected.add_record(
            Record.new(
                expected,
                'under',
                {
                    'ttl': 3600,
                    'type': 'NS',
                    'values': ['ns1.unit.tests.', 'ns2.unit.tests.'],
                },
            )
        )

        return expected

    def test_notes(self):
        provider = ConstellixProvider('test', 'api', 'secret')

        self.assertEqual({}, provider._parse_notes(None))
        self.assertEqual({}, provider._parse_notes(''))
        self.assertEqual({}, provider._parse_notes('blah-blah-blah'))

        # Round tripping
        data = {'key': 'value', 'priority': 1}
        notes = provider._encode_notes(data)
        self.assertEqual(data, provider._parse_notes(notes))

        # integers come out as int
        self.assertEqual(
            {'rule-order': 1}, provider._parse_notes('rule-order:1')
        )

        # floats come out as strings (not currently used so not parsed)
        self.assertEqual(
            {'rule-order': '1.2'}, provider._parse_notes('rule-order:1.2')
        )

        # strings that start with integers are still strings
        self.assertEqual(
            {'rule-order': '1-thing'},
            provider._parse_notes('rule-order:1-thing'),
        )

    def test_populate(self):
        provider = ConstellixProvider('test', 'api', 'secret')
        expected = self.populate_expected('unit.tests.')

        # Add an ALIAS record.
        expected.add_record(
            Record.new(
                expected,
                '',
                {'ttl': 1800, 'type': 'ALIAS', 'value': 'aname.unit.tests.'},
            )
        )

        # Add a dynamic record.
        expected.add_record(
            Record.new(
                expected,
                'www.dynamic',
                {
                    'ttl': 300,
                    'type': 'A',
                    # The global geo filter id=1 is exclusively used
                    # for these non-pooled default values.
                    'values': ['2.2.3.4', '2.2.3.5'],
                    'dynamic': {
                        'pools': {
                            'one': {
                                'values': [
                                    {'value': '1.2.3.6', 'weight': 1},
                                    {'value': '1.2.3.7', 'weight': 1},
                                ]
                            },
                            'two': {
                                'values': [
                                    {'value': '1.2.3.4', 'weight': 1},
                                    {'value': '1.2.3.5', 'weight': 1},
                                ]
                            },
                        },
                        'rules': [
                            {
                                'geos': [
                                    'AS',
                                    'EU-ES',
                                    'EU-UA',
                                    'EU-SE',
                                    'NA-CA-NL',
                                    'OC',
                                ],
                                'pool': 'one',
                            },
                            {'pool': 'two'},
                        ],
                    },
                },
            )
        )

        provider._client.geofilters = Mock(
            return_value=[
                {
                    'id': 1,
                    'name': 'World (Default)',
                    'geoipContinents': ['default'],
                }
            ]
        )

        # Bad auth
        with requests_mock() as mock:
            mock.get(
                ANY,
                status_code=401,
                text='{"errors": ["Unable to authenticate token"]}',
            )

            with self.assertRaises(Exception) as ctx:
                zone = Zone('unit.tests.', [])
                provider.populate(zone)
            self.assertEqual('Unauthorized', str(ctx.exception))

        with requests_mock() as mock:
            mock.get(
                ANY,
                status_code=401,
                text='{"errors": ["Unable to authenticate token"]}',
            )

            with self.assertRaises(Exception) as ctx:
                provider._sonar.agents
            self.assertEqual('Unauthorized', str(ctx.exception))

        # Bad request
        with requests_mock() as mock:
            mock.get(
                ANY,
                status_code=400,
                text='{"errors": ["\\"unittests\\" is not '
                'a valid domain name"]}',
            )

            with self.assertRaises(Exception) as ctx:
                zone = Zone('unit.tests.', [])
                provider.populate(zone)
            self.assertEqual(
                '\n  - "unittests" is not a valid domain name',
                str(ctx.exception),
            )

        with requests_mock() as mock:
            mock.get(ANY, status_code=400, text='error text')

            with self.assertRaises(Exception) as ctx:
                provider._sonar.agents
            self.assertEqual('\n  - error text', str(ctx.exception))

        # General error
        with requests_mock() as mock:
            mock.get(ANY, status_code=502, text='Things caught fire')

            with self.assertRaises(HTTPError) as ctx:
                zone = Zone('unit.tests.', [])
                provider.populate(zone)
            self.assertEqual(502, ctx.exception.response.status_code)

        # Non-existent zone doesn't populate anything.
        with requests_mock() as mock:
            mock.get(
                ANY,
                status_code=404,
                text='<html><head></head><body></body></html>',
            )

            zone = Zone('unit.tests.', [])
            provider.populate(zone)
            self.assertEqual(set(), zone.records)

        with requests_mock() as mock:
            mock.get(ANY, status_code=404, text='')
            with self.assertRaises(Exception) as ctx:
                provider._sonar.agents
            self.assertEqual('Not Found', str(ctx.exception))

        # Sonar Normal response.
        provider = ConstellixProvider('test', 'api', 'secret')
        with requests_mock() as mock:
            mock.get(ANY, status_code=200, text='[]')
            agents = provider._sonar.agents
            self.assertEqual({}, agents)
            agents = provider._sonar.agents

        provider = ConstellixProvider('test', 'api', 'secret', 0.01)
        with requests_mock() as mock:
            mock.get(ANY, status_code=200, text='[]')
            agents = provider._sonar.agents

        provider = ConstellixProvider('test', 'api', 'secret', 1.01)
        with requests_mock() as mock:
            mock.get(ANY, status_code=200, text='[]')
            agents = provider._sonar.agents

        provider = ConstellixProvider('test', 'api', 'secret')
        # No diffs == no changes
        with requests_mock() as mock:
            base = 'https://api.dns.constellix.com/v1'
            with open('tests/fixtures/constellix-domains.json') as fh:
                mock.get(f'{base}/domains', text=fh.read())
            with open('tests/fixtures/constellix-records.json') as fh:
                mock.get(f'{base}/domains/123123/records', text=fh.read())
            with open('tests/fixtures/constellix-pools.json') as fh:
                mock.get(f'{base}/pools/A', text=fh.read())
            with open('tests/fixtures/constellix-geofilters.json') as fh:
                mock.get(f'{base}/geoFilters', text=fh.read())

                zone = Zone('unit.tests.', [])
                provider.populate(zone)
                self.assertEqual(17, len(zone.records))
                changes = expected.changes(zone, provider)
                self.assertEqual(0, len(changes))

        # 2nd populate makes no network calls/all from cache
        again = Zone('unit.tests.', [])
        provider.populate(again)
        self.assertEqual(17, len(again.records))

        # Bust the cache.
        del provider._zone_records[zone.name]

    def test_apply(self):
        provider = ConstellixProvider(
            'test', 'api', 'secret', strict_supports=False
        )
        expected = self.populate_expected('unit.tests.')

        # Add an ALIAS record
        expected.add_record(
            Record.new(
                expected,
                '',
                {'ttl': 1800, 'type': 'ALIAS', 'value': 'aname.unit.tests.'},
            )
        )

        resp = Mock()
        resp.json = Mock()
        provider._client._request = Mock(return_value=resp)

        # Non-existent domain, create everything.
        resp_side_effect = [
            [],  # no domains returned during populate
            [{'id': 123123, 'name': 'unit.tests'}],  # domain created in apply
            [
                {
                    'id': 1808516,
                    'type': 'A',
                    'name': 'www',
                    'ttl': 300,
                    'recordOption': 'roundRobin',
                    'value': ['1.2.3.4', '2.2.3.4'],
                }
            ],  # global default entry created in apply
            [],
            [],
            [],
            [],
            [],
            [],
            [],
            [],
            [],
            [],
            [],
            [],
            [],
            [],
            [],
            [],
        ]
        resp.json.side_effect = resp_side_effect

        plan = provider.plan(expected)

        # 23 records given in unit.tests.yaml
        #  1 ALIAS record added
        #  1 Root NS record removed by test setup
        # 23 records exepected
        #  1 ignored
        #  1 exclued
        #  5 unsupported: URLFWD, NAPTR, LOC, SSHFP, DNAME
        #  8 records not applied
        # 16 records applied
        self.assertEqual(len(expected.records), 23)
        n = len(expected.records) - 7
        self.assertEqual(n, len(plan.changes))
        self.assertEqual(n, provider.apply(plan))

        # Check that nothing else happened during apply.
        self.assertEqual(
            len(resp_side_effect), provider._client._request.call_count
        )

        # Check what happened during apply.
        provider._client._request.assert_has_calls(
            [
                # get all domains to build the cache
                call('GET', '/domains'),
                # created the domain
                call('POST', '/domains', data={'names': ['unit.tests']}),
                # created a simple A record with non-default ttl
                # and ignoring unsupported geo information
                call(
                    'POST',
                    '/domains/123123/records/A',
                    data={
                        'name': '',
                        'ttl': 300,
                        'roundRobin': [
                            {'value': '1.2.3.4'},
                            {'value': '1.2.3.5'},
                        ],
                    },
                ),
                # created an ALIAS record with ALIAS to ANAME mapping
                call(
                    'POST',
                    '/domains/123123/records/ANAME',
                    data={
                        'name': '',
                        'ttl': 1800,
                        'roundRobin': [
                            {'value': 'aname.unit.tests.', 'disableFlag': False}
                        ],
                    },
                ),
                # created a CAA record
                call(
                    'POST',
                    '/domains/123123/records/CAA',
                    data={
                        'name': '',
                        'ttl': 3600,
                        'roundRobin': [
                            {'tag': 'issue', 'data': 'ca.unit.tests', 'flag': 0}
                        ],
                    },
                ),
                # created SRV record
                call(
                    'POST',
                    '/domains/123123/records/SRV',
                    data={
                        'name': '_imap._tcp',
                        'ttl': 600,
                        'roundRobin': [
                            {
                                'value': '.',
                                'priority': 0,
                                'weight': 0,
                                'port': 0,
                            }
                        ],
                    },
                ),
                call(
                    'POST',
                    '/domains/123123/records/SRV',
                    data={
                        'name': '_pop3._tcp',
                        'ttl': 600,
                        'roundRobin': [
                            {
                                'value': '.',
                                'priority': 0,
                                'weight': 0,
                                'port': 0,
                            }
                        ],
                    },
                ),
                call(
                    'POST',
                    '/domains/123123/records/SRV',
                    data={
                        'name': '_srv._tcp',
                        'ttl': 600,
                        'roundRobin': [
                            {
                                'value': 'foo-1.unit.tests.',
                                'priority': 10,
                                'weight': 20,
                                'port': 30,
                            },
                            {
                                'value': 'foo-2.unit.tests.',
                                'priority': 12,
                                'weight': 20,
                                'port': 30,
                            },
                        ],
                    },
                ),
                call(
                    'POST',
                    '/domains/123123/records/SRV',
                    data={
                        'name': '_srv._tcp',
                        'ttl': 600,
                        'roundRobin': [
                            {
                                'value': 'foo-1.unit.tests.',
                                'priority': 10,
                                'weight': 20,
                                'port': 30,
                            },
                            {
                                'value': 'foo-2.unit.tests.',
                                'priority': 12,
                                'weight': 20,
                                'port': 30,
                            },
                        ],
                    },
                ),
                call(
                    'POST',
                    '/domains/123123/records/AAAA',
                    data={
                        'name': 'aaaa',
                        'ttl': 600,
                        'roundRobin': [
                            {'value': '2601:644:500:e210:62f8:1dff:feb8:947a'}
                        ],
                    },
                ),
                call(
                    'POST',
                    '/domains/123123/records/CNAME',
                    data={'name': 'cname', 'ttl': 300, 'host': 'unit.tests.'},
                ),
                call(
                    'POST',
                    '/domains/123123/records/CNAME',
                    data={
                        'name': 'included',
                        'ttl': 3600,
                        'host': 'unit.tests.',
                    },
                ),
                call(
                    'POST',
                    '/domains/123123/records/MX',
                    data={
                        'value': 'smtp-1.unit.tests.',
                        'name': 'mx',
                        'ttl': 300,
                        'roundRobin': [
                            {'value': 'smtp-4.unit.tests.', 'level': 10},
                            {'value': 'smtp-2.unit.tests.', 'level': 20},
                            {'value': 'smtp-3.unit.tests.', 'level': 30},
                            {'value': 'smtp-1.unit.tests.', 'level': 40},
                        ],
                    },
                ),
                call(
                    'POST',
                    '/domains/123123/records/PTR',
                    data={
                        'name': 'ptr',
                        'ttl': 300,
                        'roundRobin': [
                            {'value': 'foo.bar.com.', 'disableFlag': False}
                        ],
                    },
                ),
                call(
                    'POST',
                    '/domains/123123/records/SPF',
                    data={
                        'name': 'spf',
                        'ttl': 600,
                        'roundRobin': [
                            {'value': '"v=spf1 ip4:192.168.0.1/16-all"'}
                        ],
                    },
                ),
                call(
                    'POST',
                    '/domains/123123/records/TXT',
                    data={
                        'name': 'txt',
                        'ttl': 600,
                        'roundRobin': [
                            {'value': '"Bah bah black sheep"'},
                            {'value': '"have you any wool."'},
                            {
                                'value': (
                                    '"v=DKIM1;k=rsa;s=email;h=sha256;'
                                    'p=A/kinda+of/long/string+with+numb3rs"'
                                )
                            },
                        ],
                    },
                ),
                call(
                    'POST',
                    '/domains/123123/records/NS',
                    data={
                        'name': 'under',
                        'ttl': 3600,
                        'roundRobin': [
                            {'value': 'ns1.unit.tests.'},
                            {'value': 'ns2.unit.tests.'},
                        ],
                    },
                ),
                call(
                    'POST',
                    '/domains/123123/records/A',
                    data={
                        'name': 'www',
                        'ttl': 300,
                        'roundRobin': [{'value': '2.2.3.6'}],
                    },
                ),
                call(
                    'POST',
                    '/domains/123123/records/A',
                    data={
                        'name': 'www.sub',
                        'ttl': 300,
                        'roundRobin': [{'value': '2.2.3.6'}],
                    },
                ),
            ]
        )

        provider._client._request.reset_mock()

        provider._client.records = Mock(
            return_value=[
                {
                    'id': 11189897,
                    'type': 'A',
                    'name': 'www',
                    'ttl': 300,
                    'recordOption': 'roundRobin',
                    'value': ['1.2.3.4', '2.2.3.4'],
                },
                {
                    'id': 11189898,
                    'type': 'A',
                    'name': 'ttl',
                    'ttl': 600,
                    'recordOption': 'roundRobin',
                    'value': ['3.2.3.4'],
                },
                {
                    'id': 1808515,
                    'type': 'ALIAS',
                    'name': '',
                    'ttl': 1800,
                    'recordOption': 'roundRobin',
                    'value': [{'value': 'aname.unit.tests.'}],
                },
            ]
        )

        # Domain exists, we don't care about return
        resp_side_effect = [
            [],  # delete A record ttl
            [],  # delete pool www.dynamic:A:two
            {
                'id': 123123,
                'name': 'unit.tests',
                'hasGeoIP': False,
            },  # domain listed for enabling geo
            [
                {'id': 1808521, 'name': 'unit.tests.:www.dynamic:A:one'}
            ],  # pool re-created in apply
            [],
            [],
            [],
            [],
            [],
            [],
            [],
            [],
            [],
            [],
            [],
            [],
            [],
            [],
        ]
        resp.json.side_effect = resp_side_effect

        wanted = Zone('unit.tests.', [])
        wanted.add_record(
            Record.new(
                wanted, 'ttl', {'ttl': 300, 'type': 'A', 'value': '3.2.3.5'}
            )
        )
        wanted.add_record(
            Record.new(
                wanted,
                'www',
                {
                    'ttl': 300,
                    'type': 'AAAA',
                    'values': [
                        '2601:644:500:e210:62f8:1dff:feb8:947a',
                        '2601:642:500:e210:62f8:1dff:feb8:947a',
                    ],
                },
            )
        )

        plan = provider.plan(wanted)
        # change 1, delete 2, keep 1, add 1
        self.assertEqual(4, len(plan.changes))
        self.assertEqual(4, provider.apply(plan))

        # Check nothing else happened

        # recreate for update
        provider._client._request.assert_has_calls(
            [call('GET', '/domains/123123')]
        )
        provider._client._request.assert_has_calls(
            [call('DELETE', '/domains/123123/records/ANAME/1808515')]
        )
        provider._client._request.assert_has_calls(
            [
                call('DELETE', '/domains/123123/records/A/11189898'),
                call(
                    'POST',
                    '/domains/123123/records/A',
                    data={
                        'name': 'ttl',
                        'ttl': 300,
                        'roundRobin': [{'value': '3.2.3.5'}],
                    },
                ),
            ]
        )
        provider._client._request.assert_has_calls(
            [
                call('DELETE', '/domains/123123/records/A/11189897'),
                call(
                    'POST',
                    '/domains/123123/records/AAAA',
                    data={
                        'name': 'www',
                        'ttl': 300,
                        'roundRobin': [
                            {'value': '2601:642:500:e210:62f8:1dff:feb8:947a'},
                            {'value': '2601:644:500:e210:62f8:1dff:feb8:947a'},
                        ],
                    },
                ),
            ]
        )

    def test_apply_healthcheck(self):
        provider = ConstellixProvider('test', 'api', 'secret')
        expected = Zone('unit.tests.', [])

        # Add a dynamic record with regional health checks
        expected.add_record(
            Record.new(
                expected,
                'www.dynamic',
                {
                    'ttl': 300,
                    'type': 'A',
                    'values': ['7.7.7.7', '8.8.8.8'],
                    'dynamic': {
                        'pools': {
                            'two': {
                                'values': [
                                    {'value': '1.2.3.4', 'weight': 1},
                                    {'value': '1.2.3.5', 'weight': 1},
                                ]
                            }
                        },
                        'rules': [{'pool': 'two'}],
                    },
                    'octodns': {
                        'constellix': {
                            'healthcheck': {
                                'sonar_port': 80,
                                'sonar_regions': ['ASIAPAC', 'EUROPE'],
                                'sonar_type': 'TCP',
                            }
                        }
                    },
                },
            )
        )

        resp = Mock()
        resp.json = Mock()
        provider._client._request = Mock(return_value=resp)

        # non-existent domain, create everything
        resp_side_effect = [
            [],  # no domains returned during populate
            [{'id': 123123, 'name': 'unit.tests'}],  # domain created in apply
            [],  # no pools returned during populate
            [
                {'id': 1808521, 'name': 'unit.tests.:www.dynamic:A:two'}
            ],  # pool created in apply
            [
                {
                    'id': 1,
                    'name': 'World (Default)',
                    'geoipContinents': ['default'],
                }
            ],  # geofilters returned
            [
                {
                    'id': 3049,
                    'name': 'unit.tests.:www.dynamic:A:two',
                    'geoipContinents': ['default'],
                }
            ],  # geofilter created in apply
            {
                'id': 123123,
                'name': 'unit.tests',
                'hasGeoIP': False,
            },  # domain listed for enabling geo
            [],  # enabling geo
            [
                {
                    'id': 1808516,
                    'type': 'A',
                    'name': 'www.dynamic',
                    'ttl': 300,
                    'recordOption': 'roundRobin',
                    'value': ['7.7.7.7', '8.8.8.8'],
                }
            ],  # global default entry created in apply
            [
                {
                    'id': 1808521,
                    'type': 'A',
                    'name': 'www.dynamic',
                    'geolocation': {'geoipFilter': 1},
                    'ttl': 300,
                    'recordOption': 'pool',
                    'value': [],
                    'pools': ['1'],
                }
            ],  # pool with geo entry created in apply
        ]
        resp.json.side_effect = resp_side_effect

        sonar_resp = Mock()
        sonar_resp.json = Mock()
        type(sonar_resp).headers = PropertyMock(
            return_value={
                'Location': 'http://api.sonar.constellix.com/rest/api/tcp/52906'
            }
        )
        sonar_resp.headers = Mock()
        provider._sonar._request = Mock(return_value=sonar_resp)

        sonar_resp_side_effect = [
            [
                {
                    'id': 1,
                    'name': 'USWAS01',
                    'label': 'Site 1',
                    'location': 'Washington, DC, U.S.A',
                    'country': 'U.S.A',
                    'region': 'ASIAPAC',
                },
                {
                    'id': 23,
                    'name': 'CATOR01',
                    'label': 'Site 1',
                    'location': 'Toronto,Canada',
                    'country': 'Canada',
                    'region': 'EUROPE',
                },
                {
                    'id': 25,
                    'name': 'CATOR01',
                    'label': 'Site 1',
                    'location': 'Toronto,Canada',
                    'country': 'Canada',
                    'region': 'OCEANIA',
                },
            ],  # available agents
            [
                {'id': 52, 'name': 'unit.tests.:www.dynamic:A:two-1.2.3.4'}
            ],  # initial checks
            {'type': 'TCP'},
            {
                'id': 52906,
                'name': 'unit.tests.:www.dynamic:A:two-1.2.3.4',
            },  # check_create GET data
            {
                'id': 52907,
                'name': 'unit.tests.:www.dynamic:A:two-1.2.3.5',
            },  # check_create GET data
        ]
        sonar_resp.json.side_effect = sonar_resp_side_effect

        plan = provider.plan(expected)

        n = len(expected.records)
        self.assertEqual(n, len(plan.changes))
        self.assertEqual(n, provider.apply(plan))

        # Check nothing else happened
        self.assertEqual(
            len(resp_side_effect), provider._client._request.call_count
        )

        # Check what happened
        provider._client._request.assert_has_calls(
            [
                # get all domains to build the cache
                call('GET', '/domains'),
                # created the domain
                call('POST', '/domains', data={'names': ['unit.tests']}),
                # get all pools to build the cache
                call('GET', '/pools/A'),
                # created the pool
                call(
                    'POST',
                    '/pools/A',
                    data={
                        'name': 'unit.tests.:www.dynamic:A:two',
                        'type': 'A',
                        'numReturn': 1,
                        'minAvailableFailover': 1,
                        'values': [
                            {
                                'value': '1.2.3.4',
                                'weight': 1,
                                'checkId': 52906,
                                'policy': 'followsonar',
                            },
                            {
                                'value': '1.2.3.5',
                                'weight': 1,
                                'checkId': 52907,
                                'policy': 'followsonar',
                            },
                        ],
                    },
                ),
                call('GET', '/geoFilters'),
                call(
                    'POST',
                    '/geoFilters',
                    data={
                        'filterRulesLimit': 100,
                        'name': 'unit.tests.:www.dynamic:A:two',
                        'geoipContinents': ['default'],
                    },
                ),
                call('GET', '/domains/123123'),
                call('PUT', '/domains/123123', data={'hasGeoIP': True}),
                call(
                    'POST',
                    '/domains/123123/records/A',
                    data={
                        'name': 'www.dynamic',
                        'ttl': 300,
                        'roundRobin': [
                            {'value': '7.7.7.7'},
                            {'value': '8.8.8.8'},
                        ],
                        'geolocation': {'geoipUserRegion': [1]},
                    },
                ),
                call(
                    'POST',
                    '/domains/123123/records/A',
                    data={
                        'name': 'www.dynamic',
                        'note': 'rule-order:0',
                        'ttl': 300,
                        'recordOption': 'pools',
                        'pools': [1808521],
                        'geolocation': {'geoipUserRegion': [3049]},
                    },
                ),
            ]
        )

        # Check nothing else happened in sonar:
        # +2 for two check_create calls, +1 for one check_delete call
        # these methods have two API calls but only one .json() call
        self.assertEqual(
            len(sonar_resp_side_effect) + 3, provider._sonar._request.call_count
        )

        # Check what happened in sonar
        provider._sonar._request.assert_has_calls(
            [
                call('GET', '/system/sites'),
                call('GET', '/tcp'),
                call('GET', '/check/type/52'),
                call('DELETE', '/tcp/52'),  # recreate, same name
                call(
                    'POST',
                    '/tcp',
                    data={
                        'name': 'unit.tests.:www.dynamic:A:two-1.2.3.4',
                        'host': '1.2.3.4',
                        'port': 80,
                        'checkSites': [1],
                        'interval': 'ONEMINUTE',
                        'ipVersion': 'IPV4',
                    },
                ),  # only returns 201 / created with new ID in header
                call(
                    'GET',
                    '/tcp/52906',
                    data={
                        'name': 'unit.tests.:www.dynamic:A:two-1.2.3.4',
                        'host': '1.2.3.4',
                        'port': 80,
                        'checkSites': [1],
                        'interval': 'ONEMINUTE',
                        'ipVersion': 'IPV4',
                    },
                ),
                call(
                    'POST',
                    '/tcp',
                    data={
                        'name': 'unit.tests.:www.dynamic:A:two-1.2.3.5',
                        'host': '1.2.3.5',
                        'port': 80,
                        'checkSites': [1],
                        'interval': 'ONEMINUTE',
                        'ipVersion': 'IPV4',
                    },
                ),  # only returns 201 / created with new ID in header
                call(
                    'GET',
                    '/tcp/52906',
                    data={
                        'name': 'unit.tests.:www.dynamic:A:two-1.2.3.5',
                        'host': '1.2.3.5',
                        'port': 80,
                        'checkSites': [1],
                        'interval': 'ONEMINUTE',
                        'ipVersion': 'IPV4',
                    },
                ),
            ]
        )

    def test_apply_healthcheck_world(self):
        provider = ConstellixProvider('test', 'api', 'secret')
        expected = Zone('unit.tests.', [])

        # Add a dynamic record with WORLD healthcheck
        expected.add_record(
            Record.new(
                expected,
                'www.dynamic',
                {
                    'ttl': 300,
                    'type': 'AAAA',
                    'values': [
                        '2601:644:500:e210:62f8:1dff:feb8:947a',
                        '2601:642:500:e210:62f8:1dff:feb8:947a',
                    ],
                    'dynamic': {
                        'pools': {
                            'two': {
                                'values': [
                                    {
                                        'value': '2601:642:500:e210:62f8:1dff:feb8:9472',
                                        'weight': 1,
                                    },
                                    {
                                        'value': '2601:642:500:e210:62f8:1dff:feb8:9473',
                                        'weight': 1,
                                    },
                                ]
                            }
                        },
                        'rules': [{'pool': 'two'}],
                    },
                    'octodns': {
                        'constellix': {
                            'healthcheck': {
                                'sonar_port': 80,
                                'sonar_regions': ['WORLD'],
                                'sonar_type': 'HTTP',
                            }
                        }
                    },
                },
            )
        )

        resp = Mock()
        resp.json = Mock()
        provider._client._request = Mock(return_value=resp)

        # non-existent domain, create everything
        resp_side_effect = [
            [],  # no domains returned during populate
            [{'id': 123123, 'name': 'unit.tests'}],  # domain created in apply
            [],  # No pools returned during populate
            [
                {'id': 1808521, 'name': 'unit.tests.:www.dynamic:A:two'}
            ],  # pool created in apply
            [
                {
                    'id': 1,
                    'name': 'World (Default)',
                    'geoipContinents': ['default'],
                }
            ],  # geofilters returned
            [
                {
                    'id': 9049,
                    'name': 'unit.tests.:www.dynamic:AAAA:two',
                    'geoipContinents': ['default'],
                }
            ],  # geofilter created in apply
            {
                'id': 123123,
                'name': 'unit.tests',
                'hasGeoIP': False,
            },  # domain listed for enabling geo
            [],  # enabling geo
            [],  # create global default AAAA record
            [],  # create pooled AAAA record
        ]
        resp.json.side_effect = resp_side_effect

        sonar_resp = Mock()
        sonar_resp.json = Mock()
        type(sonar_resp).headers = PropertyMock(
            return_value={
                'Location': 'http://api.sonar.constellix.com/rest/api/tcp/52906'
            }
        )
        sonar_resp.headers = Mock()
        provider._sonar._request = Mock(return_value=sonar_resp)

        sonar_resp.json.side_effect = [
            [
                {
                    'id': 1,
                    'name': 'USWAS01',
                    'label': 'Site 1',
                    'location': 'Washington, DC, U.S.A',
                    'country': 'U.S.A',
                    'region': 'ASIAPAC',
                },
                {
                    'id': 23,
                    'name': 'CATOR01',
                    'label': 'Site 1',
                    'location': 'Toronto,Canada',
                    'country': 'Canada',
                    'region': 'EUROPE',
                },
            ],  # available agents
            [],  # no checks
            {'id': 52906, 'name': 'check1'},
            {'id': 52907, 'name': 'check2'},
        ]

        plan = provider.plan(expected)

        n = len(expected.records)
        self.assertEqual(n, len(plan.changes))
        self.assertEqual(n, provider.apply(plan))

        provider._client._request.assert_has_calls(
            [
                # get all domains to build the cache
                call('GET', '/domains'),
                # created the domain
                call('POST', '/domains', data={'names': ['unit.tests']}),
            ]
        )

        # Check we tried to get our pool
        provider._client._request.assert_has_calls(
            [
                # get all pools to build the cache
                call('GET', '/pools/AAAA'),
                # created the pool
                call(
                    'POST',
                    '/pools/AAAA',
                    data={
                        'name': 'unit.tests.:www.dynamic:AAAA:two',
                        'type': 'AAAA',
                        'numReturn': 1,
                        'minAvailableFailover': 1,
                        'values': [
                            {
                                'value': '2601:642:500:e210:62f8:1dff:feb8:9472',
                                'weight': 1,
                                'checkId': 52906,
                                'policy': 'followsonar',
                            },
                            {
                                'value': '2601:642:500:e210:62f8:1dff:feb8:9473',
                                'weight': 1,
                                'checkId': 52907,
                                'policy': 'followsonar',
                            },
                        ],
                    },
                ),
            ]
        )

        # Check we updated our record
        provider._client._request.assert_has_calls(
            [
                # updated the record
                call(
                    'POST',
                    '/domains/123123/records/AAAA',
                    data={
                        'name': 'www.dynamic',
                        'ttl': 300,
                        'roundRobin': [
                            {'value': '2601:642:500:e210:62f8:1dff:feb8:947a'},
                            {'value': '2601:644:500:e210:62f8:1dff:feb8:947a'},
                        ],
                        'geolocation': {'geoipUserRegion': [1]},
                    },
                )
            ]
        )

        # Check nothing else happened
        self.assertEqual(
            len(resp_side_effect), provider._client._request.call_count
        )

    def test_apply_dynamic(self):
        provider = ConstellixProvider(
            'test', 'api', 'secret', strict_supports=False
        )
        expected = Zone('unit.tests.', [])

        # Add a dynamic record.
        expected.add_record(
            Record.new(
                expected,
                'www.dynamic',
                {
                    'ttl': 300,
                    'type': 'A',
                    'values': ['1.2.3.4', '1.2.3.5'],
                    'dynamic': {
                        'pools': {
                            'one': {
                                'fallback': 'two',
                                'values': [
                                    {'value': '1.2.3.6', 'weight': 1},
                                    {'value': '1.2.3.7', 'weight': 1},
                                ],
                            },
                            'two': {
                                'values': [
                                    {'value': '1.2.3.4', 'weight': 2},
                                    {'value': '1.2.3.5', 'weight': 4},
                                ]
                            },
                        },
                        'rules': [
                            {
                                'geos': [
                                    'AS',
                                    'EU-ES',
                                    'EU-UA',
                                    'EU-SE',
                                    'NA-CA-NL',
                                    'OC',
                                ],
                                'pool': 'one',
                            },
                            {'pool': 'two'},
                        ],
                    },
                },
            )
        )

        resp = Mock()
        resp.json = Mock()
        provider._client._request = Mock(return_value=resp)

        # non-existent domain, create everything
        resp_side_effect = [
            [],  # no domains returned during populate
            [{'id': 123123, 'name': 'unit.tests'}],  # domain created in apply
            [],  # No pools returned during populate
            [
                {'id': 1808522, 'name': 'unit.tests.:www.dynamic:A:one'}
            ],  # pool created in apply
            [
                {'id': 1808521, 'name': 'unit.tests.:www.dynamic:A:two'}
            ],  # pool created in apply
            [
                {
                    'id': 1,
                    'name': 'World (Default)',
                    'geoipContinents': ['default'],
                }
            ],  # geofilters returned in apply
            [
                {
                    'id': 5303,
                    'name': 'unit.tests.:www.dynamic:A:one',
                    'filterRulesLimit': 100,
                    'geoipContinents': ['AS', 'OC'],
                    'geoipCountries': ['ES', 'SE', 'UA'],
                    'regions': [
                        {
                            'continentCode': 'NA',
                            'countryCode': 'CA',
                            'regionCode': 'NL',
                        }
                    ],
                }
            ],  # geofilter created in apply
            [
                {
                    'id': 9303,
                    'name': 'unit.tests.:www.dynamic:A:two',
                    'filterRulesLimit': 100,
                    'geoipContinents': ['default'],
                }
            ],  # geofilter created in apply
            {
                'id': 123123,
                'name': 'unit.tests',
                'hasGeoIP': False,
            },  # domain listed for enabling geo
            [],  # enabling geo
            [],
            [],
            [],
        ]
        resp.json.side_effect = resp_side_effect

        plan = provider.plan(expected)

        # No root NS, no ignored, no excluded, no unsupported
        n = len(expected.records)
        self.assertEqual(n, len(plan.changes))
        self.assertEqual(n, provider.apply(plan))

        # Check that nothing else happened in apply.
        self.assertEqual(
            len(resp_side_effect), provider._client._request.call_count
        )

        # Check what happened in apply.
        provider._client._request.assert_has_calls(
            [
                # get all domains to build the cache
                call('GET', '/domains'),
                # created the domain
                call('POST', '/domains', data={'names': ['unit.tests']}),
                call('GET', '/pools/A'),
                call(
                    'POST',
                    '/pools/A',
                    data={
                        'name': 'unit.tests.:www.dynamic:A:one',
                        'type': 'A',
                        'numReturn': 1,
                        'minAvailableFailover': 1,
                        'values': [
                            {'value': '1.2.3.6', 'weight': 1},
                            {'value': '1.2.3.7', 'weight': 1},
                        ],
                    },
                ),
                call(
                    'POST',
                    '/pools/A',
                    data={
                        'name': 'unit.tests.:www.dynamic:A:two',
                        'type': 'A',
                        'numReturn': 1,
                        'minAvailableFailover': 1,
                        'values': [
                            {'value': '1.2.3.4', 'weight': 2},
                            {'value': '1.2.3.5', 'weight': 4},
                        ],
                    },
                ),
                call('GET', '/geoFilters'),
                call(
                    'POST',
                    '/geoFilters',
                    data={
                        'filterRulesLimit': 100,
                        'name': 'unit.tests.:www.dynamic:A:one',
                        'geoipContinents': ['AS', 'OC'],
                        'geoipCountries': ['ES', 'SE', 'UA'],
                        'regions': [
                            {
                                'continentCode': 'NA',
                                'countryCode': 'CA',
                                'regionCode': 'NL',
                            }
                        ],
                    },
                ),
                call(
                    'POST',
                    '/geoFilters',
                    data={
                        'filterRulesLimit': 100,
                        'name': 'unit.tests.:www.dynamic:A:two',
                        'geoipContinents': ['default'],
                    },
                ),
                call('GET', '/domains/123123'),
                call('PUT', '/domains/123123', data={'hasGeoIP': True}),
                call(
                    'POST',
                    '/domains/123123/records/A',
                    data={
                        'name': 'www.dynamic',
                        'ttl': 300,
                        'roundRobin': [
                            {'value': '1.2.3.4'},
                            {'value': '1.2.3.5'},
                        ],
                        'geolocation': {'geoipUserRegion': [1]},
                    },
                ),
                call(
                    'POST',
                    '/domains/123123/records/A',
                    data={
                        'name': 'www.dynamic',
                        'note': 'rule-order:0',
                        'ttl': 300,
                        'recordOption': 'pools',
                        'pools': [1808522],
                        'geolocation': {'geoipUserRegion': [5303]},
                    },
                ),
                call(
                    'POST',
                    '/domains/123123/records/A',
                    data={
                        'name': 'www.dynamic',
                        'note': 'rule-order:1',
                        'ttl': 300,
                        'recordOption': 'pools',
                        'pools': [1808521],
                        'geolocation': {'geoipUserRegion': [9303]},
                    },
                ),
            ]
        )

        provider._client._request.reset_mock()
        resp.json.reset_mock()

        provider._client.records = Mock(
            return_value=[
                {
                    'id': 1808518,
                    'type': 'A',
                    'name': 'www.dynamic',
                    'geolocation': {'geoipFilter': 1},
                    'ttl': 300,
                    'recordOption': 'roundRobin',
                    'value': ['1.2.3.4', '1.2.3.5'],
                },
                {
                    'id': 1808520,
                    'type': 'A',
                    'name': 'www.dynamic',
                    'note': 'rule-order:0',
                    'geolocation': {'geoipFilter': 9303},
                    'recordOption': 'pools',
                    'ttl': 300,
                    'value': [],
                    'pools': [1808521],
                },
                {
                    'id': 1808521,
                    'type': 'A',
                    'name': 'www.dynamic',
                    'note': 'rule-order:1',
                    'geolocation': {'geoipFilter': 5303},
                    'recordOption': 'pools',
                    'ttl': 300,
                    'value': [],
                    'pools': [1808522],
                },
            ]
        )

        provider._client.pools = Mock(
            return_value=[
                {
                    'id': 1808521,
                    'name': 'unit.tests.:www.dynamic:A:two',
                    'note': 'rule-order:1',
                    'type': 'A',
                    'values': [
                        {'value': '1.2.3.4', 'weight': 2},
                        {'value': '1.2.3.5', 'weight': 4},
                    ],
                },
                {
                    'id': 1808522,
                    'name': 'unit.tests.:www.dynamic:A:one',
                    'note': 'rule-order:0',
                    'type': 'A',
                    'values': [
                        {'value': '1.2.3.6', 'weight': 1},
                        {'value': '1.2.3.7', 'weight': 1},
                    ],
                },
            ]
        )

        provider._client.geofilters = Mock(
            return_value=[
                {
                    'id': 1,
                    'name': 'World (Default)',
                    'geoipContinents': ['default'],
                },
                {
                    'id': 5303,
                    'name': 'unit.tests.:www.dynamic:A:one',
                    'filterRulesLimit': 100,
                    'geoipContinents': ['AS', 'OC'],
                    'geoipCountries': ['ES', 'SE', 'UA'],
                    'regions': [
                        {
                            'continentCode': 'NA',
                            'countryCode': 'CA',
                            'regionCode': 'NL',
                        }
                    ],
                },
                {
                    'id': 9303,
                    'name': 'unit.tests.:www.dynamic:A:two',
                    'filterRulesLimit': 100,
                    'geoipContinents': ['default'],
                },
            ]
        )

        # Domain exists, we don't care about return
        resp_side_effect = [
            [],  # get domain
            [],  # delete A
            [],  # delete geofilter
            [],  # delete pool
            [],  # delete A
            [],  # delete geofilter
            [],  # delete pool
            [],  # delete A
            {
                'id': 1808522,
                'name': 'unit.tests.:www.dynamic:A:one',
                'type': 'A',
                'values': [
                    {'value': '1.2.3.6', 'weight': 5},
                    {'value': '1.2.3.7', 'weight': 2},
                ],
            },  # update pool - no list
            {
                'id': 1808521,
                'name': 'unit.tests.:www.dynamic:A:two',
                'type': 'A',
                'values': [{'value': '1.2.3.4', 'weight': 1}],
            },  # update pool - no list
            [
                {
                    'id': 1808523,
                    'name': 'unit.tests.:www.dynamic:A:fallback',
                    'type': 'A',
                    'values': [{'value': '9.9.9.9', 'weight': 1}],
                }
            ],  # create pool - list
            {},
            {},
            {
                'id': 123123,
                'name': 'unit.tests',
                'hasGeoIP': True,
            },  # domain listed for enabling geo
            [],
            [],
            [],
            [],
        ]
        resp.json.side_effect = resp_side_effect

        wanted = Zone('unit.tests.', [])
        wanted.add_record(
            Record.new(
                wanted,
                'www.dynamic',
                {
                    'ttl': 600,
                    'type': 'A',
                    'values': ['1.2.3.4'],
                    'dynamic': {
                        'pools': {
                            'one': {
                                'fallback': 'two',
                                'values': [
                                    {'value': '1.2.3.6', 'weight': 5},
                                    {'value': '1.2.3.7', 'weight': 2},
                                ],
                            },
                            'two': {
                                'fallback': 'fallback',
                                'values': [{'value': '1.2.3.4', 'weight': 1}],
                            },
                            'fallback': {  # fallback pool without rule
                                'values': [{'value': '9.9.9.9'}]
                            },
                        },
                        'rules': [
                            {
                                'geos': [
                                    'AS',
                                    'EU-DK',
                                    'EU-UA',
                                    'EU-SE',
                                    'NA-CA-NL',
                                    'OC',
                                ],
                                'pool': 'one',
                            },
                            {'pool': 'two'},
                        ],
                    },
                },
            )
        )

        plan = provider.plan(wanted)
        self.assertEqual(1, len(plan.changes))
        self.assertEqual(1, provider.apply(plan))

        self.assertEqual(
            len(resp_side_effect), provider._client._request.call_count
        )

        # recreate for update, and deletes for the 2 parts of the other
        provider._client._request.assert_has_calls(
            [
                call('GET', '/domains/123123'),
                call('DELETE', '/domains/123123/records/A/1808520'),
                call('DELETE', '/geoFilters/9303'),
                call('DELETE', '/pools/A/1808521'),
                call('DELETE', '/domains/123123/records/A/1808521'),
                call('DELETE', '/geoFilters/5303'),
                call('DELETE', '/pools/A/1808522'),
                call('DELETE', '/domains/123123/records/A/1808518'),
                call(
                    'PUT',
                    '/pools/A/1808522',
                    data={
                        'name': 'unit.tests.:www.dynamic:A:one',
                        'type': 'A',
                        'numReturn': 1,
                        'minAvailableFailover': 1,
                        'values': [
                            {'value': '1.2.3.6', 'weight': 5},
                            {'value': '1.2.3.7', 'weight': 2},
                        ],
                    },
                ),
                call(
                    'PUT',
                    '/pools/A/1808521',
                    data={
                        'name': 'unit.tests.:www.dynamic:A:two',
                        'type': 'A',
                        'numReturn': 1,
                        'minAvailableFailover': 1,
                        'values': [{'value': '1.2.3.4', 'weight': 1}],
                    },
                ),
                call(
                    'POST',
                    '/pools/A',
                    data={
                        'name': 'unit.tests.:www.dynamic:A:fallback',
                        'type': 'A',
                        'numReturn': 1,
                        'minAvailableFailover': 1,
                        'values': [{'value': '9.9.9.9', 'weight': 1}],
                    },
                ),
                call(
                    'PUT',
                    '/geoFilters/5303',
                    data={
                        'filterRulesLimit': 100,
                        'name': 'unit.tests.:www.dynamic:A:one',
                        'geoipContinents': ['AS', 'OC'],
                        'geoipCountries': ['DK', 'SE', 'UA'],
                        'regions': [
                            {
                                'continentCode': 'NA',
                                'countryCode': 'CA',
                                'regionCode': 'NL',
                            }
                        ],
                    },
                ),
                call(
                    'PUT',
                    '/geoFilters/9303',
                    data={
                        'filterRulesLimit': 100,
                        'name': 'unit.tests.:www.dynamic:A:two',
                        'geoipContinents': ['default'],
                    },
                ),
                call('GET', '/domains/123123'),
                call(
                    'POST',
                    '/domains/123123/records/A',
                    data={
                        'name': 'www.dynamic',
                        'ttl': 600,
                        'roundRobin': [{'value': '1.2.3.4'}],
                        'geolocation': {'geoipUserRegion': [1]},
                    },
                ),
                call(
                    'POST',
                    '/domains/123123/records/A',
                    data={
                        'name': 'www.dynamic',
                        'note': 'rule-order:0',
                        'ttl': 600,
                        'pools': [1808522],
                        'recordOption': 'pools',
                        'geolocation': {'geoipUserRegion': [5303]},
                    },
                ),
                call(
                    'POST',
                    '/domains/123123/records/A',
                    data={
                        'name': 'www.dynamic',
                        'note': 'rule-order:1',
                        'ttl': 600,
                        'pools': [1808521],
                        'recordOption': 'pools',
                        'geolocation': {'geoipUserRegion': [9303]},
                    },
                ),
            ]
        )

    def test_dynamic_record_failures(self):
        provider = ConstellixProvider('test', 'api', 'secret')

        resp = Mock()
        resp.json = Mock()
        provider._client._request = Mock(return_value=resp)

        # Let's handle some failures for pools - first if it's not a simple
        # weighted pool - we'll be OK as we assume a weight of 1 for all
        # entries
        provider._client._request.reset_mock()
        provider._client.records = Mock(
            return_value=[
                {
                    'id': 1808518,
                    'type': 'A',
                    'name': 'www.dynamic',
                    'geolocation': {'geoipFilter': 1},
                    'ttl': 300,
                    'recordOption': 'roundRobin',
                    'value': ['1.2.3.4'],
                },
                {
                    'id': 1808520,
                    'type': 'A',
                    'name': 'www.dynamic',
                    'note': 'rule-order:0',
                    'geolocation': None,
                    'recordOption': 'pools',
                    'ttl': 300,
                    'value': [],
                    'pools': [1808521],
                },
            ]
        )

        provider._client.pools = Mock(
            return_value=[
                {
                    'id': 1808521,
                    'name': 'unit.tests.:www.dynamic:A:two',
                    'type': 'A',
                    'values': [{'value': '1.2.3.4', 'weight': 1}],
                }
            ]
        )

        provider._client.geofilters = Mock(return_value=[])

        wanted = Zone('unit.tests.', [])

        resp.json.side_effect = [['{}'], ['{}']]
        wanted.add_record(
            Record.new(
                wanted,
                'www.dynamic',
                {
                    'ttl': 300,
                    'type': 'A',
                    'values': ['1.2.3.4'],
                    'dynamic': {
                        'pools': {'two': {'values': [{'value': '1.2.3.4'}]}},
                        'rules': [{'pool': 'two'}],
                    },
                },
            )
        )

        plan = provider.plan(wanted)
        self.assertIsNone(plan)

    def test_dynamic_record_updates(self):
        provider = ConstellixProvider(
            'test', 'api', 'secret', strict_supports=False
        )

        # Constellix API can return an error if you try and update a pool and
        # don't change anything, so let's test we handle it silently

        provider._client.records = Mock(
            return_value=[
                {
                    'id': 1808520,
                    'type': 'A',
                    'name': 'www.dynamic',
                    'note': 'rule-order:0',
                    'geolocation': {'geoipFilter': 1},
                    'recordOption': 'pools',
                    'ttl': 300,
                    'value': [],
                    'pools': [1808521],
                },
                {
                    'id': 1808521,
                    'type': 'A',
                    'name': 'www.dynamic',
                    'note': 'rule-order:1',
                    'geolocation': {'geoipFilter': 5303},
                    'recordOption': 'pools',
                    'ttl': 300,
                    'value': [],
                    'pools': [1808522],
                },
            ]
        )

        provider._client.pools = Mock(
            return_value=[
                {
                    'id': 1808521,
                    'name': 'unit.tests.:www.dynamic:A:two',
                    'type': 'A',
                    'values': [
                        {'value': '1.2.3.4', 'weight': 1},
                        {'value': '1.2.3.5', 'weight': 1},
                    ],
                },
                {
                    'id': 1808522,
                    'name': 'unit.tests.:www.dynamic:A:one',
                    'type': 'A',
                    'values': [
                        {'value': '1.2.3.6', 'weight': 1},
                        {'value': '1.2.3.7', 'weight': 1},
                    ],
                },
            ]
        )

        provider._client.geofilters = Mock(
            return_value=[
                {
                    'id': 1,
                    'name': 'World (Default)',
                    'geoipContinents': ['default'],
                },
                {
                    'id': 6303,
                    'name': 'some.other',
                    'filterRulesLimit': 100,
                    'createdTs': '2021-08-19T14:47:47Z',
                    'modifiedTs': '2021-08-19T14:47:47Z',
                    'geoipContinents': ['AS', 'OC'],
                    'geoipCountries': ['ES', 'SE', 'UA'],
                    'regions': [
                        {
                            'continentCode': 'NA',
                            'countryCode': 'CA',
                            'regionCode': 'NL',
                        }
                    ],
                },
                {
                    'id': 5303,
                    'name': 'unit.tests.:www.dynamic:A:one',
                    'filterRulesLimit': 100,
                    'geoipContinents': ['AS', 'OC'],
                    'geoipCountries': ['ES', 'SE', 'UA'],
                    'regions': [
                        {
                            'continentCode': 'NA',
                            'countryCode': 'CA',
                            'regionCode': 'NL',
                        }
                    ],
                },
                {
                    'id': 9303,
                    'name': 'unit.tests.:www.dynamic:A:two',
                    'filterRulesLimit': 100,
                    'geoipContinents': ['default'],
                },
            ]
        )

        wanted = Zone('unit.tests.', [])

        wanted.add_record(
            Record.new(
                wanted,
                'www.dynamic',
                {
                    'ttl': 300,
                    'type': 'A',
                    'values': ['1.2.3.4'],
                    'dynamic': {
                        'pools': {
                            'one': {
                                'fallback': 'two',
                                'values': [
                                    {'value': '1.2.3.6', 'weight': 1},
                                    {'value': '1.2.3.7', 'weight': 1},
                                ],
                            },
                            'two': {
                                'values': [{'value': '1.2.3.4', 'weight': 1}]
                            },
                        },
                        'rules': [
                            {
                                'geos': ['AS', 'EU-ES', 'EU-UA', 'EU-SE', 'OC'],
                                'pool': 'one',
                            },
                            {'pool': 'two'},
                        ],
                    },
                },
            )
        )

        # Try an error we can handle
        with requests_mock() as mock:
            mock.get(
                'https://api.dns.constellix.com/v1/domains',
                status_code=200,
                text='[{"id": 1234, "name": "unit.tests", "hasGeoIP": true}]',
            )
            mock.get(
                'https://api.dns.constellix.com/v1/domains/1234',
                status_code=200,
                text='{"id": 1234, "name": "unit.tests", "hasGeoIP": true}',
            )
            mock.delete(ANY, status_code=200, text='{}')
            mock.put(
                'https://api.dns.constellix.com/v1/pools/A/1808521',
                status_code=400,
                text='{"errors": [\"no changes to save\"]}',
            )
            mock.put(
                'https://api.dns.constellix.com/v1/pools/A/1808522',
                status_code=400,
                text='{"errors": [\"no changes to save\"]}',
            )
            mock.put(
                'https://api.dns.constellix.com/v1/geoFilters/5303',
                status_code=400,
                text='{"errors": [\"no changes to save\"]}',
            )
            mock.put(
                'https://api.dns.constellix.com/v1/geoFilters/9303',
                status_code=400,
                text='{"errors": [\"no changes to save\"]}',
            )
            mock.post(ANY, status_code=200, text='[{"id": 1234}]')

            plan = provider.plan(wanted)
            self.assertEqual(1, len(plan.changes))
            self.assertEqual(1, provider.apply(plan))

            provider._client.geofilters = Mock(
                return_value=[
                    {
                        'id': 1,
                        'name': 'World (Default)',
                        'geoipContinents': ['default'],
                    },
                    {
                        'id': 5303,
                        'name': 'unit.tests.:www.dynamic:A:one',
                        'filterRulesLimit': 100,
                        'regions': [
                            {
                                'continentCode': 'NA',
                                'countryCode': 'CA',
                                'regionCode': 'NL',
                            }
                        ],
                    },
                    {
                        'id': 9303,
                        'name': 'unit.tests.:www.dynamic:A:two',
                        'filterRulesLimit': 100,
                        'geoipContinents': ['default'],
                    },
                ]
            )

            plan = provider.plan(wanted)
            self.assertEqual(1, len(plan.changes))
            self.assertEqual(1, provider.apply(plan))

            provider._client.geofilters = Mock(
                return_value=[
                    {
                        'id': 1,
                        'name': 'World (Default)',
                        'geoipContinents': ['default'],
                    },
                    {
                        'id': 5303,
                        'name': 'unit.tests.:www.dynamic:A:one',
                        'filterRulesLimit': 100,
                        'geoipContinents': ['AS', 'OC'],
                    },
                    {
                        'id': 9303,
                        'name': 'unit.tests.:www.dynamic:A:two',
                        'filterRulesLimit': 100,
                        'geoipContinents': ['default'],
                    },
                ]
            )

            plan = provider.plan(wanted)
            self.assertEqual(1, len(plan.changes))
            self.assertEqual(1, provider.apply(plan))

        # Now what happens if an error happens that we can't handle
        # geofilter case
        with requests_mock() as mock:
            mock.get(
                'https://api.dns.constellix.com/v1/domains',
                status_code=200,
                text='[{"id": 1234, "name": "unit.tests", "hasGeoIP": true}]',
            )
            mock.get(
                'https://api.dns.constellix.com/v1/domains/1234',
                status_code=200,
                text='{"id": 1234, "name": "unit.tests", "hasGeoIP": true}',
            )
            mock.delete(ANY, status_code=200, text='{}')
            mock.put(
                'https://api.dns.constellix.com/v1/pools/A/1808521',
                status_code=400,
                text='{"errors": [\"no changes to save\"]}',
            )
            mock.put(
                'https://api.dns.constellix.com/v1/pools/A/1808522',
                status_code=400,
                text='{"errors": [\"no changes to save\"]}',
            )
            mock.put(
                'https://api.dns.constellix.com/v1/geoFilters/5303',
                status_code=400,
                text='{"errors": [\"generic error\"]}',
            )
            mock.post(ANY, status_code=200, text='[{"id": 1234}]')

            plan = provider.plan(wanted)
            self.assertEqual(1, len(plan.changes))
            with self.assertRaises(ConstellixAPIBadRequest):
                provider.apply(plan)

        # Now what happens if an error happens that we can't handle
        with requests_mock() as mock:
            mock.get(
                'https://api.dns.constellix.com/v1/domains',
                status_code=200,
                text='[{"id": 1234, "name": "unit.tests", "hasGeoIP": true}]',
            )
            mock.get(
                'https://api.dns.constellix.com/v1/domains/1234',
                status_code=200,
                text='{"id": 1234, "name": "unit.tests", "hasGeoIP": true}',
            )
            mock.delete(ANY, status_code=200, text='{}')
            mock.put(
                'https://api.dns.constellix.com/v1/pools/A/1808521',
                status_code=400,
                text='{"errors": [\"generic error\"]}',
            )
            mock.put(
                'https://api.dns.constellix.com/v1/pools/A/1808522',
                status_code=400,
                text='{"errors": [\"generic error\"]}',
            )
            mock.put(
                'https://api.dns.constellix.com/v1/geoFilters/5303',
                status_code=400,
                text='{"errors": [\"generic error\"]}',
            )
            mock.post(ANY, status_code=200, text='[{"id": 1234}]')

            plan = provider.plan(wanted)
            self.assertEqual(1, len(plan.changes))
            with self.assertRaises(ConstellixAPIBadRequest):
                provider.apply(plan)

    def test_pools_that_are_notfound(self):
        provider = ConstellixProvider('test', 'api', 'secret')

        provider._client.pools = Mock(
            return_value=[
                {
                    'id': 1808521,
                    'name': 'unit.tests.:www.dynamic:A:two',
                    'type': 'A',
                    'values': [{'value': '1.2.3.4', 'weight': 1}],
                }
            ]
        )

        self.assertIsNone(provider._client.pool_by_id('A', 1))
        self.assertIsNone(provider._client.pool('A', 'foobar'))

    def test_pools_are_cached_correctly(self):
        provider = ConstellixProvider('test', 'api', 'secret')

        provider._client.pools = Mock(
            return_value=[
                {
                    'id': 1808521,
                    'name': 'unit.tests.:www.dynamic:A:two',
                    'type': 'A',
                    'values': [{'value': '1.2.3.4', 'weight': 1}],
                }
            ]
        )

        found = provider._client.pool('A', 'unit.tests.:www.dynamic:A:two')
        self.assertIsNotNone(found)

        not_found = provider._client.pool(
            'AAAA', 'unit.tests.:www.dynamic:A:two'
        )
        self.assertIsNone(not_found)

        provider._client.pools = Mock(
            return_value=[
                {
                    'id': 42,
                    'name': 'unit.tests.:www.dynamic:A:two',
                    'type': 'A',
                    'values': [{'value': '1.2.3.4', 'weight': 1}],
                },
                {
                    'id': 451,
                    'name': 'unit.tests.:www.dynamic:A:two',
                    'type': 'AAAA',
                    'values': [{'value': '1.2.3.4', 'weight': 1}],
                },
            ]
        )

        a_pool = provider._client.pool('A', 'unit.tests.:www.dynamic:A:two')
        self.assertEqual(42, a_pool['id'])

        aaaa_pool = provider._client.pool(
            'AAAA', 'unit.tests.:www.dynamic:A:two'
        )
        self.assertEqual(451, aaaa_pool['id'])

    def test_global_geofilter_untouched(self):
        provider = ConstellixProvider('test', 'api', 'secret')

        global_geofilter = {
            'id': 1,
            'name': 'World (Default)',
            'geoipContinents': ['default'],
        }

        resp = Mock()
        resp.json = Mock()
        provider._client._request = Mock(return_value=resp)

        resp_side_effect = [
            [
                {
                    'id': 1,
                    'name': 'World (Default)',
                    'geoipContinents': ['default'],
                }
            ],  # geofilters returned
            [],
        ]
        resp.json.side_effect = resp_side_effect

        result = provider._create_update_geofilter(
            'World (Default)', ['EU'], [], [{'continentCode': 'EU'}]
        )
        self.assertEqual(global_geofilter, result)

    def test_unsupported_geo_warn(self):
        provider = ConstellixProvider(
            'test', 'api', 'secret', strict_supports=False
        )
        zone = Zone('unit.tests.', [])

        with self.assertLogs() as captured:
            with requests_mock() as mock:
                base = 'https://api.dns.constellix.com/v1'
                with open('tests/fixtures/constellix-domains.json') as fh:
                    mock.get(f'{base}/domains', text=fh.read())
                with open('tests/fixtures/constellix-records-geo.json') as fh:
                    mock.get(f'{base}/domains/123123/records', text=fh.read())
                with open('tests/fixtures/constellix-geofilters.json') as fh:
                    mock.get(f'{base}/geoFilters', text=fh.read())
                mock.get(f'{base}/pools/A', text='')
                with open('tests/fixtures/constellix-geofilters.json') as fh:
                    mock.get(f'{base}/geoFilters', text=fh.read())

                provider.populate(zone)
            self.assertEqual(len(captured.records), 3)
            self.assertEqual(
                captured.records[0].getMessage(),
                "unsupported geofilter 5303 on non-pool record; "
                "will ignore the geo filter",
            )
            self.assertEqual(
                captured.records[1].getMessage(),
                "unsupported geo configuration; "
                "will use global default only",
            )
            self.assertEqual(
                captured.records[2].getMessage(),
                "populate:   found 1 records, exists=True",
            )

    def test_unsupported_geo_strict(self):
        provider = ConstellixProvider('test', 'api', 'secret')
        zone = Zone('unit.tests.', [])

        provider.strict_supports = True

        with self.assertRaises(SupportsException) as context:
            with requests_mock() as mock:
                base = 'https://api.dns.constellix.com/v1'
                with open('tests/fixtures/constellix-domains.json') as fh:
                    mock.get(f'{base}/domains', text=fh.read())
                with open('tests/fixtures/constellix-records-geo.json') as fh:
                    mock.get(f'{base}/domains/123123/records', text=fh.read())
                with open('tests/fixtures/constellix-geofilters.json') as fh:
                    mock.get(f'{base}/geoFilters', text=fh.read())
                mock.get(f'{base}/pools/A', text='')
                with open('tests/fixtures/constellix-geofilters.json') as fh:
                    mock.get(f'{base}/geoFilters', text=fh.read())

                provider.populate(zone)
        self.assertEqual(
            str(context.exception),
            "test: " "unsupported geofilter 5303 on non-pool record",
        )

    def test_unsupported_multi_warn(self):
        provider = ConstellixProvider(
            'test', 'api', 'secret', strict_supports=False
        )
        zone = Zone('unit.tests.', [])

        with self.assertLogs() as captured:
            with requests_mock() as mock:
                base = 'https://api.dns.constellix.com/v1'
                with open('tests/fixtures/constellix-domains.json') as fh:
                    mock.get(f'{base}/domains', text=fh.read())
                with open(
                    'tests/fixtures/constellix-records-multi-gtd.json'
                ) as fh:
                    mock.get(f'{base}/domains/123123/records', text=fh.read())
                mock.get(f'{base}/pools/A', text='')
                mock.get(f'{base}/geoFilters', text='')

                provider.populate(zone)
            self.assertEqual(len(captured.records), 2)
            self.assertEqual(
                captured.records[0].getMessage(),
                "unsupported multiple entries; "
                "will use first value ['2.2.3.4', '2.2.3.5']",
            )
            self.assertEqual(
                captured.records[1].getMessage(),
                "populate:   found 1 records, exists=True",
            )


class TestConstellixClient(TestCase):
    def test_unknown_geofilter(self):
        log = logging.getLogger('client')
        client = ConstellixClient(log, 'api', 'secret')

        resp = Mock()
        resp.json = Mock()
        client._request = Mock(return_value=resp)
        resp_side_effect = [[]]  # GET /geoFilters
        resp.json.side_effect = resp_side_effect

        self.assertIsNone(client.geofilter_by_id(9999999))


class TestConstellixAPI(TestCase):
    def test_v1_v2_sonar_auth(self):
        log = logging.getLogger('client')
        api_key = 'api'
        secret_key = 'test'
        time.time = Mock(return_value=1234567890.1234)
        for base_url in [
            'https://api.dns.constellix.com/v1',
            'https://api.dns.constellix.com/v2',
            'https://api.sonar.constellix.com/rest/api',
        ]:
            api = ConstellixAPI(base_url, log, api_key, secret_key, 0.0)

            auth_header = api._auth_header()
            auth_token = auth_header.get('x-cns-security-token', None)
            self.assertIsNotNone(auth_token)
            self.assertIsNone(auth_header.get('authorization', None))

            parts = auth_token.split(':')
            self.assertEqual(3, len(parts))

            self.assertEqual(api_key, parts[0])
            self.assertEqual('S5VaK5DN7gpfTGh1975BlT6xw7k=', parts[1])
            self.assertEqual(str(int(time.time() * 1000)), parts[2])

    def test_v4_sonar_auth(self):
        pass
        log = logging.getLogger('client')
        api_key = 'api'
        secret_key = 'test'
        time.time = Mock(return_value=1234567890.1234)

        api = ConstellixAPI(
            'https://api.dns.constellix.com/v4', log, api_key, secret_key, 0.0
        )

        auth_header = api._auth_header()
        auth_value = auth_header.get('Authorization', None)
        bearer_prefix = 'Bearer '
        self.assertIsNotNone(auth_value)
        self.assertIsNone(auth_header.get('x-cns-security-token', None))
        self.assertTrue(auth_value.startswith(bearer_prefix))

        auth_token = auth_value[len(bearer_prefix) :]

        parts = auth_token.split(':')
        self.assertEqual(3, len(parts))

        self.assertEqual(api_key, parts[0])
        self.assertEqual('S5VaK5DN7gpfTGh1975BlT6xw7k=', parts[1])
        self.assertEqual(str(int(time.time() * 1000)), parts[2])
