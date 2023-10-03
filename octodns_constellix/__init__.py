#
#
#

import hashlib
import hmac
import json
import logging
import time
from base64 import b64encode, standard_b64encode
from collections import defaultdict

from pycountry_convert import country_alpha2_to_continent_code
from requests import Session
from requests_cache import CachedSession

from octodns import __VERSION__ as octodns_version
from octodns.provider import ProviderException
from octodns.provider.base import BaseProvider
from octodns.record import Record

__VERSION__ = '0.0.4'


class ConstellixClientException(ProviderException):
    pass


class ConstellixClientBadRequest(ConstellixClientException):
    def __init__(self, data):
        errors = '\n  - '.join(data.get('errors', []))
        super().__init__(f'\n  - {errors}')


class ConstellixClientUnauthorized(ConstellixClientException):
    def __init__(self):
        super().__init__('Unauthorized')


class ConstellixClientNotFound(ConstellixClientException):
    def __init__(self):
        super().__init__('Not Found')


class ConstellixClient(object):
    BASE = 'https://api.dns.constellix.com/v1'

    def __init__(self, log, api_key, secret_key, ratelimit_delay=0.0):
        self.log = log
        self.api_key = api_key
        self.secret_key = secret_key
        self.ratelimit_delay = ratelimit_delay
        self._sess = Session()
        self._sess.headers.update(
            {
                'x-cnsdns-apiKey': self.api_key,
                'User-Agent': f'octodns/{octodns_version} octodns-constellix/{__VERSION__}',
            }
        )
        self._domains = None
        self._pools = {'A': None, 'AAAA': None, 'CNAME': None}
        self._geofilters = None

    def _current_time(self):
        return str(int(time.time() * 1000))

    def _hmac_hash(self, now):
        return hmac.new(
            self.secret_key.encode('utf-8'),
            now.encode('utf-8'),
            digestmod=hashlib.sha1,
        ).digest()

    def _request(self, method, path, params=None, data=None):
        self.log.debug("Call _request %s %s", method, path)
        now = self._current_time()
        hmac_hash = self._hmac_hash(now)

        headers = {
            'x-cnsdns-hmac': b64encode(hmac_hash),
            'x-cnsdns-requestDate': now,
        }

        url = f'{self.BASE}{path}'
        resp = self._sess.request(
            method, url, headers=headers, params=params, json=data
        )
        if resp.status_code == 400:
            raise ConstellixClientBadRequest(resp.json())
        if resp.status_code == 401:
            raise ConstellixClientUnauthorized()
        if resp.status_code == 404:
            raise ConstellixClientNotFound()
        resp.raise_for_status()
        time.sleep(self.ratelimit_delay)
        return resp

    @property
    def domains(self):
        if self._domains is None:
            self.log.debug('fetch domains')
            zones = []

            resp = self._request('GET', '/domains').json()
            zones += resp

            self._domains = {f'{z["name"]}.': z['id'] for z in zones}

        return self._domains

    def domain(self, name):
        self.log.debug('domain %s', name)
        zone_id = self.domains.get(name, False)
        if not zone_id:
            raise ConstellixClientNotFound()
        path = f'/domains/{zone_id}'
        return self._request('GET', path).json()

    def domain_create(self, name):
        self.log.debug('domain_create %s', name)
        resp = self._request('POST', '/domains', data={'names': [name]}).json()
        # Add newly created zone to domain cache
        self._domains[f'{name}.'] = resp[0]['id']
        return resp

    def domain_enable_geoip(self, domain_name):
        domain = self.domain(domain_name)
        if domain['hasGeoIP'] is False:
            domain_id = self.domains[domain_name]
            return self._request(
                'PUT', f'/domains/{domain_id}', data={'hasGeoIP': True}
            ).json()

    def _absolutize_value(self, value, zone_name):
        if value == '':
            value = zone_name
        elif not value.endswith('.'):
            value = f'{value}.{zone_name}'

        return value

    def records(self, zone_name):
        zone_id = self.domains.get(zone_name, False)
        if not zone_id:
            raise ConstellixClientNotFound()
        path = f'/domains/{zone_id}/records'

        resp = self._request('GET', path).json()
        for record in resp:
            # change ANAME records to ALIAS
            if record['type'] == 'ANAME':
                record['type'] = 'ALIAS'

            # change relative values to absolute
            value = record['value']
            if record['type'] in ['ALIAS', 'CNAME', 'MX', 'NS', 'SRV']:
                if isinstance(value, str):
                    record['value'] = self._absolutize_value(value, zone_name)
                if isinstance(value, list):
                    for v in value:
                        v['value'] = self._absolutize_value(
                            v['value'], zone_name
                        )

        return resp

    def record_create(self, zone_name, record_type, params):
        # change ALIAS records to ANAME
        if record_type == 'ALIAS':
            record_type = 'ANAME'

        zone_id = self.domains.get(zone_name, False)
        path = f'/domains/{zone_id}/records/{record_type}'

        return self._request('POST', path, data=params).json()

    def record_delete(self, zone_name, record_type, record_id):
        # change ALIAS records to ANAME
        if record_type == 'ALIAS':
            record_type = 'ANAME'

        zone_id = self.domains.get(zone_name, False)
        path = f'/domains/{zone_id}/records/{record_type}/{record_id}'
        return self._request('DELETE', path).json()

    def pool_update_cache(self, pool_type, pool_id, value):
        # Create cache for pool_type if needed
        if value is not None and self._pools[pool_type] is None:
            self._pools[pool_type] = {}

        if self._pools[pool_type] is not None:
            self._pools[pool_type][pool_id] = value

    def pool_clear_cache(self, pool_type, pool_id):
        self.log.debug('pool_clear_cache %s %d', pool_type, pool_id)
        self.pool_update_cache(pool_type, pool_id, None)

    def pool_get_cache(self, pool_type):
        if self._pools[pool_type] is None:
            return []
        else:
            return self._pools[pool_type].values()

    def pools(self, pool_type):
        self.log.debug('pools %s', pool_type)
        # The list view does not return checkId, policy and other details
        result = self.pool_get_cache(pool_type)
        if 0 == len(self.pool_get_cache(pool_type)):
            path = f'/pools/{pool_type}'
            response = self._request('GET', path).json()
            for pool in response:
                self.pool_update_cache(pool_type, pool['id'], pool)
            result = self.pool_get_cache(pool_type)
        return result

    def pool_by_id(self, pool_type, pool_id):
        self.log.debug('pool_by_id %s %d', pool_type, pool_id)
        pools = self.pools(pool_type)
        result = None
        for pool in pools:
            if pool['id'] == pool_id:
                result = pool
                break

        # We do not have the details yet, fetch the pool.
        # Do not try to fetch details for something that is not in the list.
        if result is not None and result.get('failedFlag', None) is None:
            path = f'/pools/{pool_type}/{pool_id}'
            result = self._request('GET', path).json()
            self._pools[pool_type][pool['id']] = result

        return result

    def pool_by_name(self, pool_type, pool_name):
        self.log.debug('pool_by_name %s %s', pool_type, pool_name)
        pools = self.pools(pool_type)
        for pool in pools:
            if pool['name'] == pool_name and pool['type'] == pool_type:
                return self.pool_by_id(pool_type, pool['id'])
        return None

    def pool_create(self, data):
        self.log.debug('pool_create %s', json.dumps(data))
        pool_type = data.get('type')
        path = f'/pools/{pool_type}'

        # This returns a list of items, we want the first (and single) one
        response = self._request('POST', path, data=data).json()

        # Unexpected response that does not contain exactly one entry
        if 1 != len(response):
            raise ConstellixClientException(response)

        response = response[0]

        # Update our cache
        self.pool_update_cache(pool_type, response['id'], response)
        return response

    def pool_update(self, pool_type, pool_id, data):
        self.log.debug('pool_update %s', json.dumps(data))
        # Note that PUT does not return the new value, but only a success string
        path = f'/pools/{pool_type}/{pool_id}'

        try:
            # This may throw a ConstellixClientBadRequest or return a status
            response = self._request('PUT', path, data=data)
            data = response.json()

            # Status does not contain success message
            if not data.get('success', False):
                raise ConstellixClientBadRequest(data)

            # We had a real change - clear the cache
            self.pool_clear_cache(pool_type, pool_id)

        except ConstellixClientBadRequest as e:
            # This is either due to a NOOP or to a real failure
            message = str(e)
            if not message or (
                "no changes to save" not in message
                and "are identical" not in message
            ):
                raise e

        return self.pool_by_id(pool_type, pool_id)

    def pool_delete(self, pool_type, pool_id):
        path = f'/pools/{pool_type}/{pool_id}'
        resp = self._request('DELETE', path).json()

        # Clear the cache entry
        self.pool_clear_cache(pool_type, pool_id)

        return resp

    def geofilters(self):
        if self._geofilters is None:
            self._geofilters = {}
            path = '/geoFilters'
            response = self._request('GET', path).json()
            for geofilter in response:
                self._geofilters[geofilter['id']] = geofilter
        return self._geofilters.values()

    def geofilter(self, geofilter_name):
        geofilters = self.geofilters()
        for geofilter in geofilters:
            if geofilter['name'] == geofilter_name:
                return geofilter
        return None

    def geofilter_by_id(self, geofilter_id):
        geofilters = self.geofilters()
        for geofilter in geofilters:
            if geofilter['id'] == geofilter_id:
                return geofilter
        return None

    def geofilter_create(self, data):
        path = '/geoFilters'
        response = self._request('POST', path, data=data).json()

        # Update our cache
        self._geofilters[response[0]['id']] = response[0]
        return response[0]

    def geofilter_update(self, geofilter_id, data):
        self.log.debug('geofilter_update %d %s', geofilter_id, json.dumps(data))
        # Note that PUT does not return the new value, but only a success string
        path = f'/geoFilters/{geofilter_id}'
        try:
            # This may throw a ConstellixClientBadRequest or return a status
            response = self._request('PUT', path, data=data)
            data = response.json()

            # Status does not contain success message
            if not data.get('success', False):
                raise ConstellixClientBadRequest(data)

            # We had a real change - clear the cache
            self._geofilters.pop(geofilter_id, None)

            # Update the record information
            path = f'/geoFilters/{geofilter_id}'
            data = self._request('GET', path).json()
            self._geofilters[geofilter_id] = data

        except ConstellixClientBadRequest as e:
            message = str(e)
            if not message or (
                "no changes to save" not in message
                and "are identical" not in message
            ):
                raise e

        return self.geofilter_by_id(geofilter_id)

    def geofilter_delete(self, geofilter_id):
        path = f'/geoFilters/{geofilter_id}'
        resp = self._request('DELETE', path).json()

        # Update our cache
        if self._geofilters is not None:
            self._geofilters.pop(geofilter_id, None)
        return resp


class SonarClientException(ProviderException):
    pass


class SonarClientBadRequest(SonarClientException):
    def __init__(self, resp):
        errors = resp.text
        super().__init__(f'\n  - {errors}')


class SonarClientUnauthorized(SonarClientException):
    def __init__(self):
        super().__init__('Unauthorized')


class SonarClientNotFound(SonarClientException):
    def __init__(self):
        super().__init__('Not Found')


class SonarClient(object):
    BASE = 'https://api.sonar.constellix.com/rest/api'

    def __init__(self, log, api_key, secret_key, ratelimit_delay=0.0):
        self.log = log
        self.api_key = api_key
        self.secret_key = secret_key
        self.ratelimit_delay = ratelimit_delay
        self._sess = CachedSession(
            backend='memory',
            allowable_methods=['GET', 'HEAD'],
            allowable_codes=[200],
            ignored_parameters=['x-cns-security-token'],
        )
        self._sess.headers = {
            'Content-Type': 'application/json',
            'User-Agent': f'octodns/{octodns_version} octodns-constellix/{__VERSION__}',
        }
        self._checks = {'tcp': None, 'http': None}

    def _current_time_ms(self):
        return str(int(time.time() * 1000))

    def _hmac_hash(self, now):
        digester = hmac.new(
            bytes(self.secret_key, "UTF-8"), bytes(now, "UTF-8"), hashlib.sha1
        )
        signature = digester.digest()
        hmac_text = str(standard_b64encode(signature), "UTF-8")
        return hmac_text

    def _url(self, path):
        return f'{self.BASE}{path}'

    def _request(self, method, path, params=None, data=None):
        self.log.debug('sonar._request %s %s', method, path)
        now = self._current_time_ms()
        hmac_text = self._hmac_hash(now)

        headers = {
            'x-cns-security-token': "{}:{}:{}".format(
                self.api_key, hmac_text, now
            )
        }

        resp = self._sess.request(
            method, self._url(path), headers=headers, params=params, json=data
        )

        self.log.debug('sonar._request response %d', resp.status_code)
        if resp.status_code == 400:
            raise SonarClientBadRequest(resp)
        if resp.status_code == 401:
            raise SonarClientUnauthorized()
        if resp.status_code == 404:
            raise SonarClientNotFound()
        resp.raise_for_status()

        if self.ratelimit_delay >= 1.0:
            self.log.info("Waiting for Sonar Rate Limit Delay")
        elif self.ratelimit_delay > 0.0:
            self.log.debug("Waiting for Sonar Rate Limit Delay")
        time.sleep(self.ratelimit_delay)

        return resp.json(), resp.headers, resp.from_cache

    @property
    def agents(self):
        self.log.debug('sonar.agents')
        data, headers, cached = self._request('GET', '/system/sites')
        return {f'{a["name"]}.': a for a in data}

    def agents_for_regions(self, regions):
        if regions[0] == "WORLD":
            res_agents = []
            for agent in self.agents.values():
                res_agents.append(agent['id'])
            return res_agents

        res_agents = []
        for agent in self.agents.values():
            if agent["region"] in regions:
                res_agents.append(agent['id'])
        return res_agents

    def parse_uri_id(self, url):
        r = str(url).rfind("/")
        res = str(url)[r + 1 :]
        return res

    def checks(self, check_type):
        self.log.debug('sonar.checks %s', check_type)
        if self._checks[check_type] is None:
            self.log.debug('sonar.checks %s fetch', check_type)
            self._checks[check_type] = {}
            path = f'/{check_type}'
            data, headers, cached = self._request('GET', path)
            self.log.debug(
                'sonar.checks %s data %s', check_type, json.dumps(data)
            )
            for check in data:
                self._checks[check_type][check['id']] = check
        return self._checks[check_type].values()

    def check(self, check_type, check_name):
        self.log.debug('sonar.check %s %s', check_type, check_name)
        checks = self.checks(check_type)
        for check in checks:
            if check['name'] == check_name:
                return check
        return None

    def check_create(self, check_type, data):
        self.log.debug('sonar.check_create %s %s', check_type, json.dumps(data))
        path = f'/{check_type}'
        data, headers, cached = self._request('POST', path, data=data)
        self.log.debug(
            'check_create response %s headers %s',
            json.dumps(data),
            json.dumps(dict(headers)),
        )

        # Parse check ID from Location response header
        check_id = self.parse_uri_id(headers['Location'])
        # Get check details
        path = f'/{check_type}/{check_id}'
        data, headers, cached = self._request('GET', path)

        # Update our cache
        self._checks[check_type][check_id] = data
        return data

    def check_delete(self, check_type, check_id):
        self.log.debug('sonar.check_delete %s %d', check_type, check_id)

        path = f'/{check_type}/{check_id}'
        self._request('DELETE', path)

        # Update our cache
        self._checks[check_type].pop(check_id, None)


class ConstellixProvider(BaseProvider):
    '''
    Constellix DNS provider

    constellix:
        class: octodns.provider.constellix.ConstellixProvider
        # Your Contellix api key (required)
        api_key: env/CONSTELLIX_API_KEY
        # Your Constellix secret key (required)
        secret_key: env/CONSTELLIX_SECRET_KEY
        # Amount of time to wait between requests to avoid
        # ratelimit (optional)
        ratelimit_delay: 0.0
    '''

    SUPPORTS_GEO = False
    SUPPORTS_DYNAMIC = True
    SUPPORTS_POOL_VALUE_STATUS = True
    SUPPORTS_ROOT_NS = False
    SUPPORTS = set(
        (
            'A',
            'AAAA',
            'ALIAS',
            'CAA',
            'CNAME',
            'MX',
            'NS',
            'PTR',
            'SPF',
            'SRV',
            'TXT',
        )
    )

    _POOL_STATUS_TO_POLICY = {
        'down': 'alwaysoff',
        'obey': 'followsonar',
        'up': 'alwayson',
    }
    _POOL_POLICY_TO_STATUS = {
        'alwaysoff': 'down',
        'alwayson': 'up',
        'followsonar': 'obey',
    }

    def __init__(
        self, id, api_key, secret_key, ratelimit_delay=0.0, *args, **kwargs
    ):
        self.log = logging.getLogger(f'ConstellixProvider[{id}]')
        self.log.debug('__init__: id=%s, api_key=***, secret_key=***', id)
        super().__init__(id, *args, **kwargs)
        self._client = ConstellixClient(
            self.log, api_key, secret_key, ratelimit_delay
        )
        self._sonar = SonarClient(
            self.log, api_key, secret_key, ratelimit_delay
        )
        self._zone_records = {}

    def _encode_notes(self, data):
        return ' '.join([f'{k}:{v}' for k, v in sorted(data.items())])

    def _parse_notes(self, note):
        data = {}
        if note:
            for piece in note.split(' '):
                try:
                    k, v = piece.split(':', 1)
                except ValueError:
                    continue
                try:
                    v = int(v)
                except ValueError:
                    pass
                data[k] = v if v != '' else None
        return data

    def _data_for_multiple(self, _type, records):
        if 1 == len(records):
            record = records[0]
            return {
                'ttl': record['ttl'],
                'type': _type,
                'values': record['value'],
            }
        return self._data_for_pools(_type, records)

    def _data_for_pool(self, _type, record, pools):
        pool_id = record['pools'][0]
        pool = self._client.pool_by_id(_type, pool_id)
        pool_name = pool['name'].split(':')[-1]

        pool_data = {'fallback': None, 'values': []}
        for value in pool['values']:
            pool_data['values'].append(
                {
                    'value': value['value'],
                    'weight': value['weight'],
                    'status': self._POOL_POLICY_TO_STATUS[
                        value.get('policy', 'obey')
                    ],
                }
            )
        pools[pool_name] = pool_data
        return pool_name

    def _data_for_pools(self, _type, records):
        default_values = []
        pools = {}
        rules = {}

        for record in records:
            if record['recordOption'] == 'pools':
                pool_name = self._data_for_pool(_type, record, pools)
                geofilter_id = 1
                if (
                    'geolocation' in record.keys()
                    and record['geolocation'] is not None
                ):
                    # fetch record geofilter data
                    geofilter_id = record['geolocation']['geoipFilter']

                # fetch options
                notes = self._parse_notes(record.get('note', ''))

                # For backwards compatibility we'll default to adding an order
                # of 0 when rules were written by older versions that predated
                # notes w/rule-order. The next time they're updated they'll have
                # the correct rule-order values written and the fallback will no
                # longer happen
                rule_order = notes.get('rule-order', 0)
                try:
                    rule = rules[rule_order]
                except KeyError:
                    rule = {'pool': pool_name, '_order': rule_order}
                    rules[rule_order] = rule

                if geofilter_id != 1:
                    geofilter = self._client.geofilter_by_id(geofilter_id)
                    geos = set()

                    if 'geoipContinents' in geofilter.keys():
                        for continent_code in geofilter['geoipContinents']:
                            geos.add(continent_code)

                    if 'geoipCountries' in geofilter.keys():
                        for country_code in geofilter['geoipCountries']:
                            continent_code = country_alpha2_to_continent_code(
                                country_code
                            )
                            geos.add(f'{continent_code}-{country_code}')

                    if 'regions' in geofilter.keys():
                        for region in geofilter['regions']:
                            geos.add(
                                f'{region["continentCode"]}-'
                                f'{region["countryCode"]}-'
                                f'{region["regionCode"]}'
                            )
                    if not (1 == len(geos) and 'default' in geos):
                        # There are geos, combine them with any existing geos
                        # for this pool; record the sorted unique set of them
                        rule['geos'] = sorted(set(rule.get('geos', [])) | geos)
            elif (
                'geolocation' in record.keys()
                and record['geolocation'] is not None
            ):
                # fetch record geofilter data
                geofilter_id = record['geolocation']['geoipFilter']
                # fetch default values from the World entry
                if geofilter_id == 1:
                    for value in record['value']:
                        default_values.append(value)
                else:
                    msg = (
                        f'unsupported geofilter {geofilter_id} '
                        f'on non-pool record'
                    )
                    fallback = 'will ignore the geo filter'
                    self.supports_warn_or_except(msg, fallback)
                    record.pop('geolocation', None)
            else:
                msg = 'unsupported multiple entries'
                fallback = f'will use first value {record["value"]}'
                self.supports_warn_or_except(msg, fallback)
                return {
                    'ttl': record['ttl'],
                    'type': _type,
                    'values': record['value'].copy(),
                }

        res = {'ttl': record['ttl'], 'type': _type, 'values': default_values}
        if 0 == len(pools.keys()):
            msg = 'unsupported geo configuration'
            fallback = 'will use global default only'
            self.supports_warn_or_except(msg, fallback)
        else:
            res['dynamic'] = {
                'pools': dict(sorted(pools.items(), key=lambda t: t[0])),
                'rules': sorted(
                    rules.values(), key=lambda t: (t['_order'], t['pool'])
                ),
            }

        return res

    _data_for_A = _data_for_multiple
    _data_for_AAAA = _data_for_multiple

    def _data_for_CAA(self, _type, records):
        values = []
        record = records[0]
        for value in record['value']:
            values.append(
                {
                    'flags': value['flag'],
                    'tag': value['tag'],
                    'value': value['data'],
                }
            )
        return {'ttl': records[0]['ttl'], 'type': _type, 'values': values}

    def _data_for_NS(self, _type, records):
        record = records[0]
        return {
            'ttl': record['ttl'],
            'type': _type,
            'values': [value['value'] for value in record['value']],
        }

    def _data_for_ALIAS(self, _type, records):
        record = records[0]
        return {
            'ttl': record['ttl'],
            'type': _type,
            'value': record['value'][0]['value'],
        }

    _data_for_PTR = _data_for_ALIAS

    def _data_for_TXT(self, _type, records):
        values = [
            value['value'].replace(';', '\\;') for value in records[0]['value']
        ]
        return {'ttl': records[0]['ttl'], 'type': _type, 'values': values}

    _data_for_SPF = _data_for_TXT

    def _data_for_MX(self, _type, records):
        values = []
        record = records[0]
        for value in record['value']:
            values.append(
                {'preference': value['level'], 'exchange': value['value']}
            )
        return {'ttl': records[0]['ttl'], 'type': _type, 'values': values}

    def _data_for_single(self, _type, records):
        record = records[0]
        return {'ttl': record['ttl'], 'type': _type, 'value': record['value']}

    _data_for_CNAME = _data_for_single

    def _data_for_SRV(self, _type, records):
        values = []
        record = records[0]
        for value in record['value']:
            values.append(
                {
                    'port': value['port'],
                    'priority': value['priority'],
                    'target': value['value'],
                    'weight': value['weight'],
                }
            )
        return {'type': _type, 'ttl': records[0]['ttl'], 'values': values}

    def zone_records(self, zone):
        if zone.name not in self._zone_records:
            try:
                self._zone_records[zone.name] = self._client.records(zone.name)
            except ConstellixClientNotFound:
                return []

        return self._zone_records[zone.name]

    def populate(self, zone, target=False, lenient=False):
        self.log.debug(
            'populate: name=%s, target=%s, lenient=%s',
            zone.name,
            target,
            lenient,
        )

        values = defaultdict(lambda: defaultdict(list))
        for record in self.zone_records(zone):
            _type = record['type']
            if _type not in self.SUPPORTS:
                self.log.warning(
                    'populate: skipping unsupported %s record', _type
                )
                continue
            values[record['name']][record['type']].append(record)

        before = len(zone.records)
        for name, types in values.items():
            for _type, records in types.items():
                data_for = getattr(self, f'_data_for_{_type}')
                record = Record.new(
                    zone,
                    name,
                    data_for(_type, records),
                    source=self,
                    lenient=lenient,
                )
                zone.add_record(record, lenient=lenient)

        exists = zone.name in self._zone_records
        self.log.info(
            'populate:   found %s records, exists=%s',
            len(zone.records) - before,
            exists,
        )
        return exists

    def _healthcheck_config(self, record):
        self.log.debug('_healthcheck_config %s', json.dumps(record.data))
        # Backwards compatibility: fetch healthcheck config
        # from octodns.constellix with preference
        sonar_healthcheck = record._octodns.get('constellix', {}).get(
            'healthcheck', {}
        )

        # Use values from constellix.healthcheck (new default) as a fallback
        healthcheck = {
            'port': sonar_healthcheck.get(
                'sonar_port', record.healthcheck_port
            ),
            'type': sonar_healthcheck.get(
                'sonar_type', record.healthcheck_protocol
            ),
        }
        if 'TCP' != healthcheck['type']:
            healthcheck['host'] = record.healthcheck_host
            healthcheck['path'] = record.healthcheck_path

        healthcheck['regions'] = sonar_healthcheck.get(
            'sonar_regions', ['WORLD']
        )
        healthcheck['interval'] = sonar_healthcheck.get(
            'sonar_interval', 'ONEMINUTE'
        )

        return healthcheck

    def _params_for_multiple(self, record):
        yield {
            'name': record.name,
            'ttl': record.ttl,
            'roundRobin': [{'value': value} for value in record.values],
        }

    _params_for_A = _params_for_multiple
    _params_for_AAAA = _params_for_multiple

    # An A record with this name must exist in this domain for
    # this NS record to be valid. Need to handle checking if
    # there is an A record before creating NS
    _params_for_NS = _params_for_multiple

    def _params_for_single(self, record):
        yield {'name': record.name, 'ttl': record.ttl, 'host': record.value}

    _params_for_CNAME = _params_for_single

    def _params_for_ALIAS(self, record):
        yield {
            'name': record.name,
            'ttl': record.ttl,
            'roundRobin': [{'value': record.value, 'disableFlag': False}],
        }

    _params_for_PTR = _params_for_ALIAS

    def _params_for_MX(self, record):
        values = []
        for value in record.values:
            values.append({'value': value.exchange, 'level': value.preference})
        yield {
            'value': value.exchange,
            'name': record.name,
            'ttl': record.ttl,
            'roundRobin': values,
        }

    def _params_for_SRV(self, record):
        values = []
        for value in record.values:
            values.append(
                {
                    'value': value.target,
                    'priority': value.priority,
                    'weight': value.weight,
                    'port': value.port,
                }
            )
        for value in record.values:
            yield {'name': record.name, 'ttl': record.ttl, 'roundRobin': values}

    def _params_for_TXT(self, record):
        # Constellix does not want values escaped
        values = []
        for value in record.chunked_values:
            values.append({'value': value.replace('\\;', ';')})
        yield {'name': record.name, 'ttl': record.ttl, 'roundRobin': values}

    _params_for_SPF = _params_for_TXT

    def _params_for_CAA(self, record):
        values = []
        for value in record.values:
            values.append(
                {'tag': value.tag, 'data': value.value, 'flag': value.flags}
            )
        yield {'name': record.name, 'ttl': record.ttl, 'roundRobin': values}

    def _gen_pool_name(self, record, pool_name):
        return f'{record.zone.name}:{record.name}:{record._type}:{pool_name}'

    def _gen_pool_data(self, record):
        pool_data = {}
        for pool_name, pool in record.dynamic.pools.items():
            values = [
                {
                    'value': value['value'],
                    'weight': value['weight'],
                    'policy': self._POOL_STATUS_TO_POLICY.get(
                        value['status'], 'obey'
                    ),
                }
                for value in pool.data.get('values', [])
            ]
            full_pool_name = self._gen_pool_name(record, pool_name)
            pool_data[full_pool_name] = {
                'pool_name': full_pool_name,
                'pool_type': record._type,
                'values': values,
            }
        return pool_data

    def _create_update_dynamic_healthchecks(self, record, pool_data):
        self.log.debug(
            '_create_update_dynamic_healthchecks %s %s',
            json.dumps(record.data),
            json.dumps(pool_data),
        )
        healthcheck = self._healthcheck_config(record)
        check_sites = self._sonar.agents_for_regions(healthcheck['regions'])

        health_data = {}
        for pool_name, pool in pool_data.items():
            for value in pool['values']:
                self.log.debug('pool %s %s', pool_name, json.dumps(value))
                policy = value.get('policy', 'followsonar')

                check_type = healthcheck['type'].lower()
                check_name = '{}-{}'.format(pool_name, value['value'])
                self.log.debug(
                    'update policy %s %s %s', policy, check_type, check_name
                )
                if policy == 'followsonar':
                    check_obj = self._create_update_check(
                        pool_type=record._type,
                        check_name=check_name,
                        check_type=check_type,
                        value=value['value'],
                        port=healthcheck['port'],
                        interval=healthcheck['interval'],
                        sites=check_sites,
                    )
                    value['checkId'] = check_obj['id']
                    health_data[check_name] = check_obj
                else:
                    self._delete_check(check_type, check_name)

        return pool_data, health_data

    def _create_update_dynamic_pools(self, pool_data, health_data):
        self.log.debug(
            '_create_update_dynamic_pools %s %s',
            json.dumps(pool_data),
            json.dumps(health_data),
        )
        pools = {}
        # TODO: use batch operation here
        for pool_name, pool in pool_data.items():
            # OK, pool is valid, let's create it or update it
            pool_obj = self._create_update_pool(**pool)
            pools[pool_name] = pool_obj
        return pools

    def _create_update_dynamic_rules(self, record):
        rules = {}
        for i, rule in enumerate(record.dynamic.rules):
            pool_name = rule.data.get('pool')
            full_pool_name = self._gen_pool_name(record, pool_name)

            notes = {'rule-order': i}

            geofilter_obj = None
            # Now will create GeoFilter for the pool
            continents = []
            countries = []
            regions = []
            for geo in rule.data.get('geos', []):
                codes = geo.split('-')
                n = len(geo)
                if n == 2:
                    continents.append(geo)
                elif n == 5:
                    countries.append(codes[1])
                else:
                    regions.append(
                        {
                            'continentCode': codes[0],
                            'countryCode': codes[1],
                            'regionCode': codes[2],
                        }
                    )
            geofilter_obj = self._create_update_geofilter(
                full_pool_name, continents, countries, regions
            )
            geofilter_obj['note'] = self._encode_notes(notes)
            rules[full_pool_name] = geofilter_obj

        return rules

    def _create_update_dynamic(self, record):
        # If we don't have dynamic, then there's no pools
        if not getattr(record, 'dynamic', False):
            return {}, {}

        # generate basic pool data
        pool_data = self._gen_pool_data(record)
        # create healthchecks and amend pool data with check ids
        pool_data, health_data = self._create_update_dynamic_healthchecks(
            record, pool_data
        )
        pools = self._create_update_dynamic_pools(pool_data, health_data)
        # create ip filter rules
        rules = self._create_update_dynamic_rules(record)

        # return created or updated pool objects
        return rules, pools

    def _delete_check(self, check_type, check_name):
        self.log.debug('_delete_check %s %s', check_type, check_name)
        if check_type == 'https':
            check_type = 'http'
        existing_check = self._sonar.check(check_type, check_name)
        if existing_check:
            self._sonar.check_delete(check_type, existing_check['id'])

    def _create_update_check(
        self, pool_type, check_name, check_type, value, port, interval, sites
    ):
        self.log.debug('_create_update_check %s', check_name)
        check = {
            'name': check_name,
            'host': value,
            'port': port,
            'checkSites': sites,
            'interval': interval,
        }
        if pool_type == 'AAAA':
            check['ipVersion'] = 'IPV6'
        else:
            check['ipVersion'] = 'IPV4'

        if check_type == 'https':
            check['protocolType'] = 'HTTPS'
            check_type = (
                'http'  # SonarClient and constellix API only know http type
            )

        # FIXME: do not delete then create, but update
        existing_check = self._sonar.check(check_type, check_name)
        if existing_check:
            self._delete_check(check_type, check_name)

        return self._sonar.check_create(check_type, check)

    def _create_update_pool(self, pool_name, pool_type, values):
        self.log.debug(
            '_create_update_pool %s %s %s', pool_type, pool_name, values
        )
        pool = {
            'name': pool_name,
            'type': pool_type,
            'numReturn': 1,
            'minAvailableFailover': 1,
            'values': values,
        }
        existing_pool = self._client.pool_by_name(pool_type, pool_name)
        if existing_pool:
            return self._client.pool_update(
                pool_type, existing_pool['id'], pool
            )
        else:
            return self._client.pool_create(pool)

    def _create_update_geofilter(
        self, geofilter_name, continents, countries, regions
    ):
        continents_len = len(continents)
        countries_len = len(countries)
        regions_len = len(regions)

        # special handling for "World" filters
        if 0 == (continents_len + countries_len + regions_len):
            continents.append('default')
        geofilter = {
            'filterRulesLimit': 100,
            'name': geofilter_name,
            'geoipContinents': continents,
        }
        if 0 != countries_len:
            geofilter['geoipCountries'] = countries
        if 0 != regions_len:
            geofilter['regions'] = regions

        existing_geofilter = self._client.geofilter(geofilter_name)
        if not existing_geofilter:
            return self._client.geofilter_create(geofilter)

        geofilter_id = existing_geofilter['id']
        if 1 == geofilter_id:
            self.log.warning('Ignoring try to modify default geofilter id 1')
            return existing_geofilter

        updated_geofilter = self._client.geofilter_update(
            geofilter_id, geofilter
        )
        updated_geofilter['id'] = geofilter_id
        return updated_geofilter

    def _apply_Create(self, change, domain_name):
        new = change.new
        params_gen = getattr(self, f'_params_for_{new._type}')(new)
        rules, pools = self._create_update_dynamic(new)

        count = 0
        for params in params_gen:
            count = 1 + count
            pool_size = len(pools.keys())
            if pool_size == 0:
                self._client.record_create(new.zone.name, new._type, params)
            else:
                # To use GeoIPFilter feature we need to enable it for domain
                self.log.debug("Enabling domain %s geo support", domain_name)
                self._client.domain_enable_geoip(domain_name)

                # First we need to create World Default (1) Record
                # that uses plain values without a pool
                params['geolocation'] = {'geoipUserRegion': [1]}
                self._client.record_create(new.zone.name, new._type, params)

                # Now we can create the rest of records.
                for pool_name, pool in pools.items():
                    pool_params = {
                        'name': params['name'],
                        'ttl': params['ttl'],
                        'recordOption': 'pools',
                        'pools': [pool['id']],
                    }
                    rule = rules.get(pool_name)
                    if rule:
                        pool_params['geolocation'] = {
                            'geoipUserRegion': [rule['id']]
                        }
                        pool_params['note'] = rule['note']
                    self._client.record_create(
                        new.zone.name, new._type, pool_params
                    )

    def _apply_Update(self, change, domain_name):
        self._apply_Delete(change, domain_name)
        self._apply_Create(change, domain_name)

    def _apply_Delete(self, change, domain_name):
        existing = change.existing
        zone = existing.zone

        # if it is dynamic pools record, we need to delete World Default last
        world_default_record = None

        for record in self.zone_records(zone):
            if (
                existing.name == record['name']
                and existing._type == record['type']
            ):
                # Handle dynamic record.
                if (
                    record.get('geolocation')
                    and record['geolocation']['geoipFilter'] == 1
                ):
                    world_default_record = record
                else:
                    # delete record
                    self.log.debug(
                        "Deleting record %s %s", zone.name, record['type']
                    )
                    self._client.record_delete(
                        zone.name, record['type'], record['id']
                    )
                    if record['recordOption'] == 'pools':
                        # delete geofilter
                        self.log.debug("Deleting geofilter %s", zone.name)
                        self._client.geofilter_delete(
                            record['geolocation']['geoipFilter']
                        )
                        # delete pool
                        self.log.debug(
                            "Deleting pool %s %s", zone.name, record['type']
                        )
                        self._client.pool_delete(
                            record['type'], record['pools'][0]
                        )

        # Must delete World Default record last, do not touch global geofilter
        if world_default_record:
            record = world_default_record
            # delete record
            self.log.debug("Deleting record %s %s", zone.name, record['type'])
            self._client.record_delete(zone.name, record['type'], record['id'])
            if record['recordOption'] == 'pools':
                # delete pool
                self.log.debug("Deleting pool %s %s", zone.name, record['type'])
                self._client.pool_delete(record['type'], record['pools'][0])

    def _process_desired_zone(self, desired):
        # Filter out fallback values without configured sonar monitoring
        for record in desired.records:
            if not getattr(record, 'dynamic', False):
                continue

            incompatible_pools = []
            for name, pool in record.dynamic.pools.items():
                if pool.data['fallback'] is not None:
                    incompatible = True
                    for value in pool.data['values']:
                        if 'obey' == value.get('status', 'obey'):
                            incompatible = False
                            break
                    if incompatible:
                        incompatible_pools.append(name)

            if not incompatible_pools:
                continue

            incompatible_pools = ','.join(incompatible_pools)
            msg = (
                f'fallback without monitor for pools '
                f'{incompatible_pools} in {record.fqdn}'
            )
            fallback = 'will ignore it'
            self.supports_warn_or_except(msg, fallback)

            record = record.copy()
            for pool in record.dynamic.pools.values():
                pool.data['fallback'] = None
            desired.add_record(record, replace=True)

        return super()._process_desired_zone(desired)

    def _apply(self, plan):
        desired = plan.desired
        changes = plan.changes
        self.log.debug(
            '_apply: zone=%s, len(changes)=%d', desired.name, len(changes)
        )

        try:
            self._client.domain(desired.name)
        except ConstellixClientNotFound:
            self.log.debug('_apply:   no matching zone, creating domain')
            self._client.domain_create(desired.name[:-1])

        for change in changes:
            class_name = change.__class__.__name__
            getattr(self, f'_apply_{class_name}')(change, desired.name)

        # Clear out the cache if any
        self._zone_records.pop(desired.name, None)
