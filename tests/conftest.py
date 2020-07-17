import re
import uuid
import pytest
from urllib.parse import urlparse, quote_plus
from octoblox import InfoBloxProvider


@pytest.fixture
def zone_name():
    return 'unit.tests.'


@pytest.fixture
def new_zone_name():
    return 'create.tests.'


@pytest.fixture
def new_ipv4_zone():
    return '12.11.10.in-addr.arpa.'


@pytest.fixture
def new_ipv4_cidr():
    return '10.11.12.0/24'


@pytest.fixture
def new_ipv6_zone():
    return 'f.e.d.c.b.a.9.8.7.6.5.4.3.2.1.0.ip6.arpa.'


@pytest.fixture
def new_ipv6_cidr():
    return '0123:4567:89ab:cdef:0000:0000:0000:0000/64'


@pytest.fixture
def schema():
    return (
        '/wapi/v1.0/?_schema',
        {
            'supported_versions': ['1.0'],
            'supported_objects': [
                'record:a',
                'record:aaaa',
                'record:alias',
                'record:caa',
                'record:cname',
                'record:mx',
                'record:naptr',
                'record:ns',
                'record:ptr',
                'record:srv',
                'record:txt',
            ],
        },
    )


@pytest.fixture
def zones(zone_name, new_zone_name, new_ipv4_cidr, new_ipv6_cidr):
    return {
        f'/wapi/v1.0/zone_auth?fqdn={zone_name[:-1]}': [
            {
                '_ref': f'zone_auth/{uuid.uuid4()}:{zone_name[:-1]}/default',
                'fqdn': zone_name[:-1],
                'view': 'default',
                'soa_default_ttl': 28800,
            }
        ],
        f'/wapi/v1.0/zone_auth?fqdn={new_zone_name[:-1]}': [],
        f'/wapi/v1.0/zone_auth?fqdn={quote_plus(new_ipv4_cidr)}': [],
        f'/wapi/v1.0/zone_auth?fqdn={quote_plus(new_ipv6_cidr)}': [],
    }


def get_records(zone):
    c = {
        'A': [
            {
                '_ref': f'record:a/{uuid.uuid4()}:xyz.{zone}/default',
                'name': 'xyz',
                'ipv4addr': '192.168.0.1',
                'use_ttl': False,
            },
            {
                '_ref': f'record:a/{uuid.uuid4()}:www.{zone}/default',
                'name': 'www',
                'ipv4addr': '192.168.0.2',
                'use_ttl': False,
            },
        ],
        'ALIAS': [
            {
                '_ref': f'record:a/{uuid.uuid4()}:alias-update.{zone}/default',
                'name': 'alias-update',
                'target_name': f'xyz.{zone}',
                'target_type': 'A',
                'use_ttl': False,
            },
            {
                '_ref': f'record:a/{uuid.uuid4()}:alias-update.{zone}/default',
                'name': 'alias-update',
                'target_name': f'xyz.{zone}',
                'target_type': 'TXT',
                'use_ttl': False,
            },
            {
                '_ref': f'record:a/{uuid.uuid4()}:alias-delete.{zone}/default',
                'name': 'alias-delete',
                'target_name': f'foo.{zone}',
                'target_type': 'A',
                'use_ttl': False,
            },
        ],
        'CNAME': [
            {
                '_ref': f'record:cname/{uuid.uuid4()}:cname.{zone}/default',
                'name': 'cname',
                'canonical': f'example.{zone}',
                'use_ttl': False,
            }
        ],
    }

    def get_record(request, context, check=c):
        return {
            'result': check.get(urlparse(request.url).path.split(':')[-1].upper(), [])
        }

    return get_record


@pytest.fixture
def records(zone_name):
    return (re.compile('/wapi/v1.0/record:\\w+([?/]|$)'), get_records(zone_name[:-1]))


@pytest.fixture
def provider(requests_mock, zones, records, schema):
    requests_mock.get(schema[0], json=schema[1])
    for url, data in zones.items():
        requests_mock.get(url, json=data)
        if not data:
            requests_mock.post(
                url.split('?').pop(0),
                status_code=201,
                json={
                    '_ref': url.replace('?fqdn=', f'/{uuid.uuid4()}:') + '/default',
                    'fqdn': url.split('?fqdn=')[-1],
                    'soa_default_ttl': 7200,
                    'use_ttl': False,
                },
            )
    requests_mock.get(records[0], json=records[1])
    requests_mock.delete(records[0], status_code=200)
    requests_mock.post(records[0], status_code=201)
    requests_mock.put(records[0], status_code=200)
    return InfoBloxProvider(
        'test',
        'non.existent',
        'username',
        'password',
        log_change=True,
        create_zones=True,
    )
