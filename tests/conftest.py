import re
import pytest
from urllib.parse import urlparse
from octoblox import InfoBloxProvider


@pytest.fixture
def zone_name():
    return 'unit.tests.'


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
def zones(zone_name):
    return (
        f'/wapi/v1.0/zone_auth?fqdn={zone_name[:-1]}',
        [
            {
                '_ref': f'zone_auth/abcd/{zone_name[:-1]}/default',
                'fqdn': zone_name[:-1],
                'view': 'default',
                'soa_default_ttl': 28800,
            }
        ],
    )


def get_records(zone):
    c = {
        'A': [
            {
                '_ref': f'record:a/wxyz/xyz.{zone}/default',
                'name': 'xyz',
                'ipv4addr': '192.168.0.1',
                'use_ttl': False,
            },
            {
                '_ref': f'record:a/wwwz/www.{zone}/default',
                'name': 'www',
                'ipv4addr': '192.168.0.2',
                'use_ttl': False,
            },
        ],
        'ALIAS': [
            {
                '_ref': f'record:a/als1/alias-update.{zone}/default',
                'name': 'alias-update',
                'target_name': f'xyz.{zone}',
                'target_type': 'A',
                'use_ttl': False,
            },
            {
                '_ref': f'record:a/als2/alias-update.{zone}/default',
                'name': 'alias-update',
                'target_name': f'xyz.{zone}',
                'target_type': 'TXT',
                'use_ttl': False,
            },
            {
                '_ref': f'record:a/als3/alias-delete.{zone}/default',
                'name': 'alias-delete',
                'target_name': f'foo.{zone}',
                'target_type': 'A',
                'use_ttl': False,
            },
        ],
        'CNAME': [
            {
                '_ref': f'record:cname/abcd/cname.{zone}/default',
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
    requests_mock.get(zones[0], json=zones[1])
    requests_mock.get(records[0], json=records[1])
    requests_mock.delete(records[0], status_code=200)
    requests_mock.post(records[0], status_code=201)
    requests_mock.put(records[0], status_code=200)
    return InfoBloxProvider(
        'test', 'non.existent', 'username', 'password', log_change=True
    )
