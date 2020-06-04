import re
import pytest
from requests_mock import ANY
from octoblox import InfoBloxProvider


@pytest.fixture
def zone_name():
    return 'unit.tests.'


@pytest.fixture
def zones(zone_name):
    return (f'/wapi/v1.0/zone_auth?fqdn={zone_name[:-1]}', [{
        '_ref': f'zone_auth/abcd/{zone_name[:-1]}/default',
        'fqdn': zone_name[:-1],
        'view': 'default',
        'soa_default_ttl': 28800,
    }])


def get_records(zone):
    c = []

    def get_record(request, context, check=c):
        if check:
            return {'result':[{
            '_ref': f'record:a/abcd/abc.{zone}/default',
            'name': 'abc',
            'canonical': f'example.{zone}',
            'use_ttl': False,
            }]}
        check.append('')
        return {'result': [{
            '_ref': f'record:a/abcd/xyz.{zone}/default',
            'name': 'xyz',
            'ipv4addr': '192.168.0.1',
            'use_ttl': False,
        }]}

    return get_record


@pytest.fixture
def records(zone_name):
    return (re.compile('/wapi/v1.0/record:\\w+[?]'), get_records(zone_name[:-1]))


@pytest.fixture
def provider():
    return InfoBloxProvider('test', 'non.existent', 'username', 'password', apiver='1.0')
