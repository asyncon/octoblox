import re
# import sys
# import yaml
import pytest
from urllib.parse import urlparse
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
    c = {
        'A': [{
            '_ref': f'record:a/wxyz/xyz.{zone}/default',
            'name': 'xyz',
            'ipv4addr': '192.168.0.1',
            'use_ttl': False,
        }, {
            '_ref': f'record:a/wwwz/www.{zone}/default',
            'name': 'www',
            'ipv4addr': '192.168.0.2',
            'use_ttl': False,
        }],
        'CNAME': [{
            '_ref': f'record:cname/abcd/cname.{zone}/default',
            'name': 'cname',
            'canonical': f'example.{zone}',
            'use_ttl': False,
        }],
    }

    def get_record(request, context, check=c):
        return {'result': check.get(urlparse(request.url).path.split(':')[-1].upper(), [])}

    return get_record


@pytest.fixture
def records(zone_name):
    return (re.compile('/wapi/v1.0/record:\\w+([?/]|$)'), get_records(zone_name[:-1]))


@pytest.fixture
def provider():
    return InfoBloxProvider('test', 'non.existent', 'username', 'password', apiver='1.0')
