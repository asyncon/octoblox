import os
from conftest import ANY, pytest
from requests_mock import ANY

# from octodns.record import Record
from octodns.provider.yaml import YamlProvider
from octodns.zone import Zone


def test_zone_data(provider, requests_mock, zone_name, zones, records):
    expected = Zone(zone_name, [])
    source = YamlProvider('test', os.path.join(os.path.dirname(__file__), 'config'))
    source.populate(expected)
    requests_mock.get(zones[0], json=zones[1])
    requests_mock.get(records[0], json=records[1])
    requests_mock.delete(records[0], status_code=200)
    requests_mock.post(records[0], status_code=201)
    requests_mock.put(records[0], status_code=200)
    zone = Zone(zone_name, [])
    provider.populate(zone)
    assert len(zone.records) == 3
    changes = expected.changes(zone, provider)
    plan = provider.plan(expected)
    provider.apply(plan)
