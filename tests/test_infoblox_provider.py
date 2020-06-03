from conftest import ANY, pytest
from requests_mock import ANY

# from octodns.record import Record
# from octodns.provider.yaml import YamlProvider
from octodns.zone import Zone


def test_zone_data(provider, requests_mock, zone_name, zones, records):
    # expected = Zone(zone_name, [])
    # source = YamlProvider('test', join(dirname(__file__), 'config'))
    # source.populate(expected)
    # expected_n = len(expected.records) - 2

    provider.SUPPORTS = {'A', 'CNAME'}
    requests_mock.get(zones[0], json=zones[1])
    requests_mock.get(records[0], json=records[1])
    zone = Zone(zone_name, [])
    provider.populate(zone)
    assert len(zone.records) == 2
    # self.assertEquals(16, len(zone.records))
    # changes = expected.changes(zone, provider)
    # self.assertEquals(0, len(changes))
