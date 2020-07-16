import os
import logging
from octodns.provider.yaml import YamlProvider
from octodns.zone import Zone

logging.basicConfig(level='INFO')


def test_zone_data(provider, zone_name):
    expected = Zone(zone_name, [])
    source = YamlProvider('test', os.path.join(os.path.dirname(__file__), 'config'))
    source.populate(expected)
    zone = Zone(zone_name, [])
    provider.populate(zone)
    assert len(zone.records) == 5
    plan = provider.plan(expected)
    provider.apply(plan)


def test_zone_creation(provider, new_zone_name):
    expected = Zone(new_zone_name, [])
    source = YamlProvider('test', os.path.join(os.path.dirname(__file__), 'config'))
    source.populate(expected)
    assert len(expected.records) == 4
    zone = Zone(new_zone_name, [])
    provider.populate(zone)
    plan = provider.plan(expected)
    provider.apply(plan)
