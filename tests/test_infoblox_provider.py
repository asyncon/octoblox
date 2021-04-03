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
    provider.populate(zone, lenient=True)
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


def test_ipv4_zone(provider, new_ipv4_zone):
    expected = Zone(new_ipv4_zone, [])
    source = YamlProvider('test', os.path.join(os.path.dirname(__file__), 'config'))
    source.populate(expected)
    assert len(expected.records) == 1
    zone = Zone(new_ipv4_zone, [])
    provider.populate(zone)
    plan = provider.plan(expected)
    provider.apply(plan)


def test_ipv6_zone(provider, new_ipv6_zone):
    expected = Zone(new_ipv6_zone, [])
    source = YamlProvider('test', os.path.join(os.path.dirname(__file__), 'config'))
    source.populate(expected)
    assert len(expected.records) == 1
    zone = Zone(new_ipv6_zone, [])
    provider.populate(zone)
    plan = provider.plan(expected)
    provider.apply(plan)
