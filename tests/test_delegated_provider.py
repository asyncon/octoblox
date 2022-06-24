import os
import logging
from octodns.provider.yaml import YamlProvider
from octodns.zone import Zone

logging.basicConfig(level='INFO')


def test_zone_data(delegated_provider, zone_name):
    expected = Zone(zone_name, [])
    source = YamlProvider('test', os.path.join(os.path.dirname(__file__), 'delegated'))
    source.populate(expected)
    zone = Zone(zone_name, [])
    delegated_provider.populate(zone, lenient=True)
    assert len(zone.records) == 0
    plan = delegated_provider.plan(expected)
    delegated_provider.apply(plan)


def test_zone_creation(delegated_provider, new_zone_name):
    expected = Zone(new_zone_name, [])
    source = YamlProvider('test', os.path.join(os.path.dirname(__file__), 'delegated'))
    source.populate(expected)
    assert len(expected.records) == 0
    zone = Zone(new_zone_name, [])
    delegated_provider.populate(zone)
    plan = delegated_provider.plan(expected)
    delegated_provider.apply(plan)


def test_empty_zone_creation(delegated_provider, empty_zone_name):
    expected = Zone(empty_zone_name, [])
    source = YamlProvider('test', os.path.join(os.path.dirname(__file__), 'delegated'))
    source.populate(expected)
    assert len(expected.records) == 0
    zone = Zone(empty_zone_name, [])
    delegated_provider.populate(zone)
    plan = delegated_provider.plan(expected)
    delegated_provider.apply(plan)


def test_ipv4_zone(delegated_provider, new_ipv4_zone):
    expected = Zone(new_ipv4_zone, [])
    source = YamlProvider('test', os.path.join(os.path.dirname(__file__), 'delegated'))
    source.populate(expected)
    assert len(expected.records) == 0
    zone = Zone(new_ipv4_zone, [])
    delegated_provider.populate(zone)
    plan = delegated_provider.plan(expected)
    delegated_provider.apply(plan)


def test_ipv6_zone(delegated_provider, new_ipv6_zone):
    expected = Zone(new_ipv6_zone, [])
    source = YamlProvider('test', os.path.join(os.path.dirname(__file__), 'delegated'))
    source.populate(expected)
    assert len(expected.records) == 0
    zone = Zone(new_ipv6_zone, [])
    delegated_provider.populate(zone)
    plan = delegated_provider.plan(expected)
    delegated_provider.apply(plan)
