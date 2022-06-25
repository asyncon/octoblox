import pytest
from octoblox import EmptySource
from octodns.provider.yaml import YamlProvider
from octodns.zone import Zone
from pathlib import Path

keys = 'result,source'
values = [
    (0, lambda: EmptySource('E')),
    (1, lambda: YamlProvider('Y', Path(__file__).parent / 'config')),
]


@pytest.mark.parametrize(keys, values)
def test_zone_data(delegated_provider, zone_name, result, source):
    expected = Zone(zone_name, [])
    source = source()
    source.populate(expected)
    assert len(expected.records) == 5 * result
    zone = Zone(zone_name, [])
    delegated_provider.populate(zone, lenient=True)
    assert len(zone.records) == 0
    plan = delegated_provider.plan(expected)
    if result:
        delegated_provider.apply(plan)
    else:
        assert plan is None


@pytest.mark.parametrize(keys, values)
def test_zone_creation(delegated_provider, new_zone_name, result, source):
    expected = Zone(new_zone_name, [])
    source = source()
    source.populate(expected)
    assert len(expected.records) == 4 * result
    zone = Zone(new_zone_name, [])
    delegated_provider.populate(zone)
    assert len(zone.records) == 0
    plan = delegated_provider.plan(expected)
    delegated_provider.apply(plan)


@pytest.mark.parametrize(keys, values)
def test_empty_zone_creation(delegated_provider, empty_zone_name, result, source):
    expected = Zone(empty_zone_name, [])
    source = source()
    source.populate(expected)
    assert len(expected.records) == 0
    zone = Zone(empty_zone_name, [])
    delegated_provider.populate(zone)
    assert len(zone.records) == 0
    plan = delegated_provider.plan(expected)
    delegated_provider.apply(plan)


@pytest.mark.parametrize(keys, values)
def test_ipv4_zone(delegated_provider, new_ipv4_zone, result, source):
    expected = Zone(new_ipv4_zone, [])
    source = source()
    source.populate(expected)
    assert len(expected.records) == 1 * result
    zone = Zone(new_ipv4_zone, [])
    delegated_provider.populate(zone)
    assert len(zone.records) == 0
    plan = delegated_provider.plan(expected)
    delegated_provider.apply(plan)


@pytest.mark.parametrize(keys, values)
def test_ipv6_zone(delegated_provider, new_ipv6_zone, result, source):
    expected = Zone(new_ipv6_zone, [])
    source = source()
    source.populate(expected)
    assert len(expected.records) == 1 * result
    zone = Zone(new_ipv6_zone, [])
    delegated_provider.populate(zone)
    assert len(zone.records) == 0
    plan = delegated_provider.plan(expected)
    delegated_provider.apply(plan)
