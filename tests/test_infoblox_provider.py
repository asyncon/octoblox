import os
import logging
from octodns.provider.yaml import YamlProvider
from octodns.zone import Zone

logging.basicConfig()


def test_zone_data(provider, zone_name):
    expected = Zone(zone_name, [])
    source = YamlProvider('test', os.path.join(os.path.dirname(__file__), 'config'))
    source.populate(expected)
    zone = Zone(zone_name, [])
    provider.populate(zone)
    assert len(zone.records) == 5
    plan = provider.plan(expected)
    provider.apply(plan)
