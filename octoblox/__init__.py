import logging
import requests
from collections import defaultdict
from functools import lru_cache
from octodns.provider.base import BaseProvider
from octodns.record import Record

single_types = {'ALIAS', 'CNAME', 'PTR'}
type_map = {
    'A': 'ipv4addr',
    'AAAA': 'ipv6addr',
    'ALIAS': 'target_name',
    'CAA': {
        'ca_flag': 'flags',
        'ca_tag': 'tag',
        'ca_value': 'value',
    },
    'CNAME': 'canonical',
    'MX': {
        'preference': 'preference',
        'mail_exchanger': 'exchange',
    },
    'NAPTR': {
        'order': 'order',
        'preference': 'preference',
        'flags': 'flags',
        'services': 'service',
        'regexp': 'regexp',
        'replacement': 'replacement',
    },
    'NS': 'nameserver',
    'PTR': 'ptrdname',
    'SRV': {
        'priority': 'priority',
        'weight': 'weight',
        'port': 'port',
        'target': 'target',
    },
    'TXT': 'text',
}


class InfoBlox(requests.Session):
    """Encapsulates all traffic with the InfoBlox WAPI"""

    def __init__(self, fqdn, username, password, verify=True, apiver=None, dns_view=None, network_view=None, log=None):
        super(InfoBlox, self).__init__()
        self.fqdn = fqdn
        self.auth = (username, password)
        self.dns_view = dns_view
        self.network_view = network_view
        self.verify = verify
        self.apiver = apiver or '1.0'
        self.log = log
        if not apiver:
            self.get_api_version()

    def url(self, url):
        return url if url.startswith('https://') else 'https://{0.fqdn}/wapi/v{0.apiver}/{1}'.format(self, url)

    def request(self, method, url, **kwargs):
        ret = super(InfoBlox, self).request(method, self.url(url),**kwargs)
        try:
            ret.raise_for_status()
        except requests.HTTPError:
            self.log.error('InfoBlox.request: %d %s %s %r %s', ret.status_code, method, url, kwargs, ret.text)
            raise
        return ret

    def get_api_version(self):
        res = self.get('?_schema')
        self.apiver = '.'.join(map(str,sorted(list(map(int,v.split('.'))) for v in res.json()['supported_versions'])[-1]))
        return self.apiver

    def get_zone(self, zone):
        return self.get('zone_auth', params={
            'fqdn': zone.rstrip('.'),
            '_return_fields+': 'soa_default_ttl',
            **({'view': self.dns_view} if self.dns_view else {}),
        }).json()

    def get_records(self, type, fields, zone, default_ttl, **extra):
        ret = self.get('record:{0}'.format(type.lower()), params={
            'zone': zone.rstrip('.'), **extra,
            '_return_fields+': ','.join((() if type == 'NS' else ('ttl','use_ttl') ) + fields),
            '_paging': 1, '_max_results': 1000, '_return_as_object': 1,
            **({'view': self.dns_view} if self.dns_view else {}),
        }).json()
        data = ret['result']
        while 'next_page_id' in ret:
            ret = self.get('record:{0}'.format(type.lower()), params={'_page_id': ret['next_page_id']}).json()
            data += ret['result']
        dd = defaultdict(list)
        for d in data:
            dd[d['name']].append(d)
        return [(rl[0]['ttl'] if rl[0]['use_ttl'] else default_ttl, n, [{
            k: v for k, v in r.items() if k in fields
        } for r in rl], rl) for n, rl in dd.items() if rl]

    def add_record(self, type, zone, name, **fields):
        self.post(f'record:{type.lower()}', json={
            'name': f'{name}.{zone}',
            **({'view': self.dns_view} if self.dns_view else {}),
            **fields
        })

    def mod_record(self, src, ttl, default_ttl):
        self.put(src['_ref'], json={
            **{k: v for k, v in src.items() if k != '_ref'},
            **({} if type == 'NS' else {'use_ttl': ttl != default_ttl, 'ttl': ttl,}),
        })

    def del_record(self, source):
        for src in source:
            self.delete(src['_ref'])


class InfoBloxProvider(BaseProvider):

    SUPPORTS_GEO = False
    SUPPORTS_DYNAMIC = False
    # SUPPORTS = {*type_map}

    def __init__(
        self, id, gridmaster, username, password, verify=True, apiver=None,
        dns_view=None, network_view=None, *args, **kwargs
    ):
        self.log = logging.getLogger('{}[{}]'.format(
            self.__class__.__name__, id))
        self.conn = InfoBlox(gridmaster, username, password, verify, apiver, dns_view, network_view, self.log)
        self.log.debug(
            '__init__: id=%s, gridmaster=%s, username=%s, apiver=%s',
            id, gridmaster, username, self.conn.apiver)
        super(InfoBloxProvider, self).__init__(id, *args, **kwargs)

    @property
    @lru_cache(1)
    def SUPPORTS(self):
        supported_objects = self.conn.get('?_schema').json()['supported_objects']
        return {t for t in type_map if f'record:{t.lower()}' in supported_objects}

    def _data_for(self, type, zone, default_ttl):
        spec = type_map[type]
        single_field = isinstance(spec, str)
        fields = (spec,) if single_field else (*spec,)
        data = self.conn.get_records(type, fields, zone, default_ttl)
        return [(ttl, name, source,
            values[0][spec]+'.' if type in single_types else [
                v[spec] if single_field else 
                {k: v[vk] for vk, k in spec.items()}
                for v in values
            ]
        ) for ttl, name, values, source in data]

    def populate(self, zone, target=False, lenient=False):
        '''
        Loads all records the provider knows about for the provided zone

        When `target` is True the populate call is being made to load the
        current state of the provider.

        When `lenient` is True the populate call may skip record validation and
        do a "best effort" load of data. That will allow through some common,
        but not best practices stuff that we otherwise would reject. E.g. no
        trailing . or mising escapes for ;.

        When target is True (loading current state) this method should return
        True if the zone exists or False if it does not.
        '''
        self.log.debug('populate: name=%s, target=%s, lenient=%s', zone.name,
                       target, lenient)

        before = len(zone.records)
        exists = False

        zone_data = self.conn.get_zone(zone.name)

        if not zone_data:
            if target:
                raise ValueError("Zone does not exist in InfoBlox: {0}".format(zone.name))
            return False

        default_ttl = zone_data[0]['soa_default_ttl']

        for _type in sorted(self.SUPPORTS):
            for t, n, s, v in self._data_for(_type, zone.name, default_ttl):
                record_name = zone.hostname_from_fqdn(n)
                record = Record.new(zone, record_name, {
                    'ttl': t,
                    'type': _type,
                    'values' if isinstance(v, list) else 'value': v
                }, source=s, lenient=lenient)
                zone.add_record(record, lenient=lenient)

        return True

    def _apply_Create(self, zone, change, default_ttl):
        new = change.new
        type = new._type
        spec = type_map[type]
        single_field = isinstance(spec, str)
        values = [new.value] if type in single_types else new.values
        fields = (spec,) if single_field else (*spec,)
        for value in values:
            self.conn.add_record(type, zone, new.name,
                ttl=new.ttl,
                use_ttl=new.ttl!=default_ttl,
                **(
                    {spec: value.rstrip('.')} if type in single_types else
                    {spec: value} if single_field else 
                    {vk: getattr(value, k) for vk, k in spec.items()}
                )
            )

    def _apply_Delete(self, zone, change, default_ttl):
        self.conn.del_record(change.existing.source)

    def _apply_Update(self, zone, change, default_ttl):
        existing = change.existing
        new = change.new
        type = new._type
        update = existing.ttl != new.ttl
        spec = type_map[type]
        single_field = isinstance(spec, str)
        values = [new.value] if type in single_types else new.values
        evalues = [existing.value,] if type in single_types else existing.values
        fields = (spec,) if single_field else (*spec,)
        for value in values:
            if type in single_types:
                self.conn.mod_record(existing.source[0], new.ttl, default_ttl)
            elif value in evalues:
                if update:
                    self.conn.mod_record(existing.source[evalues.index(value)], new.ttl, default_ttl)
            else:
                self.conn.add_record(type, zone, new.name,
                    ttl=new.ttl,
                    use_ttl=new.ttl!=default_ttl,
                    **(
                        {spec: value.rstrip('.')} if type in single_types else
                        {spec: value} if single_field else 
                        {vk: getattr(value, k) for vk, k in spec.items()}
                    )
                )
        self.conn.del_record(existing.source[i] for i, value in enumerate(evalues) if value not in values)

    def _apply(self, plan):

        zone = plan.desired.name[:-1]

        zone_data = self.conn.get_zone(zone)

        if not zone_data:
            if target:
                raise ValueError("Zone does not exist in InfoBlox: {0}".format(zone.name))
            return False

        default_ttl = zone_data[0]['soa_default_ttl']

        for change in plan.changes:
            class_name = change.__class__.__name__
            getattr(self, '_apply_{}'.format(class_name))(zone, change, default_ttl)
