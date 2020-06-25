import logging
import requests
from collections import defaultdict
from functools import lru_cache
from octodns.provider.base import BaseProvider
from octodns.record import Record

# fmt: off
single_types = {'ALIAS', 'CNAME', 'PTR'}
dot_types = single_types | {'NS'}
no_dot_types = {'A', 'AAAA', 'TXT'}
dot_fields = {
    'target_name',
    'canonical',
    'nameserver',
    'ptrdname',
    'mail_exchanger',
    'target',
}
type_map = {
    'A': 'ipv4addr',
    'AAAA': 'ipv6addr',
    'ALIAS': ['target_name', 'target_type'],
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
# fmt: on


class InfoBlox(requests.Session):
    """Encapsulates all traffic with the InfoBlox WAPI"""

    def __init__(
        self,
        fqdn,
        username,
        password,
        verify=True,
        apiver=None,
        dns_view=None,
        alias_types=None,
        log_change=False,
        log=None,
    ):
        super(InfoBlox, self).__init__()
        self.fqdn = fqdn
        self.auth = (username, password)
        self.dns_view = dns_view
        self.alias_types = {*alias_types} if alias_types else {'A', 'AAAA'}
        self.verify = verify
        self.apiver = apiver or '1.0'
        self.log_change = log_change
        self.log = log
        if not apiver:
            self.apiver = self.get_api_version()

    def url(self, url):
        return f'https://{self.fqdn}/wapi/v{self.apiver}/{url}'

    def request(self, method, url, **kwargs):
        if self.log_change and method not in ('GET', 'HEAD'):
            print(f'{method} {url} {kwargs}')
        ret = super().request(method, self.url(url), **kwargs)
        try:
            ret.raise_for_status()
        except requests.HTTPError:
            self.log.error(
                'InfoBlox.request: %d %s %s %r %s',
                ret.status_code,
                method,
                url,
                kwargs,
                ret.text,
            )
            raise
        return ret

    def get_api_version(self):
        vers = self.get('?_schema').json()['supported_versions']
        vers = ([int(i) for i in v.split('.')] for v in vers)
        return '.'.join(str(i) for i in sorted(vers)[-1])

    def get_zone(self, zone):
        return self.get(
            'zone_auth',
            params={
                'fqdn': zone.rstrip('.'),
                '_return_fields+': 'soa_default_ttl',
                **({'view': self.dns_view} if self.dns_view else {}),
            },
        ).json()

    def get_records(self, type, fields, zone, default_ttl, **extra):
        ret = self.get(
            'record:{0}'.format(type.lower()),
            params={
                'zone': zone.rstrip('.'),
                **extra,
                '_return_fields+': ','.join(
                    (() if type == 'NS' else ('ttl', 'use_ttl')) + fields
                ),
                '_paging': 1,
                '_max_results': 1000,
                '_return_as_object': 1,
                **({'view': self.dns_view} if self.dns_view else {}),
            },
        ).json()
        data = ret['result']
        while 'next_page_id' in ret:
            ret = self.get(
                'record:{0}'.format(type.lower()),
                params={'_page_id': ret['next_page_id']},
            ).json()
            data += ret['result']
        dd = defaultdict(list)
        for d in data:
            dd[d['name']].append(d)
        return [
            (
                rl[0]['ttl'] if type != 'NS' and rl[0]['use_ttl'] else default_ttl,
                n,
                [
                    {
                        k: (v + '.' if k in dot_fields else v)
                        for k, v in r.items()
                        if k in fields
                    }
                    for r in rl
                ],
                rl,
            )
            for n, rl in dd.items()
            if rl
        ]

    def payload_value(self, type, value, ttl, default_ttl):
        spec = type_map[type]
        single_field = isinstance(spec, str)
        return {
            **(
                value
                if type == 'ALIAS'
                else {spec: value[:-1]}
                if type in dot_types
                else {spec: value}
                if single_field
                else {
                    vk: (
                        getattr(value, k)[:-1]
                        if vk in dot_fields
                        else getattr(value, k)
                    )
                    for vk, k in spec.items()
                }
            ),
            **({} if type == 'NS' else {'use_ttl': ttl != default_ttl, 'ttl': ttl,}),
        }

    def add_record(self, type, zone, name, value, ttl, default_ttl):
        self.post(
            f'record:{type.lower()}',
            json={
                'name': f'{name}.{zone}',
                **self.payload_value(type, value, ttl, default_ttl),
                **({'view': self.dns_view} if self.dns_view else {}),
            },
        )

    def mod_record(self, type, src, value, ttl, default_ttl):
        self.put(src['_ref'], json=self.payload_value(type, value, ttl, default_ttl))

    def del_record(self, source):
        for src in source:
            self.delete(src['_ref'])


class InfoBloxProvider(BaseProvider):

    SUPPORTS_GEO = False
    SUPPORTS_DYNAMIC = False

    def __init__(
        self,
        id,
        gridmaster,
        username,
        password,
        verify=True,
        apiver=None,
        dns_view=None,
        alias_types=None,
        log_change=False,
        *args,
        **kwargs,
    ):
        self.log = logging.getLogger(f'{self.__class__.__name__}[{id}]')
        self.conn = InfoBlox(
            gridmaster,
            username,
            password,
            verify,
            apiver,
            dns_view,
            alias_types,
            log_change,
            self.log,
        )
        self.log.debug(
            f'__init__: https://{username}@{gridmaster}/wapi/v{self.conn.apiver}/'
        )
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
        return [
            (
                ttl,
                name,
                source,
                (
                    values[0][spec[0]]
                    if {v[spec[1]] for v in values} == self.conn.alias_types
                    else 'example.com.'
                )
                if type == 'ALIAS'
                else values[0][spec]
                if type in single_types
                else [
                    v[spec] if single_field else {k: v[vk] for vk, k in spec.items()}
                    for v in values
                ],
            )
            for ttl, name, values, source in data
        ]

    def populate(self, zone, target=False, lenient=False):
        self.log.debug(
            'populate: name=%s, target=%s, lenient=%s', zone.name, target, lenient
        )

        zone_data = self.conn.get_zone(zone.name)

        if not zone_data:
            if target:
                raise ValueError(
                    "Zone does not exist in InfoBlox: {0}".format(zone.name)
                )
            return False

        default_ttl = zone_data[0]['soa_default_ttl']

        for type in sorted(self.SUPPORTS):
            for t, n, s, v in self._data_for(type, zone.name, default_ttl):
                record_name = zone.hostname_from_fqdn(n)
                record = Record.new(
                    zone,
                    record_name,
                    {
                        'ttl': t,
                        'type': type,
                        'values' if isinstance(v, list) else 'value': v,
                    },
                    source=self,
                    lenient=lenient,
                )
                record.refs = s
                zone.add_record(record, lenient=lenient)

        return True

    def _apply_Create(self, zone, change, default_ttl):
        new = change.new
        type = new._type
        values = [new.value] if type in single_types else new.values
        for value in values:
            if type == 'ALIAS':
                spec = type_map[type]
                for t in self.conn.alias_types:
                    v = {spec[0]: value, spec[1]: t}
                    self.conn.add_record(type, zone, new.name, v, new.ttl, default_ttl)
            else:
                self.conn.add_record(type, zone, new.name, value, new.ttl, default_ttl)

    def _apply_Delete(self, zone, change, default_ttl):
        self.conn.del_record(change.existing.refs)

    def _apply_Update(self, zone, change, default_ttl):
        ext = change.existing
        new = change.new
        type = new._type
        update = ext.ttl != new.ttl
        values = [new.value] if type in single_types else new.values
        evalues = [ext.value,] if type in single_types else ext.values
        for value in values:
            if type == 'ALIAS':
                spec = type_map[type]
                refs = {r[spec[1]]: r for r in ext.refs}
                for t in self.conn.alias_types - {*refs}:
                    v = {spec[0]: value, spec[1]: t}
                    self.conn.add_record(type, zone, new.name, v, new.ttl, default_ttl)
                for t in self.conn.alias_types & {*refs}:
                    if refs[t][spec[0]] != value:
                        v = {spec[0]: value, spec[1]: t}
                        self.conn.mod_record(type, refs[t], v, new.ttl, default_ttl)
                self.conn.del_record(
                    r for t, r in refs.items() if t not in self.conn.alias_types
                )
            elif type in single_types:
                self.conn.mod_record(type, ext.refs[0], value, new.ttl, default_ttl)
            elif value in evalues:
                if update:
                    self.conn.mod_record(
                        type,
                        ext.refs[evalues.index(value)],
                        value,
                        new.ttl,
                        default_ttl,
                    )
            else:
                self.conn.add_record(type, zone, new.name, value, new.ttl, default_ttl)
        if type not in single_types:
            self.conn.del_record(
                ext.refs[i] for i, value in enumerate(evalues) if value not in values
            )

    def _apply(self, plan):

        zone = plan.desired.name[:-1]

        zone_data = self.conn.get_zone(zone)

        if not zone_data:
            raise ValueError("Zone does not exist in InfoBlox: {0}".format(zone.name))

        default_ttl = zone_data[0]['soa_default_ttl']

        for change in plan.changes:
            class_name = change.__class__.__name__
            getattr(self, '_apply_{}'.format(class_name))(zone, change, default_ttl)
