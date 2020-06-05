import logging
import requests
from collections import defaultdict
from octodns.provider.base import BaseProvider
from octodns.record import Record


class InfoBlox(requests.Session):
    """Encapsulates all traffic with the InfoBlox WAPI"""

    def __init__(self, fqdn, username, password, verify=True, apiver=None, dns_view=None, network_view=None):
        super(InfoBlox, self).__init__()
        self.fqdn = fqdn
        self.auth = (username, password)
        self.dns_view = dns_view
        self.network_view = network_view
        self.verify = verify
        self.apiver = apiver or '1.0'
        if not apiver:
            self.get_api_version()

    def url(self, url):
        return url if url.startswith('https://') else 'https://{0.fqdn}/wapi/v{0.apiver}/{1}'.format(self, url)

    def request(self, method, url, **kwargs):
        return super(InfoBlox, self).request(method, self.url(url),**kwargs)
        ret.raise_for_status()
        return ret

    def get_api_version(self):
        res = self.get('?_schema')
        self.apiver = '.'.join(sorted(list(map(int,v.split('.'))) for v in res.json()['supported_versions'])[-1])
        return self.apiver

    def get_zone(self, zone):
        return self.get('zone_auth', params={
            'fqdn': zone.rstrip('.'),
            '_return_fields+': 'soa_default_ttl',
            **({'view': self.dns_view} if self.dns_view else {}),
        }).json()

    def get_records(self, type, fields, zone, default_ttl):
        ret = self.get('record:{0}'.format(type.lower()), params={
            'zone': zone.rstrip('.'),
            '_return_fields+': ','.join(('ttl','use_ttl') + fields),
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
        } for r in rl]) for n, rl in dd.items() if rl]


class InfoBloxProvider(BaseProvider):

    SUPPORTS_GEO = False
    SUPPORTS_DYNAMIC = False
    SUPPORTS = set(('A', 'AAAA', 'CAA', 'CNAME', 'MX', 'NAPTR', 'PTR', 'SRV', 'TXT'))

    def __init__(
        self, id, gridmaster, username, password, verify=True, apiver=None,
        dns_view=None, network_view=None, *args, **kwargs
    ):
        self.log = logging.getLogger('{}[{}]'.format(
            self.__class__.__name__, id))
        self.conn = InfoBlox(gridmaster, username, password, verify, apiver, dns_view, network_view)
        self.conn.log = self.log
        self.log.debug(
            '__init__: id=%s, gridmaster=%s, username=%s, apiver=%s',
            id, gridmaster, username, self.conn.apiver)
        super(InfoBloxProvider, self).__init__(id, *args, **kwargs)

    def _data_for_multiple(self, type, key, zone, default_ttl):
        data = self.conn.get_records(type, (key,), zone, default_ttl)
        return [(ttl, name, [v[key] for v in values]) for ttl, name, values in data]

    def _data_for_A(self, zone, default_ttl):
        return self._data_for_multiple('A', 'ipv4addr', zone, default_ttl)

    def _data_for_AAAA(self, zone, default_ttl):
        return self._data_for_multiple('AAAA', 'ipv6addr', zone, default_ttl)

    # def _data_for_NS(self, zone, default_ttl):
    #     return self._data_for_multiple('NS', 'nameserver', zone, default_ttl)

    def _data_for_TXT(self, zone, default_ttl):
        return self._data_for_multiple('TXT', 'text', zone, default_ttl)

    def _data_for_CAA(self, zone, default_ttl):
        data = self.conn.get_records('CAA', ('ca_flag', 'ca_tag', 'ca_value'), zone, default_ttl)
        return [(ttl, name, [{
            'flags': v['ca_flag'],
            'tag': v['ca_tag'],
            'value': v['ca_value'],
        } for v in values]) for ttl, name, values in data]

    def _data_for_single(self, type, keys, zone, default_ttl):
        data = self.conn.get_records(type, keys, zone, default_ttl)
        return [(t, n, rl[0][list(rl[0])[0]]+'.') for t, n, rl in data]
        # return data[0][ret[list(ret)[0]]]

    # def _data_for_ALIAS(self, zone, default_ttl):
    #     return self._data_for_single('ALIAS', ('',), zone, default_ttl)

    def _data_for_CNAME(self, zone, default_ttl):
        return self._data_for_single('CNAME', ('canonical',), zone, default_ttl)

    def _data_for_PTR(self, zone, default_ttl):
        return self._data_for_single('PTR', ('ptrdname',), zone, default_ttl)

    def _data_for_MX(self, zone, default_ttl):
        data = self.conn.get_records('MX', ('preference', 'mail_exchanger'), zone, default_ttl)
        return [(ttl, name, [{
            'preference': v['preference'],
            'exchange': v['mail_exchanger'],
        } for v in values]) for ttl, name, values in data]

    def _data_for_NAPTR(self, zone, default_ttl):
        data = self.conn.get_records('NAPTR', ('order', 'preference', 'flags', 'services', 'regexp', 'replacement'), zone, default_ttl)
        return [(ttl, name, [{
            'order': v['order'],
            'preference': v['preference'],
            'flags': v['flags'],
            'service': v['services'],
            'regexp': v['regexp'],
            'replacement': v['replacement'],
        } for v in values]) for ttl, name, values in data]

    def _data_for_SRV(self, zone, default_ttl):
        data = self.conn.get_records('SRV', ('priority', 'weight', 'port', 'target'), zone, default_ttl)
        return [(ttl, name, [{
            'priority': v['priority'],
            'weight': v['weight'],
            'port': v['port'],
            'target': v['target'],
        } for v in values]) for ttl, name, values in data]

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
            data_for = getattr(self, '_data_for_{}'.format(_type))
            for t, n, v in data_for(zone.name, default_ttl):
                record_name = zone.hostname_from_fqdn(n)
                record = Record.new(zone, record_name, {
                    'ttl': t,
                    'type': _type,
                    'values' if isinstance(v, list) else 'value': v
                }, source=self, lenient=lenient)
                zone.add_record(record, lenient=lenient)

        return True

    def _apply(self, plan):
        pass
