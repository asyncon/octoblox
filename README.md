# OctoBlox

Infoblox provider for [octoDNS](https://github.com/github/octodns)

[![PyPI](https://img.shields.io/pypi/v/octoblox.svg)](https://pypi.org/project/octoblox/)
[![MIT](https://img.shields.io/pypi/l/octoblox.svg)](https://github.com/asyncon/octoblox/blob/master/LICENSE)
[![Travis (.org)](https://img.shields.io/travis/asyncon/octoblox)](https://travis-ci.org/projects/asyncon/octoblox)
[![Python](https://img.shields.io/pypi/pyversions/octoblox.svg)](https://pypi.org/project/octoblox/)
[![Downloads](https://pepy.tech/badge/octoblox)](https://pepy.tech/project/octoblox)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

OctoBlox provides the glue for enterprise migration to
[GitOps](https://www.gitops.tech/) with [Infoblox](https://www.infoblox.com/).

## Installation

```sh
pip install octoblox
```

## Configure

```yaml
providers:
  infoblox:
    class: octoblox.InfoBloxProvider
    endpoint: infoblox.example.com
    username: admin
    password: env/INFOBLOX_PASSWORD
    # verify: ./infoblox.pem
    # apiver: 1.0
    # dns_view: default
    # log_change: true
    # alias_types:
    #   - A
    #   - AAAA
    #   - TXT
    # create_zones: true
    # new_zone_fields:
    #   grid_primary:
    #     - name: infoblox.example.com
    #   ns_group: default
    #   restart_if_needed: true
    #   soa_default_ttl: 3600
    #   view: default
    #   use_grid_zone_timer: true
```

## Alias Record Update Behaviour

Infoblox allows for an alias record per DNS record type.
By default OctoBlox will ensure both A and AAAA records are created.
This can be changed using the `alias_types` parameter.

In the event that too many or not enough record types exist for a single record,
the discovered target value will have `invalid.` appended to make sure that
a record update is generated. This value was chosen as it's specifically listed
in [RFC2606](https://tools.ietf.org/html/rfc2606#section-2) for this purpose.

This will result in octoDNS reporting that the value is incorrect when the
reality is that the number of ALIAS records is incorrect. While it is possible
that both are the case this is unlikely and OctoBlox can handle this as well.

### Use of Lenient Flag for Alias Records

OctoDNS has implemented a behavior of not accepting alias records for non-root
zone entries by default. To get around this provide the `--lenient` flag when
dumping from InfoBlox with alias records.

When storing alias entries in YAML ensure that you add the octodns lenient
entry to the record like so:

```yaml
---
alias:
  octodns:
    lenient: true
  type: ALIAS
  value: www.example.com.
```

Alternatively you can set a zone level lenient flag like so:

```yaml
---
example.com.:
    octodns:
      lenient: true
    sources:
    - yaml
    targets:
    - infoblox
```

Refer to the [octoDNS entry on lenience][lenience] for more information.

[lenience]: https://github.com/octodns/octodns/blob/master/docs/records.md#lenience
