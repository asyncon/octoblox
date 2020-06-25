# octoblox

Infoblox provider for [octoDNS](https://github.com/github/octodns)

[![PyPI](https://img.shields.io/pypi/v/octoblox.svg)](https://pypi.org/project/octoblox/)
[![MIT](https://img.shields.io/pypi/l/octoblox.svg)](https://pypi.org/project/octoblox/)
[![Travis (.org)](https://img.shields.io/travis/asyncon/octoblox)](https://travis-ci.org/projects/asyncon/octoblox)
[![Python](https://img.shields.io/pypi/pyversions/octoblox.svg)](https://pypi.org/project/octoblox/)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

## Configure

```yaml
providers:
  infoblox:
    class: octoblox.InfoBloxProvider
    gridmaster: infoblox.example.com
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
```
