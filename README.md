# octoblox

Infoblox provider for [octoDNS](https://github.com/github/octodns)

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
    # log_change: false
```
