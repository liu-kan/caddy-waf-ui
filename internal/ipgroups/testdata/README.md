# sing-box rule-set fixtures

Each `.srs` file was compiled from the `.json` source of the same name with
sing-box v1.14.2's own encoder (`srs.Write`, the code behind
`sing-box rule-set compile`). Each `.expected` file lists the IP prefixes
that sing-box's decoder (`srs.Read`) yields for the rules usable as an IP
group: default rules holding only `ip_cidr`/`source_ip_cidr`, and `or`
logical rules made of them. The IP ranges are documentation and private
ranges or seeded random data; no third-party list is included.

| Fixture | Rule-set version | Purpose |
| --- | --- | --- |
| `ip-v1` | 1 | Legacy version, IPv4 and IPv6 |
| `ip` | 3 | Two IP rules, overlapping and adjacent prefixes |
| `mixed` | 5 | IP rules among domain, AdGuard, port, process, network and interface-address rules that must be skipped |
| `random` | 3 | 3,600 random IPv4/IPv6 prefixes |
| `mixed-condition` | 3 | `ip_cidr` combined with `port`: rejected |
| `inverted` | 3 | Inverted IP rule: rejected |
| `logical-and` | 3 | `and` logical rule over IP rules: rejected |
