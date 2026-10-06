# IP group sources

Files in this directory can be used as file sources on the **IP Groups**
page. Compose mounts it read-only into the UI at `/ipgroups`
(`CADDY_UI_IPGROUP_PATH` selects another host directory).

Supported formats, detected from the content:

- sing-box binary rule-sets (`.srs`, rule-set versions 1 to 5);
- sing-box source rule-sets (JSON);
- plain lists: one IP or CIDR per line, `#` starts a comment.

Only `ip_cidr` and `source_ip_cidr` rules are used; rules without IP
conditions (domains, ports, processes) are skipped. Rules that combine IP
CIDRs with other conditions, inverted IP rules and `and` logical rules over
IP rules are rejected, because they cannot be expressed as an IP list.

The UI checks file sources every minute and publishes a changed list to the
sites whose policies use the group.
