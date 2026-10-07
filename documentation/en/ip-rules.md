# IP Rules

The **IP Rules** tab (`/?tab=iprules&domain=<site>`) configures per-site access controls based on client IP addresses. Directives are written to `ip-rules-<slug>.conf`, located before Coraza WAF in the site's `route` block, ensuring blocked connections are severed before reaching the WAF engine.

## Access Control Lists

| List | Generated Directive | Effect |
| --- | --- | --- |
| Denylist | `client_ip` matcher + `abort` | Matches on the list are abruptly terminated; connection dropped without sending HTTP responses. |
| Allowlist | `not client_ip` matcher + `abort` | **If this list is non-empty, all client IPs outside the list are abruptly disconnected.** |

The Allowlist functions as an exclusive gate, not a WAF bypass: addresses on the allowlist are still fully inspected by Coraza WAF. Use allowlists only for restricted environments such as internal administrative portals.

Entries can be individual IP addresses or CIDR blocks. Single IPv4 addresses are stored as `/32`; IPv6 addresses as `/128`. Unparseable entries are rejected.

## Client IP Resolution

`client_ip` resolution is performed by Caddy according to `trusted_proxies`:

- If a request arrives through a trusted proxy (e.g., Cloudflare IP ranges in caddy-with-auth), Caddy evaluates the real client IP forwarded in headers.
- If the request arrives directly or from an untrusted peer, Caddy evaluates the socket remote address. Arbitrary client headers are not trusted.

When deployed behind Cloudflare without trusted proxies configured, all connections appear to originate from Cloudflare edge nodes, rendering IP-based access rules ineffective. Ensure trusted proxy settings remain active.

## Adding and Removing Entries

The UI form appends entries (DENY or ALLOW) one at a time, deploying changes immediately to Caddy and logging them to the change history. Because IP rules do not affect WAF overlays, publishing stages consist of `validate`, `load`, and `readback`.

Individual deletions are not performed in the web UI. To remove entries:
- Submit the updated list via the REST API; or
- Restore a previous `ip-rules` snapshot under **Rollback & History**.

## IP Rules vs. IP Groups

| Dimension | IP Rules | [IP Groups](ip-groups.md) |
| --- | --- | --- |
| Evaluation Point | Caddy native routing (Pre-WAF) | Inside Coraza WAF (Pre-CRS) |
| Enforcement Action | Abrupt connection drop (`abort`), no event generated | HTTP 403 block (logs event), HTTP 403 ban (no event), trial mode, engine toggling, threshold tuning |
| Dataset | Manually curated, small address lists | Automated bulk feeds (sing-box rule-sets or CIDR files) with scheduled refreshes |
| Change Flow | Applied immediately | Diff preview, impact simulation, and snapshot rollback bundled with WAF policy |

Use IP Rules for immediate, low-latency drops of specific abusive IPs. Use IP Groups for country-level filtering, partner ranges, or dynamic blocklists.

## Integration with Threat Analysis

The **Analysis** tab surfaces suspected attacker IPs, but does not block them automatically. Before banning an IP, review its 14-day history in the event log to confirm it is not a shared egress IP (corporate NAT, mobile carrier, VPN). Long-term mitigation of large subnets is best enforced at upstream edge providers like Cloudflare.

## REST API

| Endpoint | Description |
| --- | --- |
| `PUT /api/sites/{domain}/iprules` | **Replaces** active rules: `{"allowlist":[],"denylist":["198.51.100.7","203.0.113.0/24"]}`. Reason can be supplied via `X-Change-Reason` header. |

```sh
curl -s -X PUT -H "Authorization: Bearer $CADDY_UI_TOKEN" -H "Content-Type: application/json" \
  -H "X-Change-Reason: scanner confirmed on event YqBrJkwPrpHwOYMd" \
  -d '{"allowlist":[],"denylist":["198.51.100.7"]}' \
  http://127.0.0.1:8080/api/sites/chat.example.com/iprules
```
