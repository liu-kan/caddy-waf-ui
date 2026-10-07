# IP Groups

The **IP Groups** tab (`/?tab=ipgroups`) manages named collections of IP addresses, such as country geo-ranges, corporate office ranges, partner networks, or threat intelligence feeds. Sources can be imported from sing-box rule-sets or CIDR text files, loaded from volume mounts, or fetched periodically over HTTPS. Sites apply group-specific rules within their [WAF Policy](policy.md): blocking, banning, trial observation, engine switching, or paranoia/threshold tuning.

IP Group rules execute inside Coraza WAF (`@ipMatchFromFile`), supporting diff previews, impact simulations, and configuration rollbacks. They operate independently from Caddy's pre-WAF [IP Rules](ip-rules.md).

## Feed Formats

Feed formats are detected automatically by content inspection:

| Format | Description |
| --- | --- |
| sing-box binary rule-set (`.srs`) | Binary rule-sets (versions 1–5), matching output from `sing-box rule-set compile`. |
| sing-box source rule-set (JSON) | `{"version": 3, "rules": [{"ip_cidr": [...]}]}`. |
| Plain text | One IP or CIDR per line; comments begin with `#`. |

Rule extraction logic:

| Rule Structure | Extraction Handling |
| --- | --- |
| Rules containing only `ip_cidr` / `source_ip_cidr`, or composite `or` blocks | Merged into the IP group. |
| Non-IP rules (domain, AdGuard, port, process, network type, etc.) | Skipped safely (skipped count reported on group card). |
| Complex rules mixing IP with other constraints (e.g., `ip_cidr` + `port`), inverted IP rules, or `and` rules | Feed rejected: cannot be cleanly represented as pure IP ranges. |

During ingestion, overlapping and contiguous subnets are merged into minimal CIDR sets, named by content SHA256 in the overlay volume (`ipgroups/<name>.<hash12>.txt`). IPv4-mapped IPv6 addresses are normalized to IPv4. A single list can contain up to `CADDY_UI_IPGROUP_MAX_PREFIXES` (default 100,000) prefixes.

## Feed Sources

| Source | Configuration | Refresh Schedule |
| --- | --- | --- |
| File | Filename inside `CADDY_UI_IPGROUP_DIR` (host `./ipgroups` mounted to `/ipgroups` in Compose); directory traversals rejected. | Polled every minute for size and mtime changes. |
| URL | Must use `https://` without embedded credentials; refresh interval 1h–720h (default 24h). | Fetched conditionally via ETag / Last-Modified; 15-minute retry on failure. |

Country feeds can be sourced directly from MetaCubeX's sing-box rule-sets (e.g., `https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/sing/geo/geoip/jp.srs`). When content is unchanged, servers return HTTP 304, preventing unnecessary re-compilations.

Downloads follow up to 5 redirects over HTTPS, capped at 32 MiB (64 MiB decompressed). Configure `CADDY_UI_IPGROUP_PROXY=http://proxy:port` if downloads require an outbound HTTP proxy.

Safety safeguards:
- Empty or malformed lists never overwrite active lists; errors are flagged and existing definitions remain active.
- If a downloaded list experiences an abrupt reduction of more than 50% in prefix count (with at least 20 active prefixes previously), it is staged for review. Operators must click **Approve** or **Discard**. This prevents upstream feed glitches from accidentally breaking production whitelists.

## Dashboard Operations

| Action | Description |
| --- | --- |
| Add / Update | Name (1–32 alphanumeric chars, `-`, `_`), source type, path or URL, refresh interval, and notes. Imported immediately on save. |
| Refresh now | Bypasses cache headers to force an immediate re-fetch. |
| Approve / Discard | Resolves staged feed updates that experienced sudden shrinkage. |
| Publish again | Re-publishes overlays if a previous reload failed. |
| Delete | Deletes unused groups; rejected if referenced by active site policies. |
| Which groups hold | Diagnostic tool checking group membership for a given IP address. |

When group content changes, the UI automatically regenerates and deploys all site overlays referencing that group. Obsolete list files are purged after 24 hours of zero active references.

## Group Rules

Configured under **IP group rules** on the **Policy** tab, executed in Phase 1 before CRS:

| Action | Effect | Rule ID | Audit Event |
| --- | --- | --- | --- |
| `block` | Returns HTTP 403; bypasses CRS | 9002000+ | Logged as `BLOCKED` (`WOULD BLOCK` on DetectionOnly sites) |
| `ban` | Returns HTTP 403; bypasses CRS without writing audit logs | 9002000+ | No event generated; appears as 403 in access logs. (`DetectionOnly` sites log "would block" for observation) |
| `trial` | Does not block; logs requests to audit log | 9002000+ | Logged as `WOULD BLOCK` event |
| `engine` | Overrides WAF engine: `On`, `DetectionOnly`, or `Off` | 9002500+ | Matched rules written to audit log (no standalone event) |
| `tune` | Overrides PL and thresholds for matched clients | 9002500+ | Events scored and evaluated using overridden thresholds |

Rules evaluate clients using **inside any** (matches any selected group) or **outside all** (matches none of the selected groups). Multiple groups in a single rule are merged into a unified set (`ipgroups/_union.<hash12>.txt`), requiring only a single lookup per request. Examples:

| Objective | Rule Configuration |
| --- | --- |
| Allow CN and JP only; drop all other traffic silently | `cn`, `jp` · `outside all` · `ban` |
| Restrict admin portal to office network with event logging | `office` · `outside all` · `block` |
| Audit impact before enforcing geo-whitelist | `cn`, `jp` · `outside all` · `trial` |
| Relax anomaly thresholds for high-volume partners | `partners` · `inside any` · `tune` · Inbound 10 |
| Bypass WAF for internal synthetic monitors | `monitors` · `inside any` · `engine Off` |
| Increase paranoia level for international traffic | `cn` · `outside all` · `tune` · Blocking PL 2 |

Execution semantics:
- `block` and `ban` immediately terminate request processing.
- When multiple `engine` or `tune` rules match, subsequent rules override earlier ones.
- Rules following `engine Off` are not executed.
- Raising blocking PL automatically raises detection PL to prevent CRS Rule 901500 errors.
- UI origin health probes (Rule 9001200) execute before IP group rules and are never intercepted.

## Performance and List Size

Matching performance depends on your backend container image:

- **Standard Images**: Coraza evaluates `@ipMatchFromFile` sequentially until finding a match. Whitelists evaluate every inbound request: allowed traffic traverses half the list on average before reaching CRS, while banned traffic scans the entire list. Latency scales linearly with prefix count.
- **Images with coraza-ipset plugin** (`liukan/caddy-with-auth:coraza-plugins-ipset`): The plugin evaluates merged sorted ranges using binary search, keeping evaluation latency flat regardless of list size. See [Backend Image](backend-image.md#ip-matching-plugin-coraza-ipset).

Benchmark comparison on identical hardware (Apple M1 Max, single-core Caddy, loopback keep-alive, merged prefixes):

| Scenario | Prefix Count | Standard Image | Image with coraza-ipset |
| --- | --- | --- | --- |
| Normal request passing CRS (no group rule) | — | ~0.38 ms (2,670 rps) | ~0.38 ms (2,650 rps) |
| CN + JP Whitelist: Allowed request | 26,730 | ~0.46 ms (2,190 rps) | ~0.38 ms (2,660 rps) |
| CN + JP Whitelist: Banned request | 26,730 | ~0.30 ms (3,330 rps) | ~0.055 ms (18,250 rps) |
| CN + JP + US Whitelist: Allowed request | 281,382 | ~1.06 ms (940 rps) | ~0.37 ms (2,690 rps) |
| CN + JP + US Whitelist: Banned request | 281,382 | ~2.70 ms (360 rps) | ~0.055 ms (18,240 rps) |

Memory consumption: Standard images load independent list copies per site (~19 MiB for CN+JP+US). The plugin shares sorted ranges globally across the process (~2 MiB for CN+JP+US).

Recommendations:
- **Standard Image**: Keep rule lists under 30,000 prefixes (adding ~0.1 ms latency). Large lists like US (260,000+ CIDRs) should be filtered at upstream CDNs.
- **Plugin Image**: List size does not impact request latency; configure `CADDY_UI_IPGROUP_MAX_PREFIXES` as needed.

## REST API

| Endpoint | Description |
| --- | --- |
| `GET /api/ipgroups` | List all groups with feed status, staged updates, errors, and referencing sites. |
| `PUT /api/ipgroups/{name}` | Create/update group: `{"source":"url","url":"...","refresh":"24h","reason":"..."}`. |
| `DELETE /api/ipgroups/{name}` | Delete group (returns 409 if in active use). |
| `POST /api/ipgroups/{name}/refresh` | Trigger immediate refresh (`?force=true` ignores cache). |
| `POST /api/ipgroups/{name}/approve` / `/discard` | Resolve staged feed update. |
| `GET /api/ipgroups/lookup?ip=203.0.113.7` | Check group membership for IP. |

Set group rules via the `ip_groups` array in `PUT /api/sites/{domain}/policy`:

```json
{
  "policy": {
    "blocking_pl": 1,
    "inbound_threshold": 5,
    "outbound_threshold": 4,
    "ip_groups": [
      {"groups": ["cn", "jp"], "negate": true, "action": "ban", "note": "allow CN and JP only"},
      {"groups": ["partners"], "action": "tune", "inbound_threshold": 10},
      {"groups": ["monitors"], "action": "engine", "engine": "Off"}
    ]
  },
  "reason": "allow CN and JP"
}
```
