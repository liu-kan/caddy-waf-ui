# Integration with caddy-with-auth

This fork uses the existing [liu-kan/caddy-with-auth](https://github.com/liu-kan/caddy-with-auth) image. It requires `http.handlers.waf` from `corazawaf/coraza-caddy/v2` and Caddy's standard Admin API. It does not depend on Developmi image packaging and does not build a replacement backend.

## Preserve the existing entrypoint

Keep your existing Caddy service, image, `/data` and `/config` volumes, TLS/DNS credentials, caddy-security configuration, validated Cloudflare trusted proxies and application networks. Add this UI alongside it. Use the repository Compose as an isolated example, or merge the sidecar/init/volume entries into your existing deployment; do not run a second public listener on ports 80/443.

Within each managed site, insert the imports in a `route` block so Caddy preserves the intended handler order:

```caddyfile
chat.example.com {
    route {
        import /etc/caddy/ui-managed/ip-rules-chat_example_com.conf
        import /etc/caddy/ui-managed/waf-chat_example_com.conf
        # Keep your existing authenticate/authorize/routing here, with
        # their existing required order and matchers.
        reverse_proxy api:3080
    }
}
```

If your site already uses `route`/`handle`, add the imports in the applicable route without changing its matcher or authentication boundary. Remove that site's old WAF handler only after moving its custom rules to the before/after files. Do not stack two WAF engines in the same request path. A global `order coraza_waf first` alone does not put native IP rejection before WAF: `route` preserves their literal ordering.

Set `CADDY_UI_SITES=chat.example.com` (comma/space separated for several sites) and `CADDYFILE_PATH` to your existing base Caddyfile. Explicit imports use `domain.DomainSlug`: dots and hyphens become underscores. The initializer checks managed imports and fails if an imported domain was not initialized. It preserves real existing WAF configs, exclusions and IP lists; missing or comment-only WAF placeholders become working DetectionOnly configurations.

```sh
docker compose run --rm runtime-init
docker compose run --rm ui-config-init
docker compose exec caddy caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile
```

The service name is `caddy` in the supplied Compose; substitute the actual Compose service name in an existing stack. There is no dependency on a fixed container name.

## Volumes and UID

Caddy's DHI runtime and the UI both run as UID/GID 65532. Runtime UI permissions are narrow:

| Mount | Caddy | UI |
| --- | --- | --- |
| Base Caddyfile | `/etc/caddy/Caddyfile:ro` | Same path, read-only, used for `/load` |
| Managed overlays | `/etc/caddy/ui-managed:ro` | `/ui-managed:rw` |
| Backups | None | `/backups:rw` |
| Audit directory | `/data/logs:rw` | `/data/logs:rw` (rename/reopen rotation) |
| UI data (events, journal, drafts, cursors) | None | `/ui-data:rw` |
| Certificate data | `/data:rw` | Not mounted |
| Caddy config | `/config:rw` | Not mounted |
| Admin socket | `/run/caddy-admin:rw` | `/run/caddy-admin:ro` |
| Operator rules | `/etc/caddy/waf-custom:ro` | `/etc/caddy/waf-custom:ro` |
| IP group sources (optional) | None | `/ipgroups:ro` (`CADDY_UI_IPGROUP_DIR`) |

IP group lists are written by the UI into the managed overlay volume (`ipgroups/` subdirectory), which Caddy already mounts read-only; no Caddy change is needed. URL sources are downloaded by the UI over HTTPS, through `CADDY_UI_IPGROUP_PROXY` when set.

`runtime-init` runs once as root with only CHOWN/FOWNER/DAC_OVERRIDE capabilities. It prepares volume roots and migrates only UI-owned overlays/backups from their old UID, setting 0750 directories and 0640 files. It does not recursively chown certificate data or application/access logs. The regular Caddy and UI containers drop all capabilities except Caddy's NET_BIND_SERVICE.

For existing bind mounts, back up overlays and snapshots before migrating ownership. Grant UID 65532 read/write access to the UI-owned directories and to the audit log directory (rotation renames the raw file). Retain the existing log path and data: changing to a new empty audit volume would hide historical logs. Do not relax every log to 0644. Bind the audit directory separately into the UI rather than mounting all certificate data.

## Admin socket and HTTP compatibility

The default Caddyfile uses `admin unix//run/caddy-admin/admin.sock`. The UI uses `CADDY_ADMIN_URL=unix:///run/caddy-admin/admin.sock`; both containers mount a dedicated `caddy_admin` volume at `/run/caddy-admin` (read-only in the UI). The initializer sets its directory owner to 65532 and mode to 0700. No application container mounts the socket, and no TCP admin listener exists. This boundary does not depend on Docker/OrbStack inter-bridge routing behavior.

The UI connects using HTTP over the Unix socket, with Host localhost matching Caddy's default socket origins. It disables proxies/redirects for this transport. The existing HTTP/HTTPS Admin API URLs remain supported for operators integrating with an existing listener; retain an appropriate network/firewall boundary and never publish 2019. Merely placing containers on different bridges does not prove that they cannot route to the listener. Origins/Host lists are not caller authentication. Embedded URL credentials are rejected.

The regular UI bridge publishes only 127.0.0.1:8080; application traffic uses a separate edge bridge. A read-only Caddyfile/socket mount does not reduce Admin API authority: any process allowed to connect to that socket can replace all Caddy configuration. Only trusted sidecars may mount it.

The base Caddyfile must be mounted read-only into the UI; `/load` sends its full text with `Content-Type: text/caddyfile` and `Cache-Control: must-revalidate`. Imported files are resolved on Caddy's filesystem. Environment placeholders are expanded by Caddy, so retain the original Caddy environment/secrets. The read-back check confirms literal hosts, not full equivalence of every TLS/auth/WAF directive, and skips environment-based addresses. Verify actual requests after changes.

The DHI backend contains no shell/pgrep/curl/wget. The example removes its shell-based healthcheck and starts the UI after Caddy starts. The UI's HTTP healthcheck checks the UI server; successful Admin API operations establish backend connectivity. To validate Caddy manually, use its own `validate` command.

## Custom baseline and CRS

Defaults use the embedded CRS files. Operator-owned before/after includes let custom rule files survive mode changes. Paths are interpreted inside Caddy and must exist there. Move old inline custom rules into these files before reapplying a mode. UI mode/response-access/audit settings are applied last, so reserve those settings for the documented environment variables.

With `CADDY_UI_CRS_MODE=files`, defaults are `/etc/caddy/coraza.conf`, `/etc/caddy/owasp-crs/crs-setup.conf` and `/etc/caddy/owasp-crs/rules/*.conf`. Override them as needed and mount the rules/config into Caddy read-only. Embedded mode needs no such mounts. Apply the current mode in the UI after changing baseline settings or custom file contents.

New audit files use `SecAuditLogFileMode 0640`, directories 0750. `SecResponseBodyAccess Off` is the default for SSE/WebSocket and streaming API use; request inspection still runs. Defaults are a starting point: verify login, uploads, OAuth/MCP callbacks, streaming TTFB and long connections against your actual deployment before enabling blocking. The baseline `SecRequestBodyLimit` is 13107200 bytes: in On mode larger request bodies are rejected with HTTP 413 (DetectionOnly does not reject them). Raise the site policy's request body limit for upload endpoints before switching to On.

## Rule updates and recovery

Snapshots use nanosecond timestamps and exclusive creation; older second-resolution names remain valid. This prevents rollback from replacing its chosen snapshot when it backs up current state in the same second.

`exclusions-{slug}.conf` is the canonical UI list, not directly imported by Coraza. Generation compiles runtime parameter-conditioned rules before CRS, and static removals after CRS. A revision comment inside `directives` changes on each generation/refresh, preventing reuse of an old Coraza v2.6.1 WAF instance.

Exclusion changes/rollback snapshot and update both the canonical file and its derived WAF overlay. Reload failure restores both. Verification failure after a successful `/load` also triggers a compensating reload. Mutations are serialized within this UI process; run one UI writer per overlay volume. A failure of compensation is returned explicitly and requires operator recovery.

WAF and exclusion snapshots are independent. WAF rollback restores the snapshot's mode and policy and regenerates the overlay with the current baseline and canonical exclusion list; use an exclusion snapshot to roll back the list. Legacy snapshots without a policy line restore their mode with the default CRS policy.

Initialization preserves existing configs. To recover or reinitialize a site deliberately, back up its three overlay files, remove/move only that site's WAF file, then rerun `ui-config-init`. Do not remove whole volumes to reset a site: they contain certificates and backup history.

## Optional cloud history and local investigation

Follow [LOCAL-CLOUD.md](LOCAL-CLOUD.md) for Alloy, separate Loki read/write credentials, local rule explanations, reviewed artifacts, temporary exclusions and origin probes. Add persistent `caddy-ui-data` and `alloy-data` volumes, prepare UID 65532 ownership before startup and mount custom rules read-only into the UI as well as Caddy. The audit directory alone is writable by the UI for rename/reopen rotation; certificate data is not mounted. The example access/runtime file logging is an operator-owned Caddyfile change: merge its redaction/rotation rules into your existing log configuration deliberately.
