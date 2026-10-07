# Upgrade Notes

This document highlights behavioral changes compared to upstream caddy-waf-ui 1.2.0 and details the migration steps from legacy deployments. For fresh installations, refer directly to [Quick Start](quick-start.md) and [Integrating with an Existing Deployment](deployment.md).

## Deployment Architecture

| Aspect | Version 1.2.0 | Current Architecture |
| --- | --- | --- |
| Backend Image | `ghcr.io/developmi/caddy-waf` (`CADDY_WAF_IMAGE`) | `liukan/caddy-with-auth` (`CADDY_IMAGE`), run unmodified |
| Site Definitions | `SITE_ADDRESS`, `BACKEND_UPSTREAM`, `ACME_EMAIL` | Use your own Caddyfile (`CADDYFILE_PATH`); managed domains specified via `CADDY_UI_SITES` |
| Admin API | `admin 0.0.0.0:2019`, UI accessed via `http://caddy-waf:2019` | Default Unix socket `unix//run/caddy-admin/admin.sock`; HTTP remains supported |
| UI Mounts | Certificate volume `/data` mounted read-only | Only `/data/logs` mounted (read-write for log rotation); dedicated `/ui-data` volume added |
| Initialization | `init-ui-managed.sh` | One-shot services: `runtime-init` (ownership) and `ui-config-init` (overlay provisioning) |
| Caddy Healthcheck | `pgrep caddy` | Removed (DHI runtime has no shell) |
| Cloud Export | Not supported | Optional `alloy` service (`cloud` profile) |

## WAF Configuration

- **Embedded CRS**: Uses CRS bundled inside coraza-caddy by default (`load_owasp_crs`, `@coraza.conf-recommended`, `@crs-setup.conf.example`, `@owasp_crs/*.conf`). Eliminates dependency on `/etc/caddy/coraza.conf` and disk-mounted rule files. Set `CADDY_UI_CRS_MODE=files` to restore mounted files.
- **Inlined Exclusions**: `exclusions-<slug>.conf` is now a canonical UI database rather than an included snippet; Caddyfiles only import `ip-rules-<slug>.conf` and `waf-<slug>.conf` inside the site's `route` block.
- **Revisions and Signatures**: Generated overlays include incrementing revision IDs and `SecComponentSignature` to track policy lineage in event records. Legacy overlays are regenerated upon the next policy change.
- **Custom Rules**: Place custom directives in `waf-custom/before.conf` (pre-CRS) and `after.conf` (post-CRS) instead of writing inline `coraza_waf` blocks.

## Feature Additions

| Feature | Description |
| --- | --- |
| IP Rules | Uses Caddy's `client_ip` matcher (honoring trusted proxies). Legacy `remote_ip` files are migrated on save. Terminology clarified: Denial aborts connections (`abort`); Allowlist provides explicit bypass. |
| Exclusions | Added support for specific parameter names, URL path scopes, expiry dates, and operator notes. Disruptive rules (949110), control rules, and UI signature rules can no longer be disabled via exclusions. |
| Rollback | WAF snapshots restore mode and paranoia/threshold policies while recompiling overlays against current exclusions; exclusion lists roll back independently. Snapshot timestamps feature nanosecond precision. |
| Publishing Pipeline | Added readback validation, origin health probing, and automated compensating rollback; intermediate stages are logged to change history. Successful configurations are tagged as `last_good`. |
| Pages | Added Events, Analysis, Rules, and Policy pages; legacy Logs tab renamed to Raw Audit Log. Overview statistics now derive from the local event store. |
| Policy Mutation Flow | Web UI modifications enforce a "Preview Diff → Apply" flow verified by SHA256-hashed drafts. |
| REST API | Preserved existing endpoints while adding support for rich parameters, event queries, rule dictionaries, policy mutations, impact analysis, and Loki backfilling. |
| Metrics | Added Prometheus `/metrics` endpoint (disabled by default unless token is configured). |
| IP Groups | Added **IP Groups** tab: automated ingestion of sing-box rule-sets (.srs/JSON) or CIDR lists, supporting block, ban, trial, engine switching, and threshold scaling. See [IP Groups](ip-groups.md). |

## Audit Logging

- Audit parts are governed by `CADDY_UI_AUDIT_LOG_PARTS` (defaults to `AHKZ`, omitting bodies and headers). Set to `ABHKZ` when header inspection is required.
- The UI handles log rotation: files exceeding 32 MiB are renamed and Coraza is signaled to reopen logs. Do not run external logrotate daemons concurrently.
- Benign requests (upstream 404, 401, or 5xx responses that triggered zero WAF rules) are filtered out and no longer generate events.

## Migrating from 1.2.0

1. Back up `caddy-ui-config` (overlays) and `caddy-ui-backups` (snapshots) volumes.
2. Update `.env` per [Configuration Reference](configuration.md): `CADDY_IMAGE`, `CADDYFILE_PATH`, `CADDY_UI_SITES`, and `CADDY_UI_TOKEN`.
3. Update Caddyfile: Switch `admin` to Unix socket; insert dual imports inside each site's `route` block; remove legacy exclusion includes and manual `coraza_waf` blocks (moving custom rules to `waf-custom/`).
4. Initialize and validate:

   ```sh
   docker compose run --rm runtime-init
   docker compose run --rm ui-config-init
   docker compose run --rm --no-deps --entrypoint /usr/local/bin/caddy caddy \
     validate --config /etc/caddy/Caddyfile --adapter caddyfile
   ```

5. Rebuild and launch: `docker compose up -d --build`.
6. Re-apply the active mode for each site in the UI to generate modern overlays; verify in **Rollback & History** that `load`, `readback`, and `request` succeed.
7. Send a test probe to `/.env` and verify event creation and matching CRS versions.

## Independent Local and Cloud Redaction (2026-10-06)

Replace legacy `CADDY_UI_MATCHED_VALUES` with `CADDY_UI_REDACTION_LOCAL` and `CADDY_UI_REDACTION_CLOUD`. Recommended settings: local `standard`, cloud `strict`. Alloy must read `/ui-data/cloud/events/events-*.jsonl`; reading `/ui-data/events` directly is deprecated to prevent leaking rich local diagnostics. Existing local events are migrated to the export queue on first startup. If not using Grafana Cloud, set `CADDY_UI_CLOUD_EXPORT=false`. Raw audit retention is configurable via `CADDY_UI_AUDIT_ARCHIVE_HOURS` (minimum 48 hours). See [Configurable Redaction](redaction.md).

## IP Groups (2026-10-06)

Compose adds a read-only volume mount: `${CADDY_UI_IPGROUP_PATH:-./ipgroups}:/ipgroups`. When integrating with an existing deployment, add this mount to the UI container or set `CADDY_UI_IPGROUP_DIR`. Generated IP group files are saved to `ipgroups/` inside the managed overlay volume, accessible to Caddy without additional mounts.
