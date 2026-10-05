# caddy-waf-ui

A self-hosted management sidecar for [caddy-with-auth](https://github.com/liu-kan/caddy-with-auth), using the standard Caddy Admin API and Coraza Caddy v2 module. The backend image is reused as-is; only this UI is built here.

This fork is based on [Developmi/caddy-waf-ui](https://github.com/Developmi/caddy-waf-ui), under its original MIT license. It retains bearer/session authentication, CSRF protection, rate limiting, per-site mode controls, exclusions, IP lists, audit log search and typed rollback.

## Start the example

```sh
cp .env.example .env
chmod 600 .env
openssl rand -hex 32
```

The default backend is `liukan/caddy-with-auth:latest`. Set `CADDY_IMAGE` to your existing published `caddy-with-auth` tag or digest, and set `CADDY_UI_TOKEN` to the generated token. Then:

```sh
docker compose config --quiet
docker compose up -d --build
```

The Compose stack builds only the UI. `runtime-init` sets volume-root ownership and migrates UI-owned overlays/backups to UID/GID 65532. `ui-config-init` seeds real DetectionOnly WAF configurations before Caddy starts, retaining all existing nonempty rules and lists. The example serves `localhost` through the optional `example-app`. Open the UI at `http://127.0.0.1:8080`.

Caddy runs its original shell-free DHI runtime. There is no shell/pgrep/curl healthcheck on that image. The UI has its own HTTP healthcheck; real reload requests check the Admin API and read back the accepted hosts. The default Admin API listens on a Unix socket in a dedicated shared volume; only Caddy and the UI mount it. There is no TCP admin listener or published port 2019. The UI uses its own bridge solely to publish the loopback UI port.

For deployment into an existing stack, use [INTEGRATION.md](INTEGRATION.md). Keep its certificate volumes, trusted proxy settings, authentication/authorization and reverse proxy behavior. Do not launch a second public Caddy alongside an existing owner of ports 80/443.

## WAF baseline

The default generator uses `load_owasp_crs` with `@coraza.conf-recommended`, `@crs-setup.conf.example` and `@owasp_crs/*.conf`. These are embedded in the maintained Coraza Caddy v2 module, so `/etc/caddy/coraza.conf` and a disk CRS installation are unnecessary. The ruleset version follows the version compiled into your backend image.

Operator-owned custom rules live in `waf-custom/before.conf` and `waf-custom/after.conf`, mounted read-only into Caddy. Move existing inline WAF overrides into these files before handing a site to the UI. Mode changes keep these includes and the configured baseline. To use an existing disk ruleset instead, set `CADDY_UI_CRS_MODE=files`, configure the three include paths, and mount those files into Caddy. No backend rebuild is needed.

| Variable | Default | Purpose |
| --- | --- | --- |
| `CADDY_IMAGE` | `liukan/caddy-with-auth:latest` | Existing caddy-with-auth image tag/digest |
| `CADDYFILE_PATH` | `./Caddyfile.example` | Host Caddyfile, mounted read-only into Caddy and UI |
| `CADDY_UI_SITES` | `localhost` in Compose | Comma/space-separated domains to initialize |
| `CADDY_ADMIN_URL` | `unix:///run/caddy-admin/admin.sock` in Compose | Socket or HTTP/HTTPS management URL; standalone default is `http://caddy:2019` |
| `CADDY_UI_TOKEN` | Required by Compose | UI/API authentication token |
| `CADDY_UI_CRS_MODE` | `embedded` | `embedded` or mounted `files` |
| `CADDY_UI_CORAZA_CONFIG` | Depends on CRS mode | Base configuration include |
| `CADDY_UI_CRS_SETUP` | Depends on CRS mode | CRS setup include |
| `CADDY_UI_CRS_RULES` | Depends on CRS mode | CRS rules include/glob |
| `CADDY_UI_WAF_BEFORE_FILE` | `waf-custom/before.conf` mount in Compose | Optional pre-CRS custom rules |
| `CADDY_UI_WAF_AFTER_FILE` | `waf-custom/after.conf` mount in Compose | Optional post-CRS custom rules |
| `CADDY_UI_RESPONSE_BODY_ACCESS` | `Off` | Avoid response buffering for streaming APIs |
| `CADDY_UI_AUDIT_LOG_PARTS` | `AHKZ` | Omit request/response headers and bodies by default |
| `CADDY_UI_AUDIT_LOG` | `/data/logs/coraza-audit.log` | Same audit path inside Caddy and UI |
| `CADDY_UI_MANAGED_DIR` | `/ui-managed` | UI view of the overlay volume |
| `CADDY_UI_INCLUDE_DIR` | `/etc/caddy/ui-managed` | Caddy view, used for bootstrap import verification |
| `CADDY_UI_BACKUP_DIR` | `/backups` | Typed configuration snapshots |
| `CADDY_UI_BACKUP_KEEP` | `10` | Retention per domain and snapshot type |
| `CADDY_UI_BIND` | `0.0.0.0:8080` | Container listener; Compose publishes only host loopback |
| `CADDY_UI_LOG_LEVEL` | `info` | UI application logging level |

Empty custom-file variables disable those optional includes in standalone runs. Compose supplies its mounted sample files. Include paths must not contain whitespace or quotes.

## Updates and rollback

Exclusions are stored in `exclusions-{slug}.conf` as the canonical editable list, then compiled into the generated WAF directives. Parameter-conditioned runtime exclusions are placed before CRS rules, and configure-time rule removals after CRS loading. A parameter-conditioned exclusion currently disables the whole selected rule when that parameter exists; it is not a per-target `ruleRemoveTarget` exception. No URI condition is offered by this UI.

Every regeneration refreshes a random revision comment **inside** `directives`. This invalidates Coraza v2.6.1's WAF pool even when only an external custom include changed or the operator reapplies the same mode. Header timestamps outside the block are insufficient. After editing an operator-owned custom file, reapply the site's current mode in the UI.

Snapshots include nanoseconds and use exclusive creation, so rapid updates and rollback cannot overwrite the selected snapshot. Legacy second-resolution names remain supported. Changes serialize the full backup/write/reload/restore transaction. Exclusion changes and exclusion rollback also update the WAF overlay. A rejected reload restores both files. If `/load` succeeds but its verification fails, the service reloads the restored files to recover live state. WAF rollback restores its own baseline/mode and retains the current independent exclusion list; use an exclusions snapshot to roll back that list. Legacy WAF snapshots without the new managed regions retain their original bytes; migrate them by reapplying a mode before relying on the new contract.

## Cloudflare and audit logs

IP allow/deny rules use Caddy's `client_ip` matcher. Retain your existing trusted proxy/strict-header configuration from `caddy-with-auth`. Without a trusted proxy match, `client_ip` falls back to the direct peer; the UI does not trust arbitrary forwarding headers. Old `remote_ip` overlay files remain readable in the editor and become `client_ip` rules when saved.

Both containers use UID/GID 65532. UI overlays and new audit files are 0640, with 0750 directories. The UI receives only the audit volume read-only, not the certificate-bearing `/data` volume. Existing audit files are not made world-readable by the initializer.

`BLOCKED` reflects Coraza's actual interruption flag rather than a rule's configured `deny` action; DetectionOnly matches remain `DETECTED`. A standalone `allow` interruption is not a denial. Legacy logs without the flag still use their action fields. The viewer reads Coraza JSON, not Caddy access/error JSON, and shows only the last 2 MiB of recent records. It is not a replacement for historical Grafana/Loki analysis.

The default `AHKZ` omits the request section, so the URI column can be empty. To retain request URI and headers, opt into `ABHKZ` and consider the resulting credential/header exposure. Rule messages and matched fragments may contain sensitive data even with `AHKZ`. Restrict access and configure retention/rotation before shipping logs externally.

## Development and verification

```sh
go test -race ./...
go vet ./...
golangci-lint run
CADDY_IMAGE=example/caddy-with-auth:test CADDY_UI_TOKEN=validation-only docker compose config --quiet
```

The application remains stdlib-only. `make` exposes the upstream build, lint and release gates. Docker integration requires a running Docker daemon; local tests are not evidence that a production container or deployment has been validated. See [ARCHITECTURE.md](ARCHITECTURE.md) and [SECURITY.md](SECURITY.md) for component and trust boundaries.

## License

MIT; original copyright and attribution are retained in [LICENSE](LICENSE).

To run the opt-in real-Caddy request test with an existing native binary containing the WAF module:

```sh
CADDY_TEST_BINARY=/absolute/path/to/caddy go test ./tests/integration -run TestRealCaddyWAFUpdatesAndStreaming -v
```

It covers actual DetectionOnly/On/Off behavior, exclusion update/rollback, external include refresh at the same mode, trusted visitor IP rejection, SSE event timing, multipart upload, callback paths and WebSocket upgrade/frame forwarding.
