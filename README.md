# caddy-waf-ui

A self-hosted management sidecar for [caddy-with-auth](https://github.com/liu-kan/caddy-with-auth), using the standard Caddy Admin API and Coraza Caddy v2 module. The backend image is reused as-is; only this UI is built here.

This fork is based on [Developmi/caddy-waf-ui](https://github.com/Developmi/caddy-waf-ui), under its original MIT license. It retains bearer/session authentication, CSRF protection, rate limiting, per-site mode controls, exclusions, IP lists, audit log search and typed rollback.

Chinese documentation (中文文档): [documentation/zh/README.md](documentation/zh/README.md) covers deployment, configuration, the backend image, Grafana Cloud, every page and its REST API.

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
| `CADDY_UI_AUDIT_LOG_PARTS` | `AHKZ` | Method, URI and rule matches; `ABHKZ` also keeps request headers locally. No request/response bodies |
| `CADDY_UI_AUDIT_LOG` | `/data/logs/coraza-audit.log` | Same audit path inside Caddy and UI |
| `CADDY_UI_MANAGED_DIR` | `/ui-managed` | UI view of the overlay volume |
| `CADDY_UI_INCLUDE_DIR` | `/etc/caddy/ui-managed` | Caddy view, used for bootstrap import verification |
| `CADDY_UI_BACKUP_DIR` | `/backups` | Typed configuration snapshots |
| `CADDY_UI_BACKUP_KEEP` | `10` | Retention per domain and snapshot type |
| `CADDY_UI_BIND` | `0.0.0.0:8080` | Container listener; Compose publishes only host loopback |
| `CADDY_UI_LOG_LEVEL` | `info` | UI application logging level |

Empty custom-file variables disable those optional includes in standalone runs. Compose supplies its mounted sample files. Include paths must not contain whitespace or quotes.

## Updates and rollback

Exclusions are stored in `exclusions-{slug}.conf` as the canonical editable list, then compiled into the generated WAF directives. Runtime exclusions run before custom/CRS rules. Parameter exceptions use `ctl:ruleRemoveTargetById` (or by tag) for the selected ARGS target; exact/prefix path scopes are available. Configure-time removals follow rule loading. Optional UTC expiry is enforced per request by Coraza, without a scheduled reload.

Every regeneration refreshes a random revision comment **inside** `directives`. This invalidates Coraza v2.6.1's WAF pool even when only an external custom include changed or the operator reapplies the same mode. Header timestamps outside the block are insufficient. After editing an operator-owned custom file, reapply the site's current mode in the UI.

Snapshots include nanoseconds and use exclusive creation, so rapid updates and rollback cannot overwrite the selected snapshot. Legacy second-resolution names remain supported. Changes serialize the full backup/write/reload/restore transaction. Exclusion changes and exclusion rollback also update the WAF overlay. A rejected reload restores both files. If `/load` succeeds but its verification fails, the service reloads the restored files to recover live state. WAF rollback restores the snapshot's mode and policy, then regenerates the overlay with the current baseline and the current independent exclusion list; use an exclusions snapshot to roll back that list. Legacy snapshots without the policy line restore their mode with the default CRS policy.

## Cloudflare and audit logs

IP allow/deny rules use Caddy's `client_ip` matcher. Retain your existing trusted proxy/strict-header configuration from `caddy-with-auth`. Without a trusted proxy match, `client_ip` falls back to the direct peer; the UI does not trust arbitrary forwarding headers. Old `remote_ip` overlay files remain readable in the editor and become `client_ip` rules when saved.

Both containers use UID/GID 65532. UI overlays and new audit files are 0640, with 0750 directories. The UI receives only the audit directory read-write for safe rename/reopen rotation, not the certificate-bearing `/data` volume. Existing audit files are not made world-readable by the initializer.

`BLOCKED` reflects Coraza's actual interruption flag rather than a configured `deny` action. The Events page uses durable normalized history; the legacy Logs page remains a recent raw-audit diagnostic view. The Rules page accepts `930130,949110` or a copied `"rule_ids_csv":"930130,949110"` field, and shows each rule's meaning, CRS version, source, score role and curated Chinese notes. In an event, detection rules and the final threshold decision appear together: 930130 detects a restricted-file request; 949110 evaluates the accumulated inbound score and is not offered as an exclusion.

## Cloud storage with local viewing

[LOCAL-CLOUD.md](LOCAL-CLOUD.md) documents the complete deployment and review workflow. Optional Alloy ships redacted WAF events, access metadata, runtime metadata and configuration-change metadata to Grafana Cloud Loki. The local UI queries Loki directly, displays rule explanations and retrospective analysis, records operator decisions and previews policy changes. No local Loki, Grafana, SQL database or Redis is required.

```sh
# Fill the separate logs:write and logs:read credentials described in LOCAL-CLOUD.md.
docker compose --profile cloud config --quiet
docker compose --profile cloud up -d --build
```

Recent views use local retained files. When Loki is configured, event and analysis ranges longer than 24 hours default to cloud queries; the Storage selector lets you choose either source. Cloud history is paginated rather than copied wholesale into memory. Impact previews have their own history selector. Analysis and impact are bounded estimates over the newest 2,000 audited matches, never total traffic counts or a raw-request replay.

Configure local and cloud redaction independently with `CADDY_UI_REDACTION_LOCAL` and `CADDY_UI_REDACTION_CLOUD`: strict, standard or full. The recommended example keeps standard diagnostic context locally and sends strict events to cloud. Hide/keep name overrides and the effective levels are described in [REDACTION.md](REDACTION.md). Alloy reads only the independently redacted `/ui-data/cloud/events` queue; deployments that never ship to Grafana Cloud can set `CADDY_UI_CLOUD_EXPORT=false`. On-demand raw lookup and legacy log viewing follow the local policy. AHKZ omits headers; ABHKZ records them locally. Full explicitly retains collected credentials unless hide matches; it does not enable body logging.

Raw audit rotation defaults to 32 MiB: rename, reopen each managed WAF writer through a revision change, and continue ingesting the archive. Archives are kept `CADDY_UI_AUDIT_ARCHIVE_HOURS` after their last write (default and minimum 48, the late-write grace period) and are removed only after ingestion reaches EOF; on-demand local match context selects the archive by the event time, so a longer retention keeps older raw context available. `CADDY_UI_AUDIT_ROTATE_MB=0` disables automatic rotation. This is bounded retention with recoverable cursors, not a guarantee of lossless transport during an indefinitely long outage. Monitor disk space and the pipeline status.

## IP groups

The **IP Groups** page imports named IP lists from sing-box rule-sets (binary `.srs`, versions 1 to 5, or JSON source) or plain CIDR lists. Sources are files in the read-only `/ipgroups` mount (`CADDY_UI_IPGROUP_PATH`, default `./ipgroups`) or HTTPS URLs downloaded on a schedule (default every 24 hours, with ETag/Last-Modified revalidation and an optional `CADDY_UI_IPGROUP_PROXY`). Only `ip_cidr`/`source_ip_cidr` rules are used; domain, port and process rules are skipped, and rules that combine IP CIDRs with other conditions are rejected. Lists are normalized into content-addressed CIDR files on the managed volume; an empty list never replaces the active one and a list that loses more than half of its prefixes waits for approval.

Site policies attach ordered rules to groups, evaluated by Coraza with `@ipMatchFromFile` before the CRS rules: `block` (403), `trial` (audit what block would deny), `engine` (On, DetectionOnly or Off) and `tune` (paranoia levels and anomaly thresholds), each for clients inside or outside a group. They are previewed, estimated against history, applied and rolled back with the rest of the policy; a changed list is republished to every site that uses the group. Coraza compares the client address with every prefix of a list, so keep lists small (about 0.15 ms per 10,000 prefixes per rule in the worst case on an Apple M-series CPU). See the [Chinese guide](documentation/zh/ip-groups.md).

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

It covers actual DetectionOnly/On/Off behavior, exclusion expiry without reload, exclusion update/rollback, external include refresh at the same mode, trusted visitor IP rejection, SSE event timing, multipart upload, callback paths and WebSocket upgrade/frame forwarding.
