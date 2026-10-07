# Configuration Reference

caddy-waf-ui is configured strictly via environment variables. When using Docker Compose, values are set in `.env` (file permissions `0600`, excluded from version control). After editing `.env`, recreate the containers with `docker compose up -d`; `docker compose restart` will not re-read modified `.env` files.

All file system paths must be set by operators via environment variables; they are never accepted from HTTP request inputs. Baseline WAF parameters (CRS mode, include paths, audit log parts) cannot be modified via the UI or REST API.

## Core Access & Caddy Connectivity

| Variable | Description | Default |
| --- | --- | --- |
| `CADDY_UI_TOKEN` | Secret token shared between browser authentication and API Bearer headers. Generate with `openssl rand -hex 32`. | None (Required in Compose) |
| `CADDY_UI_BIND` | Address and port for the UI HTTP server. | `0.0.0.0:8080` (Compose binds only to host `127.0.0.1:8080`) |
| `CADDY_ADMIN_URL` | Caddy Admin API endpoint: `unix:///absolute/path` or `http(s)://host:port`. Credentials cannot be embedded in URLs. | Standalone: `http://caddy:2019`; Compose: `unix:///run/caddy-admin/admin.sock` |
| `CADDY_UI_CADDYFILE` | Caddyfile path passed to `/load` (inside the UI container). | `/etc/caddy/Caddyfile` |
| `CADDY_UI_ACTOR_HEADER` | Request header populated by an authenticating reverse proxy (e.g., caddy-security). Recorded in change logs for auditing; does not bypass token checks. | Empty |
| `CADDY_UI_LOG_LEVEL` | Structured logging verbosity: `debug`, `info`, `warn`, or `error`. | `info` |

## Managed Sites & File Paths

| Variable | Description | Default |
| --- | --- | --- |
| `CADDY_UI_SITES` | Sites initialized by the `init` command, separated by commas or spaces. | `localhost` in Compose |
| `CADDY_UI_MANAGED_DIR` | Directory containing managed overlay files as seen by the UI sidecar. | `/ui-managed` |
| `CADDY_UI_INCLUDE_DIR` | Directory containing the same overlay files as seen by Caddy (used to verify imports during init). | `/etc/caddy/ui-managed` |
| `CADDY_UI_BACKUP_DIR` | Directory storing configuration rollback snapshots. | `/backups` |
| `CADDY_UI_BACKUP_KEEP` | Maximum snapshots retained per site per overlay type. | `10` |
| `CADDY_UI_DATA_DIR` | Directory for persistent UI data: normalized events, daily rollups, change logs, drafts, false-positive annotations, read offsets, and `last_good` state. | `/ui-data` |

## WAF Baseline Settings

| Variable | Description | Default |
| --- | --- | --- |
| `CADDY_UI_CRS_MODE` | `embedded` uses rules bundled inside the coraza-caddy module; `files` loads mounted rule files from disk. | `embedded` |
| `CADDY_UI_CORAZA_CONFIG` | Path or directive for the recommended Coraza base configuration. | `embedded`: `@coraza.conf-recommended`; `files`: `/etc/caddy/coraza.conf` |
| `CADDY_UI_CRS_SETUP` | Path or directive for CRS setup configuration. | `embedded`: `@crs-setup.conf.example`; `files`: `/etc/caddy/owasp-crs/crs-setup.conf` |
| `CADDY_UI_CRS_RULES` | Path or glob pattern for CRS rule includes. | `embedded`: `@owasp_crs/*.conf`; `files`: `/etc/caddy/owasp-crs/rules/*.conf` |
| `CADDY_UI_WAF_BEFORE_FILE` | Custom rules loaded before CRS (path inside Caddy container). | Empty; `/etc/caddy/waf-custom/before.conf` in Compose |
| `CADDY_UI_WAF_AFTER_FILE` | Custom rules loaded after CRS (path inside Caddy container). | Empty; `/etc/caddy/waf-custom/after.conf` in Compose |
| `CADDY_UI_RESPONSE_BODY_ACCESS` | `On` or `Off`. Keeping `Off` prevents buffering on streaming endpoints (SSE, large downloads). | `Off` |
| `CADDY_UI_AUDIT_LOG_PARTS` | Audit parts captured by Coraza. `AHKZ` records request line, URI, and matched rules. `ABHKZ` also captures request headers (including Cookies and Authorization, stored only locally). Neither captures body content. | `AHKZ` |
| `CADDY_UI_CRS_RULES_DIR` | Directory of rule files parsed at startup to build the rule dictionary (used when backend CRS differs from embedded dict or for custom rules). | Empty |

Paths must not contain whitespace, quotes, or braces. If you edit files in `before.conf` or `after.conf`, re-apply the current WAF mode in the UI to regenerate the site overlay with a new revision ID, forcing Coraza to instantiate a fresh engine.

## Audit Logs & Local Events

| Variable | Description | Default |
| --- | --- | --- |
| `CADDY_UI_AUDIT_LOG` | Path to the raw Coraza JSON audit log (shared path between Caddy and UI). | `/data/logs/coraza-audit.log` |
| `CADDY_UI_AUDIT_ROTATE_MB` | Maximum size in MiB before raw audit logs are rotated and Coraza reopens the file. Set to `0` to disable rotation. | `32` |
| `CADDY_UI_AUDIT_ARCHIVE_HOURS` | Retention in hours for rotated raw archives (minimum 48 hours), allowing on-demand local inspection of match fragments. | `48` |
| `CADDY_UI_INGEST_INTERVAL` | Polling interval for ingesting new audit log entries. | `2s` |
| `CADDY_UI_EVENTS_RETENTION_DAYS` | Retention period in days for normalized local event files (daily rollups are retained separately). | `14` |
| `CADDY_UI_EVENTS_DISK_MAX_MB` | Disk ceiling in MiB for normalized event files. Ingestion pauses when reached; events are not deleted prematurely. | `128` |
| `CADDY_UI_EVENTS_MEMORY_MAX` | Number of full event records kept in memory; older events are loaded on demand via file offsets. | `1000` |
| `CADDY_UI_REDACTION_LOCAL` | Local redaction level: `strict`, `standard`, or `full`. `standard` is recommended in example configs. | `strict` when unset in Compose |
| `CADDY_UI_REDACTION_CLOUD` | Cloud export redaction level: `strict`, `standard`, or `full`. Effective level cannot be broader than the local level. | `strict` |
| `CADDY_UI_REDACTION_HIDE` | Comma- or space-separated list of names always hidden at all levels, taking precedence over `KEEP`. | Empty |
| `CADDY_UI_REDACTION_KEEP` | Names exempt from standard credential heuristics; cannot override `strict` or `HIDE`. | Empty |
| `CADDY_UI_CLOUD_DISK_MAX_MB` | Disk ceiling in MiB for the independent cloud export queue. | `128` |
| `CADDY_UI_CLOUD_EXPORT` | Whether to write out redacted event replicas for Alloy. Set to `false` if not shipping to Grafana Cloud to save disk and CPU. Re-enabling backfills retained events. | `true` |
| `CADDY_UI_NODE` | Unique identifier for the origin node written into each event. Nodes sharing a Loki tenant must have distinct names. | System hostname; `caddy-local` in Compose |
| `CADDY_UI_PROBE_URLS` | JSON map of origin verification URLs per site, e.g., `{"chat.example.com":"https://origin.internal/__waf_health"}`. | Empty (Probing skipped) |

## IP Groups

| Variable | Description | Default |
| --- | --- | --- |
| `CADDY_UI_IPGROUP_DIR` | Read-only directory containing local group source files (inside UI container). | `/ipgroups` |
| `CADDY_UI_IPGROUP_MAX_PREFIXES` | Maximum allowed CIDR prefixes in a single group list. In standard images, evaluation time scales with prefix count; with `coraza-ipset`, lookup is O(log N). See [IP Groups](ip-groups.md#performance-and-list-size). | `100000` |
| `CADDY_UI_IPGROUP_PROXY` | Dedicated HTTP/HTTPS proxy used exclusively for downloading IP groups, e.g., `http://10.0.0.2:7890`. Defaults to `HTTPS_PROXY` / `NO_PROXY` if empty. | Empty |
| `CADDY_UI_IPGROUP_PATH` | (Compose only) Host directory mounted into `/ipgroups`. | `./ipgroups` |

See [IP Groups](ip-groups.md) for detailed configuration and strategies.

## Grafana Cloud & Metrics

| Variable | Description | Default |
| --- | --- | --- |
| `CADDY_UI_LOKI_URL` | Loki query base URL (without `/loki/api/v1/push`), e.g., `https://logs-prod-012.grafana.net`. | Empty (Remote queries disabled) |
| `CADDY_UI_LOKI_USER` | Loki tenant ID / user. Taken from `GRAFANA_CLOUD_LOKI_USER` in Compose. | Empty |
| `CADDY_UI_LOKI_TOKEN` | Read-only token scoped to `logs:read`. Taken from `GRAFANA_CLOUD_LOGS_READ_TOKEN` in Compose. | Empty |
| `CADDY_UI_LOKI_SELECTOR` | Log stream selector expression for event queries. | `{job="caddy-waf-ui",kind="event"}` |
| `CADDY_UI_LOKI_SYNC_INTERVAL` | Interval for pulling events from other cluster nodes locally; `0` enables on-demand querying only. | `0` |
| `CADDY_UI_GRAFANA_URL` | Grafana instance base URL used to render "Explore in Grafana" links on event details. | Empty |
| `CADDY_UI_GRAFANA_LOKI_DATASOURCE` | UID of the Loki datasource used in Grafana Explore URLs. | `grafanacloud-logs` |
| `CADDY_UI_METRICS_TOKEN` | Bearer token for accessing `/metrics`. When empty, `/metrics` returns HTTP 404. | Empty |

## Compose-Only Variables

| Variable | Description | Default |
| --- | --- | --- |
| `CADDY_IMAGE` | Container image tag or digest for the Caddy edge gateway. | `liukan/caddy-with-auth:latest` |
| `CADDYFILE_PATH` | Path to the Caddyfile on the host. | `./Caddyfile.example` |
| `EXAMPLE_APP_IMAGE` | Upstream demo application image. | `containous/whoami:v1.5.0` |
| `ALLOY_IMAGE` | Grafana Alloy collector image. | `grafana/alloy:v1.20.0` |
| `ALLOY_CONFIG_PATH` | Path to the Alloy configuration file. | `./alloy/config.alloy` |
| `GRAFANA_CLOUD_LOKI_URL` | Loki push endpoint for Alloy, including `/loki/api/v1/push`. | Empty |
| `GRAFANA_CLOUD_LOKI_USER` | Loki tenant ID shared between Alloy and UI. | Empty |
| `GRAFANA_CLOUD_LOGS_WRITE_TOKEN` | Write-only token scoped to `logs:write`, used exclusively by Alloy. | Empty |
| `GRAFANA_CLOUD_LOGS_READ_TOKEN` | Read-only token scoped to `logs:read`, used exclusively by the UI. | Empty |
| `GRAFANA_CLOUD_PROMETHEUS_URL` / `_USER` / `GRAFANA_CLOUD_METRICS_WRITE_TOKEN` | Optional Prometheus metric endpoint for Alloy. See [Metrics](metrics.md). | Empty |

## Resource Allocations (Compose Defaults)

| Component | Limit |
| --- | --- |
| Caddy | 512 MiB RAM, 1 CPU |
| UI Sidecar | 256 MiB RAM, 0.5 CPU |
| Alloy | 256 MiB RAM, 0.5 CPU (`GOMEMLIMIT=160MiB`) |
| Normalized Events Store | 14 days retention, 128 MiB disk ceiling |
| Analysis & Impact Estimation | 2,000 most recent matching events |

Rotated raw audit archives, snapshots, drafts, daily rollups, and Alloy position files are tracked outside the 128 MiB normalized events ceiling. Size the audit volume to accommodate at least 48 hours of rotated audit data.

For details on redaction levels, migration behavior, and examples, refer to [Configurable Redaction](redaction.md). The deprecated `CADDY_UI_MATCHED_VALUES` is kept solely for backward compatibility with bare binaries and should be migrated to the new variables.
