# Local investigation with Grafana Cloud storage

## Topology and resource budget

Keep `liukan/caddy-with-auth` as the ingress and WAF backend. The Go UI manages overlays, explanations and operator workflow. Optional Grafana Alloy ships metadata to Grafana Cloud Loki; the same local UI uses Loki's query API to retrieve history. No local Grafana/Loki database, SQL database or Redis is required. The Go application has no external dependencies.

Default Compose budgets:

| Component or buffer | Default |
| --- | --- |
| UI container memory ceiling | 256 MiB |
| Alloy container memory ceiling / Go memory target | 256 MiB / 160 MiB |
| Alloy CPU ceiling | 0.5 CPU |
| Full event cache | 1,000 events |
| Local normalized events | 14 days, 128 MiB ceiling |
| Separate cloud export queue | 14 days, 128 MiB ceiling, one-event cache |
| Analysis / impact sample | 2,000 newest matching events |
| Raw audit rotation threshold | 32 MiB, checked every 30 seconds |
| Raw archive late-write grace | 48 hours after last modification |
| Cloud background import | Disabled; direct paginated queries |

The local event index holds compact file offsets, timestamps and identities, rather than full historical records. Cache eviction does not remove detail pages or permit duplicate ingestion. Event identity includes node and transaction ID. The disk ceiling stops ingestion before advancing the source cursor; it does not delete unsent events to make space. Shorten retention or increase the disk budget if the pipeline reports full storage. Raw archives, backups, drafts, feedback, rollups and Alloy positions are additional disk use: the 128 MiB limit applies only to normalized event files. Size the audit disk for two days of rotated traffic. Rotation requires UI-managed WAF overlays and one UI writer per shared volume.

## Configure the cloud profile

Copy `.env.example`, set a strong UI token and retain your existing Caddy image tag/digest and topology. Fill:

```dotenv
# Alloy push endpoint: include the complete path supplied by Grafana Cloud.
GRAFANA_CLOUD_LOKI_URL=https://logs-REGION.grafana.net/loki/api/v1/push
# UI query API base: omit /loki/api/v1/push.
CADDY_UI_LOKI_URL=https://logs-REGION.grafana.net
GRAFANA_CLOUD_LOKI_USER=YOUR_LOGS_TENANT_ID
GRAFANA_CLOUD_LOGS_WRITE_TOKEN=YOUR_LOGS_WRITE_TOKEN
GRAFANA_CLOUD_LOGS_READ_TOKEN=YOUR_LOGS_READ_TOKEN
# Stable, unique origin identity for multi-node history.
CADDY_UI_NODE=origin-01
```

Create separate access-policy tokens scoped to `logs:write` for Alloy and `logs:read` for the UI. Keep `.env` mode 0600 and out of Git. The query URL, credentials and selector are operator configuration; end users cannot choose arbitrary upstream endpoints.

```sh
docker compose --profile cloud config --quiet
docker compose --profile cloud up -d --build
docker compose logs --tail=80 alloy caddy-waf-ui
```

For an existing deployment, merge the sidecar/data/init/Alloy entries following [INTEGRATION.md](INTEGRATION.md); preserve authentication, TLS volumes, trusted proxies and application networks. Alloy mounts only the log/data directories read-only and its own position directory read-write. It has neither the Docker socket nor the Caddy Admin socket. The UI mounts the raw audit directory read-write for rotation, not the certificate-bearing `/data` volume. The internal `waf-probe` network connects Caddy and UI for origin checks; Alloy uses the UI bridge for cloud egress.

## Logs and privacy

`alloy/config.alloy` collects four kinds:

| Kind | Cloud fields | Local-only data |
| --- | --- | --- |
| WAF event | Independently redacted event: strict by default, optionally standard/full | Raw audit file; detail removed by the cloud policy |
| Access | Method, path, site as a JSON field, client IP, peer IP, status, duration and size | Headers, query, user agent |
| Runtime | Timestamp, level, logger | Diagnostic message text |
| Change | Site, action, result, revision, SHA256, stage names/results | Actor, reason, error text, diff, draft contents and feedback |

Loki indexes bounded labels: job/kind and, where appropriate, managed site, action, node, result or level. IPs, paths, transaction IDs and rule IDs remain JSON fields. Arbitrary access Host headers are not indexed. `imported-*.jsonl` is never shipped again. Cloud history expects this normalized `kind="event"` schema, not arbitrary legacy Caddy/Coraza log formats.

Coraza's `RelevantOnly` engine writes every response whose status matches the baseline `SecAuditLogRelevantStatus` (400–419, 500–519), including upstream 404/401/5xx responses without any rule match. The UI skips records without rule matches, so they never become events or cloud data; they only use raw-log disk space until rotation.

The default `AHKZ` audit parts already contain method, URI and matched variables; `ABHKZ` additionally keeps request headers locally, which may contain secrets. Their normalized copies reach cloud only if the effective cloud policy retains them. Neither includes request or response bodies. Local and cloud redaction have separate strict/standard/full levels and hide/keep name overrides; see [REDACTION.md](REDACTION.md). Alloy reads `/ui-data/cloud/events`, not the richer local events. Path/parameter names and operator-written rule messages can themselves be sensitive. The legacy Logs page shows raw local diagnostics to authenticated operators.

Access/runtime records currently support broader cloud observability; this local UI's forensic pages query WAF events and the local change journal. Use Grafana Explore for the extra streams. Optional `alloy/metrics.alloy.example` can be appended to a copy of the logs config, selected with `ALLOY_CONFIG_PATH`, and enabled with a separate UI metrics token plus the Grafana metrics endpoint/write token. Metrics export is off by default; per-rule counters are dropped by the example to control series count.

## Investigate and adjust a rule

1. Open Events locally. Recent views read retained files; ranges longer than 24 hours use Loki when configured. Select Storage explicitly if needed, then filter by site, IP, path, action or rule. Older continues the cloud cursor; errors and incomplete timestamp-boundary history are visible.
2. Open an event. Each rule shows its ID, meaning, severity, paranoia level, score role and source; curated Chinese notes explain common rules. Paste `930130,949110` or `"rule_ids_csv":"930130,949110"` into Rules to resolve several IDs together. Unknown IDs are displayed explicitly, and a CRS version mismatch warns against assuming the installed dictionary matches historical behavior. Mount the actual rule tree with `CADDY_UI_CRS_RULES_DIR` for a different CRS version. Mounted before/after rules also supply custom-rule explanations at UI startup. **Show matched values** reads the event's raw record on demand from this node's audit log or its 48-hour archives; the lookup result is never stored or shipped and follows the configured local policy. A blocked event without a decision rule is usually the request body limit (HTTP 413 in On mode).
3. For the example, **930130** detects a restricted file such as `.env`; **949110** is the inbound anomaly-threshold decision. Review the detection hit and request context. Disabling 949110 would disable a blocking decision and is not offered as a tuning exception.
4. Follow Same path / Same client / Analyze this site. Analysis is heuristic, covers at most the newest 2,000 audited matches and does not represent total traffic. Truncated hits, early blocking, missing audit context and rules that never executed cannot be reconstructed. Re-enabling disabled groups may cause additional blocks that historical hits cannot predict.
5. Record `Confirmed false positive` or `Confirmed attack` with a reason. This decision remains local and never automatically creates an allowlist or exception.
6. Review a proposed rule/ARGS target/path exception or a per-site policy change. Select the impact history source. Prefer exact paths and target exceptions, optionally with a UTC expiry. Keep response body access Off for streaming APIs. Never exempt all `/api/` based on a heuristic alone.
7. Preview the generated diff and impact. Apply publishes the exact reviewed artifact, validates hashes and rejects edited intent, expired drafts (30 minutes) or changed baseline/custom files. A new preview is required after editing the form.
8. Inspect Changes. Stages distinguish validate/load/read-back/request verification and compensation. A successful origin check confirms the accepted revision and mode; a missing probe URL is explicitly skipped. Failed verification restores files and reloads the previous configuration. Typed backups and `releases/<site>/last_good` retain recovery evidence.

Impact is a score/exclusion estimate, not a replay of raw requests. Method/content-type/body-limit changes, early blocking, higher rules that did not execute and incomplete match sets have explicit caveats. Expiry is enforced by per-request `TIME_EPOCH`; requests already started before expiry can retain their prior transaction state. The authenticated direct API remains available for automation, with validation, journal and compensation, while browser policy/exclusion forms require a reviewed draft.

## Origin verification

Set a safe per-site origin URL independently of public routing:

```dotenv
CADDY_UI_PROBE_URLS={"chat.example.com":"http://caddy/__waf_health"}
```

The example stack uses `{"localhost":"http://caddy"}`. Keep each production origin on a network reachable from the UI, choose a side-effect-free GET path and ensure the site's Host routing matches. HTTPS verification remains enabled; the TLS server name is the managed site. Redirects are not followed. On mode verifies the synthetic probe's HTTP 418 plus audit signature; DetectionOnly verifies the audit signature while permitting normal upstream handling. Off verifies origin reachability and Admin revision read-back, with no WAF audit expected. Probe ID 9001200 is omitted from business event counts.

## What has been proven

See [VALIDATION.md](VALIDATION.md). Local tests use the actual backend image and actual Alloy with an isolated Loki protocol fixture. Grafana Cloud account credentials were not available for a real-cloud test. The supplied endpoints/tokens still need to be filled for your account; no production service was changed.

## LogFlux implementation references

The workflow borrows the verified candidate/apply/compensation and last-good patterns from [LogFlux's Caddy configuration service](https://github.com/GateCross/LogFlux/blob/d7bbc7aa38a212846463c748038e4e13828cc5ab/backend/internal/logic/caddy/simple_waf_config_service.go), while keeping this UI's overlay architecture and stdlib-only deployment. Base configuration/custom files remain operator-owned and read-only; SHA256 checks detect drift. The design preserves validated client IP versus peer IP as separate fields. It does not adopt automatic WAF bypass for API paths or IP-based hosts, and does not assume undocumented advanced features exist in the current LogFlux code.
