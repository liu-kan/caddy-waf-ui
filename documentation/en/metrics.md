# Metrics

caddy-waf-ui exposes operational telemetry via a Prometheus text-format `/metrics` endpoint. The endpoint is disabled by default: requests return HTTP 404 when `CADDY_UI_METRICS_TOKEN` is unset. Once configured, requests require `Authorization: Bearer <CADDY_UI_METRICS_TOKEN>`. This token is restricted strictly to scraping metrics and cannot authenticate to the web UI or management API. `/metrics` shares the API rate limiter of 120 requests/minute per source IP.

## Exported Metrics

| Metric | Type | Labels | Description |
| --- | --- | --- | --- |
| `waf_events_total` | counter | `site`, `action` | Newly ingested WAF events (`action`: `blocked`, `would_block`, `detected`). |
| `waf_rule_hits_total` | counter | `site`, `rule_id`, `action` | Rule match counts in events (counted once per rule per event, excluding decision rules). |
| `waf_reload_total` | counter | `result` | Caddy configuration reload attempts (`success` or `failed`). |
| `waf_ingest_errors_total` | counter | `kind` | Audit log ingestion errors (`read`, `parse`, `store`). |
| `waf_ingest_lag_bytes` | gauge | | Bytes remaining in the audit log waiting to be ingested. |
| `waf_ingest_last_poll_timestamp_seconds` | gauge | | Unix timestamp of the most recent audit tailer poll. |
| `waf_events_in_memory` | gauge | | Count of full event records cached in memory. |
| `waf_policy_info` | gauge (value 1) | `site`, `mode`, `blocking_pl`, `detection_pl`, `tuning` | Active WAF mode and policy parameters per managed site. |
| `waf_ipgroup_prefixes` | gauge | `group` | Prefix count in each active IP group feed. |
| `waf_ipgroup_checked_timestamp_seconds` | gauge | `group` | Unix timestamp of the most recent refresh check per IP group. |
| `waf_ipgroup_error` | gauge | `group` | Set to 1 if the most recent IP group feed download or parse failed. |
| `waf_ipgroup_pending` | gauge | `group` | Set to 1 if an updated IP group feed experienced a sudden drop in prefix count and awaits manual approval. |

Counters reset to 0 upon UI restart; evaluate them using `rate()` or `increase()`.

## Shipping Metrics to Grafana Cloud

Metric shipping is optional and managed independently from logs.

1. In your Grafana Cloud console, generate an Access Policy token scoped exclusively to `metrics:write`, noting the Prometheus remote_write URL and instance ID.
2. Merge the metrics collector snippet into your Alloy configuration:

   ```sh
   cat alloy/config.alloy alloy/metrics.alloy.example > alloy/config-metrics.alloy
   ```

3. Update `.env`:

   ```dotenv
   ALLOY_CONFIG_PATH=./alloy/config-metrics.alloy
   CADDY_UI_METRICS_TOKEN=          # openssl rand -hex 32
   GRAFANA_CLOUD_PROMETHEUS_URL=https://prometheus-prod-xx.grafana.net/api/prom/push
   GRAFANA_CLOUD_PROMETHEUS_USER=   # Instance ID
   GRAFANA_CLOUD_METRICS_WRITE_TOKEN=
   ```

4. Recreate Alloy: `docker compose --profile cloud up -d alloy`.

Alloy scrapes `caddy-waf-ui:8080/metrics` every 30 seconds. The example configuration drops `waf_rule_hits_total`: its cardinality scales as `site × triggered_rules × action`, which can easily consume free-tier limits of 10,000 active series. Query rule-level frequencies via the **Analysis** tab or Loki log streams instead.

## Recommended Alerting Rules

| Prometheus Condition | Severity / Action |
| --- | --- |
| `waf_ingest_lag_bytes` continuously growing | Ingestion pipeline stalled; typically indicates the normalized events disk ceiling has been reached. See [Audit Logs & Rotation](audit-log.md#disk-budget--ceilings). |
| `time() - waf_ingest_last_poll_timestamp_seconds > 300` | Ingestion tailer loop has crashed or stopped polling. |
| `increase(waf_ingest_errors_total{kind="store"}[15m]) > 0` | Events cannot be persisted to local disk (disk full or write permissions error). |
| `increase(waf_reload_total{result="failed"}[1h]) > 0` | Caddy configuration reload failure; inspect **Rollback & History** for stage details and errors. |
| `waf_policy_info{mode="Off"}` | A managed production domain has disabled WAF protection. |
| `waf_ipgroup_error == 1` for > 24h | An automated IP group list failed to refresh and continues using stale definitions. |
| `waf_ipgroup_pending == 1` | An IP group list underwent a major reduction in prefix count and is pending operator review. |
