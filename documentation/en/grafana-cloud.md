# Grafana Cloud & Alloy

Grafana Cloud integration is an optional capability. When enabled, Grafana Alloy forwards redacted WAF events and minimal operational metadata to Grafana Cloud Loki. Event inspection, rule explanation, and retrospective analysis continue to run directly in the local UI, which queries Loki using a read-only token. You do not need to operate Loki, Grafana, or a time-series database locally.

When disabled, the UI relies strictly on local event files (retained for 14 days by default), and all other management features remain fully operational.

## Data Shipped to Cloud

Alloy reads strictly from UI persistent volumes and log directories (both mounted read-only). Configuration is defined in `alloy/config.alloy`.

| Kind | Source | Shipped Fields | Excluded / Not Shipped |
| --- | --- | --- | --- |
| `event` | `/ui-data/cloud/events/events-*.jsonl` | WAF events processed under the cloud redaction policy. `strict` preserves rule IDs, variable names, path, and scores. | Raw audit logs and fields stripped by cloud policy. Explicit `full` sends captured credentials. |
| `change` | `/ui-data/changes/changes.jsonl` | Site, action, outcome, revision, SHA256, pipeline stage names and results. | Operator usernames, reasons, error messages, diffs, drafts, false-positive annotations. |
| `access` | Caddy `access*.json` (configured in Caddyfile) | Site, client IP, remote IP, HTTP method, path, status, latency, request size. | Request headers, query strings, User-Agent. |
| `runtime` | Caddy `error*.json` | Timestamp, log level, logger name. | Log message body. |

Files named `imported-*.jsonl` (events backfilled from Loki), local rich event files, raw audit logs, configuration snapshots, and policy drafts are excluded from shipping. The export queue is written by the UI; deployments not using Grafana Cloud can set `CADDY_UI_CLOUD_EXPORT=false` to stop writing export files. See [Configurable Redaction](redaction.md#files-and-inspection).

Index labels are restricted to low-cardinality attributes: all streams include `job="caddy-waf-ui"` and `kind`. `event` adds `site`, `action`, `node`; `change` adds `site`, `action`, `result`; `runtime` adds `level`. Dynamic attributes (`tx`, `ip`, `rule_ids_csv`, `path`, `rev`) are stored as structured metadata rather than indexed labels to prevent time-series explosion. `access` avoids indexing on Host headers.

## Configuration & Integration (Step-by-Step Guide)

Integrating Grafana Cloud Loki and Alloy involves generating scoped credentials in the Grafana Cloud portal and setting environment variables in your local `.env`. Follow these step-by-step instructions:

### Step 1: Retrieve Loki User ID and Host URL

1. Sign in to your [Grafana Cloud Portal](https://grafana.com/) (`grafana.com/orgs/<your-org>`).
2. Under **My Account / Cloud Portal**, locate your stack and click **Details** on the **Loki / Logs** service tile (or select Loki from your Hosted Services list).
3. Note the connection details displayed:
   - **User / Tenant ID**: Typically a numeric ID (e.g., `123456`), assigned to `GRAFANA_CLOUD_LOKI_USER`.
   - **Host URL**: Formatted like `https://logs-prod-012.grafana.net`.

> [!IMPORTANT]
> **Critical URL Differences**:
> - **Alloy Push URL** (`GRAFANA_CLOUD_LOKI_URL`): Must include the full path `/loki/api/v1/push` (e.g., `https://logs-prod-012.grafana.net/loki/api/v1/push`).
> - **UI Query URL** (`CADDY_UI_LOKI_URL`): Must be the base URL and **must NOT** include `/loki/api/v1/push` (e.g., `https://logs-prod-012.grafana.net`), as the UI internally appends `/loki/api/v1/query_range`.

### Step 2: Create Scoped Access Policies and Tokens

To maintain least-privilege security, Alloy (push-only) and the local UI (query-only) must use two separate Access Policy tokens rather than a shared or administrative key:

1. In the Grafana Cloud Portal left navigation, go to **Security** -> **Access Policies** (or click **Manage Access Policies** on the Loki Details page).
2. **Create the Alloy push policy and token**:
   - Click **Create access policy**.
   - **Policy Name**: Enter `caddy-waf-alloy-write`.
   - **Scopes**: Select only **`logs:write`**.
   - **Label Policies**: Leave default to allow all labels, or ensure `job="caddy-waf-ui"` and its derived labels are permitted.
   - Click **Create** to save the policy.
   - On the newly created policy card, click **Add token**.
   - **Token Name**: Enter `alloy-logs-write`.
   - Choose expiration (e.g., No expiration or preferred cycle).
   - Click **Create**, copy the generated token string (starts with `glc_...`), and save it as `GRAFANA_CLOUD_LOGS_WRITE_TOKEN`.
3. **Create the UI read-only policy and token**:
   - Click **Create access policy** again.
   - **Policy Name**: Enter `caddy-waf-ui-read`.
   - **Scopes**: Select only **`logs:read`**.
   - Click **Create** to save the policy.
   - On the policy card, click **Add token**.
   - **Token Name**: Enter `ui-logs-read`.
   - Click **Create**, copy the generated token string (starts with `glc_...`), and save it as `GRAFANA_CLOUD_LOGS_READ_TOKEN`.

### Step 3: (Optional) Configure Grafana URL and Datasource UID

To enable the **Open in Grafana Explore** deep-link in local event details:

1. Note your Grafana instance root URL (e.g., `https://my-company.grafana.net`), assigned to `CADDY_UI_GRAFANA_URL`.
2. Open that Grafana instance, navigate to **Connections** -> **Data sources**.
3. Select the default Loki data source (typically named `grafanacloud-logs`) and locate its **UID** in the settings. The default UID is usually `grafanacloud-logs`, assigned to `CADDY_UI_GRAFANA_LOKI_DATASOURCE`.

### Step 4: Populate Local `.env` File

Add the following block to your project's `.env` file:

```dotenv
# ==============================================================================
# Grafana Cloud Loki & Alloy Configuration
# ==============================================================================

# Alloy push endpoint (must end with /loki/api/v1/push)
GRAFANA_CLOUD_LOKI_URL=https://logs-prod-012.grafana.net/loki/api/v1/push

# Local UI query endpoint (root domain, do NOT include /loki/api/v1/push)
CADDY_UI_LOKI_URL=https://logs-prod-012.grafana.net

# Loki User ID / Tenant ID (numeric string from Loki Details page)
GRAFANA_CLOUD_LOKI_USER=123456

# Alloy write token (scoped strictly to logs:write)
GRAFANA_CLOUD_LOGS_WRITE_TOKEN=glc_...write_token...

# UI read token (scoped strictly to logs:read)
GRAFANA_CLOUD_LOGS_READ_TOKEN=glc_...read_token...

# Origin node identifier (unique across nodes in a cluster)
CADDY_UI_NODE=origin-01

# (Optional) Grafana instance URL & datasource UID for Explore deep-linking
CADDY_UI_GRAFANA_URL=https://my-company.grafana.net
CADDY_UI_GRAFANA_LOKI_DATASOURCE=grafanacloud-logs

# Ensure cloud export pipeline is enabled (default true)
CADDY_UI_CLOUD_EXPORT=true
```

### Step 5: Start Containers with Cloud Profile

Because Alloy is assigned to `profiles: [cloud]` in Compose, you must specify `--profile cloud` when running:

```sh
# 1. Validate Compose syntax and environment resolution
docker compose --profile cloud config --quiet

# 2. Start all services including Alloy
docker compose --profile cloud up -d --build

# 3. Stream container initialization logs
docker compose logs --tail=80 -f alloy caddy-waf-ui
```

Alloy operates under limits of 256 MiB RAM and 0.5 CPU (`GOMEMLIMIT=160MiB`). Its read offsets are persisted in the `alloy-data` volume to resume gracefully across restarts. Alloy mounts volumes read-only and does not touch the Docker socket or Caddy Admin socket.

### Step 6: End-to-End Verification

Verify both the push and query paths:

1. **Trigger a test WAF event**:
   Send a sample request matching CRS inspection rules:
   ```sh
   curl -I "http://127.0.0.1/?test=<script>alert(1)</script>"
   ```
2. **Inspect Alloy logs**:
   ```sh
   docker compose logs --tail=50 alloy
   ```
   Within 1 second, Alloy batches and forwards the event to Loki. Confirm there are no HTTP 401/403/404 errors.
3. **Verify ingestion in Grafana Explore**:
   - Open your Grafana Cloud instance and go to **Explore**.
   - Select the Loki data source (`grafanacloud-logs`).
   - Run the LogQL query:
     ```logql
     {job="caddy-waf-ui", kind="event"}
     ```
   - Confirm the ingested event line appears along with indexed labels (`site`, `action`, `node`) and structured metadata (`tx`, `ip`, `rule_ids_csv`, `path`, `rev`).
4. **Verify remote querying in the Local UI**:
   - Visit the local UI at `http://127.0.0.1:8080/events`.
   - Switch the **Storage** dropdown from "Local (14d)" to "Grafana Cloud Loki".
   - Confirm historical events load cleanly without error banners.
   - Click an event row to inspect details and verify that the **Open in Grafana Explore** link opens the corresponding log window in Grafana Cloud.

---

## Troubleshooting & FAQ

| Symptom / Error | Root Cause | Resolution |
| --- | --- | --- |
| **HTTP 401 Unauthorized** (Alloy push or UI query) | 1. Incorrect `GRAFANA_CLOUD_LOKI_USER` number.<br>2. Token string truncated or contains stray spaces.<br>3. Write token and read token swapped. | 1. Check Loki Details for the exact numeric user ID.<br>2. Re-copy token string, verifying `glc_` prefix.<br>3. Verify Alloy has the write token and UI has the read token. |
| **HTTP 403 Forbidden** (Push or query rejected) | 1. Missing scope in Access Policy.<br>2. Label Policy filters out labels. | 1. Ensure write policy has `logs:write` and read policy has `logs:read`.<br>2. Verify Label Policies do not disallow `job="caddy-waf-ui"`. |
| **HTTP 404 Not Found** (Push fails or query fails) | Malformed URL path. | **Check URL suffix**:<br>- `GRAFANA_CLOUD_LOKI_URL` **must** end with `/loki/api/v1/push`.<br>- `CADDY_UI_LOKI_URL` **must NOT** include `/loki/api/v1/push` (domain root only). |
| **Alloy container does not start** | Launched without cloud profile. | Run `docker compose --profile cloud up -d` or add `COMPOSE_PROFILES=cloud` to your `.env` file. |
| **Alloy runs clean but no events in Grafana** | 1. No WAF events triggered locally.<br>2. Cloud export disabled (`CADDY_UI_CLOUD_EXPORT=false`). | 1. Send test attack payloads to produce audit events.<br>2. Ensure `CADDY_UI_CLOUD_EXPORT=true`.<br>3. Verify that `/ui-data/cloud/events/events-*.jsonl` files are being generated. |
| **"Open in Grafana Explore" links break or 404** | 1. `CADDY_UI_GRAFANA_URL` unconfigured.<br>2. Datasource UID mismatch. | 1. Set your Grafana instance URL (e.g., `https://org.grafana.net`).<br>2. Check your data source settings in Grafana and update `CADDY_UI_GRAFANA_LOKI_DATASOURCE=<uid>`. |

## Free-Tier Budget Management

Grafana Cloud's free tier provides 50 GB/month log storage with 14-day retention and 10,000 active metric series.

| Telemetry | Average Record Size | Usage Notes |
| --- | --- | --- |
| WAF Events | ~1.5 KB avg, ~3 KB max | Raw audit records (~16 KB) are never shipped. |
| Access Logs | ~0.2 KB | Typically represents the majority of volume: 1M reqs/day ≈ 6 GB/month. |
| Changes, Runtime | Negligible | Very low volume. |

For high-traffic environments, comment out the `access` block in `alloy/config.alloy` or remove `access.json` output from the Caddyfile. Metric shipping is disabled by default; see [Metrics](metrics.md).

## Viewing Cloud History Locally

When `CADDY_UI_LOKI_URL` is configured:

- The **Storage** selector on the **Events** and **Analysis** pages allows selecting "Grafana Cloud Loki". Time ranges greater than 24 hours query Loki by default.
- Remote event queries use cursor-based pagination via **Older →**. If queries error or record bursts sharing identical timestamps exceed limits, clear notices are displayed.
- Opening a cloud event loads matching site events from the past 14 days in Loki (up to 2,000 events) for exclusion recommendations and impact analysis.
- Setting `CADDY_UI_GRAFANA_URL` renders an **Open in Grafana Explore** deep-link on event details.

### Backfilling to Local Storage

The **Backfill** action on the **Events** tab pulls cloud events from the past 24 hours, 7 days, or 14 days into local storage (saved as `imported-*.jsonl`, never re-shipped). Once imported, queries run faster and participate in 14-day rule statistics on the **Rules** page.

In multi-node architectures, configure `CADDY_UI_LOKI_SYNC_INTERVAL` (e.g., `10m`) to let the UI automatically import events recorded by peer nodes. Defaults to `0` (on-demand querying only).

Imported events are deduplicated by `(node, tx_id)`. Only the specific origin node that generated an event can read its raw audit context (see [WAF Events](events.md#local-raw-match-context)).

## REST API

| Endpoint | Description |
| --- | --- |
| `GET /api/events?source=loki` | Query cloud events using local query parameters plus `cursor` (from previous `next_cursor`); `more=true` indicates older records remain. |
| `GET /api/events/{tx}?node=&ts=` | Fetch a single event from Loki when absent locally; `ts` narrows search windows. |
| `POST /api/loki/backfill` | Import a historical time range: `{"from":"2026-10-01T00:00:00Z","to":"2026-10-06T00:00:00Z"}` (max 31 days). |

```sh
curl -s -H "Authorization: Bearer $CADDY_UI_TOKEN" \
  "http://127.0.0.1:8080/api/events?source=loki&range=7d&rule=930130&limit=50"
```
