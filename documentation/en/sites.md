# Sites & WAF Modes

The **Domains & WAF** tab (`/?tab=sites&domain=<site>`) manages the active Coraza engine mode for individual sites and displays the generated overlay file (`waf-<slug>.conf`). Mode toggle buttons are also accessible on the **Overview** page.

## Managed Sites

The UI discovers managed sites by scanning the overlay directory for `waf-*.conf` files and parsing the file header metadata: `# domain: … | mode: … | updated: …`. New sites are provisioned via `CADDY_UI_SITES` and `ui-config-init` (defaulting to `DetectionOnly`), with corresponding dual imports configured in the Caddyfile. See [Integrating with an Existing Deployment](deployment.md).

If the header mode cannot be parsed, the site is flagged with a **degraded** badge. This indicates that the UI state may differ from Caddy's running configuration; re-applying the desired mode restores clean synchronization.

## Three Operating Modes

| Mode | Rule Execution | Trigger Action | Audit Logging |
| --- | --- | --- | --- |
| `On` | Active | Requests meeting thresholds or matching direct blocking rules are blocked: HTTP 403 standard, HTTP 400 on body parsing errors. | Interrupted requests recorded as `BLOCKED`. |
| `DetectionOnly` | Active | Requests are not blocked; forwarded safely to upstream. | Requests that would have been blocked are logged as `WOULD BLOCK`. |
| `Off` | Disabled | Coraza engine is bypassed completely. | No audit logs generated. |

For newly introduced domains, maintain `DetectionOnly` mode for an initial burn-in window (ideally with [Tuning Mode](policy.md#tuning-mode) enabled). Review and tune false positives in **Analysis** before switching to `On`. Switching a site to `Off` requires explicit confirmation in the UI.

Toggling modes updates only `SecRuleEngine`; existing paranoia levels, anomaly thresholds, and exclusions remain intact.

## Publication Pipeline

Every change to WAF modes, policies, or rule exclusions executes a robust pipeline, recording all intermediate stages to the change journal:

| Stage | Operation | On Failure |
| --- | --- | --- |
| `validate` | Validates submitted parameters | Abort without modifying files |
| `(snapshot)` | Saves active file to `/backups/<slug>/` | Abort without modifying files |
| `load` | Generates new overlay with an incremented revision ID; submits Caddyfile to Admin API `/load` | Restore previous file |
| `readback` | Reads running configuration from Admin API to verify domain existence and active revision | Restore previous file and reload restored config via `/load` |
| `request` | Sends synthetic probe request to origin verifying that the new revision is actively serving traffic | Restore previous file and reload (compensating rollback stage) |

Upon successful completion across all stages, the validated overlay and stage telemetry are archived to `/ui-data/releases/<slug>/last_good.conf` and `last_good.json` as the verified golden revision.

Revisions are embedded as unique string comments within the `coraza_waf` directive. Because `coraza-caddy` caches WAF engine instances based on directive text, changing the revision string forces Coraza to recompile a fresh instance. Consequently, re-applying the current mode will also apply modifications to external `waf-custom` files.

## Origin Verification Probes

Configure origin probe endpoints in `.env` via `CADDY_UI_PROBE_URLS`:

```dotenv
CADDY_UI_PROBE_URLS={"chat.example.com":"https://caddy/__waf_health","localhost":"http://caddy"}
```

| Aspect | Behavior |
| --- | --- |
| Request | HTTP `GET` with `Host: <site>`, header `X-Caddy-WAF-Probe: <revision>`, 5s timeout. |
| TLS / SNI | Validates certificates with SNI matching site domain; redirects are never followed. |
| `On` Mode | Expects HTTP 418 (injected Rule `9001200` blocks probe requests matching the active revision) and confirms an audit entry with matching revision and `On` engine. |
| `DetectionOnly` Mode | Probe forwards to upstream; confirms an audit entry with matching revision and `DetectionOnly` engine. |
| `Off` Mode | Verifies origin reachability (non-5xx response); revision is verified during readback. |
| Failure Conditions | Upstream 5xx errors, connection timeouts, non-418 status in `On` mode, or missing audit log records within 5 seconds. |

Operational considerations:

- Probe URLs are configured strictly by operators via environment variables; they only accept `http`/`https` and reject embedded credentials, queries, or fragments.
- Endpoints must be routable from within the UI container. In Compose, the UI and Caddy communicate over the internal `waf-probe` bridge network (`http://caddy`).
- In `DetectionOnly` mode, probes reach the upstream backend. Point to safe, idempotent health check endpoints.
- If no probe URL is configured for a site, the `request` stage reports `skipped`, relying on `readback` validation.
- Probe transactions are discarded during ingestion and never appear as WAF events.

## REST API

| Endpoint | Description |
| --- | --- |
| `PUT /api/sites/{domain}/mode` | Switch mode: `{"mode":"On","reason":"..."}` (`On`, `DetectionOnly`, `Off`). |
| `GET /api/sites/{domain}/policy` | Returns active `mode`, `policy`, `revision`, `exclusions`, and `managed` status. |

```sh
curl -s -X PUT -H "Authorization: Bearer $CADDY_UI_TOKEN" -H "Content-Type: application/json" \
  -d '{"mode":"On","reason":"two weeks in DetectionOnly, false positives handled"}' \
  http://127.0.0.1:8080/api/sites/chat.example.com/mode
```
