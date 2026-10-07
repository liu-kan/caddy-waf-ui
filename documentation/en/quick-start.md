# Quick Start

The repository includes a ready-to-run Docker Compose example: `liukan/caddy-with-auth` acts as the edge reverse proxy and WAF, `containous/whoami` serves as an example upstream application, and the UI listens strictly on the local loopback interface. The default example site is `localhost`.

## Starting the Stack

```sh
cp .env.example .env
chmod 600 .env
openssl rand -hex 32   # Set this generated value as CADDY_UI_TOKEN in .env
docker compose config --quiet
docker compose up -d --build
```

Open `http://127.0.0.1:8080` in your browser and log in using `CADDY_UI_TOKEN`.

Startup sequence:

| Service | Purpose |
| --- | --- |
| `runtime-init` | One-shot initialization container running as root with dropped capabilities (only `CHOWN`, `FOWNER`, `DAC_OVERRIDE`). Grants ownership of shared volume roots to UID/GID 65532 and restricts Admin socket directory permissions to 0700. |
| `ui-config-init` | One-shot container. Generates `DetectionOnly` WAF overlays, empty exclusion lists, and empty IP rules for sites defined in `CADDY_UI_SITES` without overwriting existing files. Validates that all imported files in the Caddyfile exist. |
| `caddy` | Runs the backend image unmodified (scratch/distroless-like, no shell, no shell-based healthchecks). Caddy Admin API listens exclusively on a Unix socket in the shared volume. |
| `caddy-waf-ui` | Management UI sidecar. Tails audit logs, manages the local event store, and issues reload requests to Caddy via the Unix socket. |
| `alloy` | Enabled only with the `cloud` profile. See [Grafana Cloud & Alloy](grafana-cloud.md). |

## Testing WAF Protection

```sh
curl -s -o /dev/null -w "%{http_code}\n" http://localhost/.env
```

Since the example site defaults to `DetectionOnly`, the request returns HTTP `200`, but triggers a "WOULD BLOCK" event in the WAF audit log. Navigate to the **Events** tab in the UI: you will see Rule `930130` (Restricted File Access) adding 5 anomaly points and Rule `949110` (Inbound Anomaly Score Exceeded) flagging an interception decision.

Go to **Domains & WAF**, change the site mode to `On`, and retry the curl request. The response will now be HTTP `403 Forbidden`.

## Architectural Conventions Worth Preserving

- The two overlay `import` directives inside each site block are nested within a `route` block, adhering to the order: IP Rules → WAF → Reverse Proxy.
- `CADDY_UI_PROBE_URLS={"localhost":"http://caddy"}` in `.env` instructs the UI to run an end-to-end HTTP health probe against the origin after every configuration change. See [Sites & WAF Modes](sites.md).
- The example Caddyfile configures `access.json` and `error.json` solely for Grafana Cloud telemetry (total request counts and runtime errors); these can be omitted if remote metrics and access logs are not needed.

To attach to an existing caddy-with-auth deployment, see [Integrating with an Existing Deployment](deployment.md). To use an image with compiled-in IP matching plugins (`coraza-ipset`), see [Deployment with coraza-ipset Image](ipset-image-deployment.md).
