# Integrating with an Existing Deployment

This guide explains how to add caddy-waf-ui as a sidecar alongside an existing caddy-with-auth deployment. Retain your existing Caddy service, container image, certificate storage (`/data`, `/config`), DNS provider credentials, caddy-security authentication, Cloudflare trusted proxy settings, and application networks. Do not launch a second Caddy container listening on ports 80/443.

## Modifying the Caddyfile: Add Two Imports Per Site

Inside each managed site's `route` block, import the IP rules and WAF overlays before downstream authentication, authorization, and reverse proxy directives:

```caddyfile
chat.example.com {
	route {
		import /etc/caddy/ui-managed/ip-rules-chat_example_com.conf
		import /etc/caddy/ui-managed/waf-chat_example_com.conf
		# Existing authenticate / authorize / route directives remain in their original order
		reverse_proxy api:3080
	}
}
```

- Site names must be standard hostnames (letters, numbers, `-`, `.`), without wildcard asterisks or port numbers. Dots (`.`) and hyphens (`-`) in the hostname translate to underscores (`_`) in filenames (e.g., `chat.example.com` maps to `waf-chat_example_com.conf`).
- Directives must be placed inside a `route` block. The global `order coraza_waf first` directive alone cannot guarantee that IP access lists evaluate before WAF rule evaluation.
- If the site already contains `route` or `handle` blocks, insert the imports into the appropriate route while preserving existing matchers and security boundaries.
- Do not stack multiple WAF instances in a single request execution path. If manual `coraza_waf` blocks previously existed, migrate custom rules to `waf-custom/before.conf` or `after.conf` before removing the manual block.

## Initialization

Configure the following variables in your `.env` file:

| Variable | Description |
| --- | --- |
| `CADDYFILE_PATH` | Path to your production Caddyfile on the Docker host |
| `CADDY_UI_SITES` | Managed domain names, separated by commas or spaces (e.g., `chat.example.com,api.example.com`) |
| `CADDY_IMAGE` | Image tag or digest of `caddy-with-auth` in use. For images with IP matching plugins, see [Deployment with coraza-ipset Image](ipset-image-deployment.md) |

Execute initial volume and configuration preparation:

```sh
docker compose run --rm runtime-init
docker compose run --rm ui-config-init
docker compose run --rm --no-deps --entrypoint /usr/local/bin/caddy caddy \
  validate --config /etc/caddy/Caddyfile --adapter caddyfile
```

`ui-config-init` only provisions missing overlay files; it will never overwrite active WAF policies, rule exclusions, or IP rules. Existing placeholder files containing only comments will be populated with safe initial `DetectionOnly` configurations. If a Caddyfile imports an overlay for a site not present in `CADDY_UI_SITES`, initialization aborts with an explanatory error.

In Docker Compose, the service name is `caddy`. When joining an existing Compose stack, update service references to match your actual service names.

## Volume Mounts and UID Permissions

Both Caddy (in distroless/DHI runtime) and caddy-waf-ui run under UID/GID `65532`.

| Mount / Path | Caddy Container | UI Sidecar | Alloy (Optional) |
| --- | --- | --- | --- |
| Caddyfile | `/etc/caddy/Caddyfile:ro` | Same path, read-only (used for `/load`) | Not mounted |
| Managed overlays | `/etc/caddy/ui-managed:ro` | `/ui-managed:rw` | Not mounted |
| Custom rules | `/etc/caddy/waf-custom:ro` | `/etc/caddy/waf-custom:ro` (for rule parsing; draft preview aborts if files mutate) | Not mounted |
| Backups & snapshots | Not mounted | `/backups:rw` | Not mounted |
| UI persistent state (events, cloud export queue, changes, drafts, offsets, IP groups) | Not mounted | `/ui-data:rw` | `/ui-data:ro` (reads only `cloud/events/` and `changes/`) |
| IP group source files (Optional) | Not mounted | `/ipgroups:ro` (maps to `./ipgroups` on host) | Not mounted |
| Audit & access logs | `/data/logs:rw` | `/data/logs:rw` (for rotation & renaming) | `/caddy-logs:ro` |
| TLS state `/data`, config `/config` | Read-write | Not mounted | Not mounted |
| Admin socket directory | `/run/caddy-admin:rw` | `/run/caddy-admin:ro` | Not mounted |

- `runtime-init` only adjusts the root ownership of each volume and specific subdirectories owned by the UI (`ui-managed`, `backups`, `ui-data`, and Alloy positions, permissions 0750 for dirs, 0640 for files). It does not recursively modify certificates or existing application logs.
- For deployments transitioning from host bind-mounts, back up existing overlays and snapshots, then grant UID `65532` read-write access to UI working directories and audit log locations.
- Preserve your existing audit log paths; pointing to a fresh empty volume will sever access to historical audit archives.
- Avoid setting permissive `0644` permissions across log directories.

## Caddy Admin API

The default Caddyfile configures `admin unix//run/caddy-admin/admin.sock`. The UI connects via `CADDY_ADMIN_URL=unix:///run/caddy-admin/admin.sock`. The socket directory is owned by UID `65532` with `0700` permissions and is mounted strictly into Caddy and the UI sidecar, avoiding TCP port exposure.

Any process with access to this Unix socket can replace the entire Caddy configuration. The UI mounting it read-only does not restrict its write capabilities through the socket protocol itself. Mount this socket only to trusted sidecar processes. While HTTP/HTTPS Admin URLs are supported, you must enforce strict network isolation and avoid exposing port 2019 publicly; credentials embedded in the URL are rejected.

## Network Topology

| Network | Members | Purpose |
| --- | --- | --- |
| `caddy-edge` | Caddy, Upstream Apps | User-facing application traffic |
| `waf-probe` (internal) | Caddy, UI | Origin health probing after policy reloads |
| `ui-access` | UI, Alloy | Loopback binding for the UI; outbound egress for Alloy to Grafana Cloud |

The UI listens strictly on `127.0.0.1:8080`. For remote administrative access, route through Tailscale, a VPN, or a TLS reverse proxy with multi-factor authentication. See [Security & Privacy](security.md).

## Verification Checklist

1. Open **Domains & WAF** and confirm that all managed sites appear with their expected WAF modes.
2. Send a test request guaranteed to trigger a rule match (such as `curl -i http://localhost/.env`) and verify that it appears on the **Events** tab.
3. Switch a site's WAF mode, and check **Rollback & History** to confirm that the `validate`, `load`, and `readback` stages succeeded (as well as `request` probing if `CADDY_UI_PROBE_URLS` is configured).
