# Deployment with coraza-ipset Image

`liukan/caddy-with-auth:coraza-plugins-ipset` is the official caddy-with-auth image bundled with the [coraza-ipset plugin](backend-image.md#ip-matching-plugin-coraza-ipset). The only difference compared to `latest` is how IP address lists are evaluated: `@ipMatchFromFile` is accelerated via binary search, ensuring evaluation time remains flat even across hundreds of thousands of CIDRs. No changes are required to Caddyfile, overlays, UI, or rule definitions.

This guide provides an end-to-end walkthrough: image verification → new deployment or existing stack migration → country whitelist configuration → verification → rollback. All commands are run from the root of the caddy-waf-ui repository.

## Image Contents

Published version as of 2026-10-07:

| Component | Version |
| --- | --- |
| Caddy | 2.11.7 |
| coraza-caddy | 2.6.1 |
| Coraza | 3.8.1 |
| CRS (coraza-coreruleset) | 4.25.0 (matches UI embedded dictionary) |
| coraza-ipset | caddy-with-auth commit `4acf03e` |

Builds are available for `linux/amd64` and `linux/arm64`, running as UID/GID 65532. Because tags can be overwritten, pinning the SHA256 digest is recommended for production (Step 1).

## Step 1: Pull and Verify the Image

```sh
docker pull liukan/caddy-with-auth:coraza-plugins-ipset
CADDY_IMAGE=liukan/caddy-with-auth:coraza-plugins-ipset make crs-version
```

Verify that the output contains the following lines:

```text
dep	github.com/corazawaf/coraza-coreruleset/v4	v4.25.0	…
dep	github.com/liu-kan/caddy-with-auth/plugins/coraza-ipset	…
```

- If `coraza-ipset` is missing, you have pulled an image without the plugin.
- If coraza-coreruleset is not 4.25.0, update the UI rule dictionary per [Backend Image](backend-image.md#upgrading-coraza-or-crs).

Retrieve the immutable digest:

```sh
docker image inspect --format '{{index .RepoDigests 0}}' liukan/caddy-with-auth:coraza-plugins-ipset
```

The output will be formatted as `liukan/caddy-with-auth@sha256:…`. Use this string as `CADDY_IMAGE` below.

## Step 2 (Fresh Deployment): Preparation & Launch

If upgrading an existing deployment, skip to [Step 2 (Existing Deployment)](#step-2-existing-deployment-migrating-the-image).

1. Clone repository:

   ```sh
   git clone https://github.com/liu-kan/caddy-waf-ui.git
   cd caddy-waf-ui
   ```

2. Create `.env` and generate access token:

   ```sh
   cp .env.example .env
   chmod 600 .env
   openssl rand -hex 32
   ```

3. Configure `.env`:

   | Variable | Value |
   | --- | --- |
   | `CADDY_UI_TOKEN` | Generated 32-byte hex token |
   | `CADDY_IMAGE` | `liukan/caddy-with-auth:coraza-plugins-ipset` or pinned digest |
   | `CADDYFILE_PATH` | Keep `./Caddyfile.example` for testing; use your production path for production |
   | `CADDY_UI_SITES` | Managed domains (e.g., `chat.example.com`) |
   | `CADDY_UI_PROBE_URLS` | Post-deploy origin health verification (e.g., `{"chat.example.com":"https://caddy/__waf_health"}`) |
   | `CADDY_UI_IPGROUP_MAX_PREFIXES` | Increase to `300000` if loading large country lists like US (260,000+ CIDRs); defaults suffice for CN/JP |
   | `CADDY_UI_IPGROUP_PROXY` | HTTP proxy if the container cannot reach GitHub directly |

4. Production Caddyfile setup: Add dual imports inside each site's `route` block (see [Integrating with an Existing Deployment](deployment.md#modifying-the-caddyfile-add-two-imports-per-site)).

   When operating behind Cloudflare, you **must** configure trusted proxies so Caddy inspects real client IPs rather than Cloudflare edge IPs:

   ```caddyfile
   {
   	admin unix//run/caddy-admin/admin.sock
   	order coraza_waf first
   	servers {
   		trusted_proxies combine {
   			import /etc/caddy/cloudflare-ranges.caddy
   			cloudflare {
   				interval 12h
   				timeout 15s
   			}
   		}
   		client_ip_headers CF-Connecting-IP
   		trusted_proxies_strict
   	}
   }
   ```

   `cloudflare-ranges.caddy` can be generated using caddy-with-auth's [gen-cloudflare-ranges.sh](https://github.com/liu-kan/caddy-with-auth/tree/main/examples/cloudflare-real-ip-fail2ban) and mounted into the Caddy container.

5. If custom mounts or port remapping are needed, create `docker-compose.override.yml`:

   ```yaml
   services:
     caddy:
       volumes:
         - ./cloudflare-ranges.caddy:/etc/caddy/cloudflare-ranges.caddy:ro
       ports: !override
         - "8081:80"
     caddy-waf-ui:
       ports: !override
         - "127.0.0.1:18088:8080"
   ```

6. Validate configuration and start containers:

   ```sh
   docker compose config --quiet
   docker compose up -d --build
   docker compose ps
   ```

7. Verify plugin presence in running container:

   ```sh
   docker compose exec -T caddy /usr/local/bin/caddy build-info | grep coraza-ipset
   ```

8. Access the UI: Navigate to `http://127.0.0.1:8080` and log in.

## Step 2 (Existing Deployment): Migrating the Image

Applies to stacks already deployed per [Integrating with an Existing Deployment](deployment.md). Migration only recreates the Caddy container; overlays and data volumes remain untouched.

1. Record current image digest for quick rollback:

   ```sh
   docker image inspect --format '{{index .RepoDigests 0}}' "$(docker inspect --format '{{.Image}}' "$(docker compose ps -q caddy)")"
   ```

2. Update `CADDY_IMAGE` in `.env` to `liukan/caddy-with-auth:coraza-plugins-ipset` or its digest.

3. Pull image and recreate Caddy (traffic will briefly pause during reload):

   ```sh
   docker compose pull caddy
   docker compose up -d --no-deps caddy
   ```

4. Confirm plugin activation:

   ```sh
   docker compose exec -T caddy /usr/local/bin/caddy build-info | grep coraza-ipset
   ```

5. Confirm policy publishing: In **Domains & WAF**, re-apply the active mode for any site and verify that `validate`, `load`, `readback`, and `request` pass in **Rollback & History**.

## Step 3: Configuring a Country Whitelist

Example goal: Allow only Mainland China (CN) and Japan (JP), banning all other traffic.

1. Import lists: On the **IP Groups** tab, click **Add / Update** to add two groups (Source: URL, Refresh: 24h):

   | Name | URL |
   | --- | --- |
   | `cn` | `https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/sing/geo/geoip/cn.srs` |
   | `jp` | `https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/sing/geo/geoip/jp.srs` |

2. Exclude internal origins (health checks, monitoring, office VPNs):
   Create `./ipgroups/internal.txt` on the host, one IP/CIDR per line, and add it in the UI as group `internal` (Source: File, Filename: `internal.txt`). Include Docker gateway ranges (`172.16.0.0/12`) during local testing.

3. Run in Trial mode first:
   - Go to **Policy** → **IP group rules**, edit rule #1:
     - Groups: Select `cn`, `jp`, and `internal` simultaneously.
     - Clients: `outside all`.
     - Action: `trial`.
   - Enter a reason, click **Preview diff and impact**, then **Apply reviewed policy**.
   - Monitor the **Events** tab for "would be blocked" events to ensure real visitor IPs are detected and internal systems are not flagged.

4. Switch to Ban:
   - Change the rule Action to `ban`, preview, and apply.
   - Ban takes effect when the site is in `On` mode (in `DetectionOnly`, it logs "would block" events).
   - Once enforced, banned requests return HTTP 403 without generating WAF events.

Via REST API:

```sh
curl -s -X PUT -H "Authorization: Bearer $CADDY_UI_TOKEN" -H "Content-Type: application/json" \
  -d '{"policy":{"blocking_pl":1,"inbound_threshold":5,"outbound_threshold":4,"ip_groups":[{"groups":["cn","jp","internal"],"negate":true,"action":"ban"}]},"reason":"allow CN and JP"}' \
  http://127.0.0.1:8080/api/sites/chat.example.com/policy
```

## Step 4: Verification Checklist

| Check | Method | Expected Result |
| --- | --- | --- |
| Plugin compiled in | `docker compose exec -T caddy /usr/local/bin/caddy build-info \| grep coraza-ipset` | Non-empty output |
| Overlay uses union set | `docker compose exec -T caddy-waf-ui grep ipMatchFromFile /ui-managed/waf-chat_example_com.conf` | References `ipgroups/_union.<hash>.txt` |
| IP Membership lookup | Use **Which groups hold** tool on the **IP Groups** tab | Matches `cn` or `jp` |
| Publication pipeline | Inspect **Rollback & History** | All stages (`validate`, `load`, `readback`, `request`) succeed |
| Site mode | Inspect **Domains & WAF** | `On` |
| Traffic filtering | Probe from CN/JP vs foreign proxy | CN/JP succeeds; foreign receives HTTP 403 |

## Rollback

1. Revert `CADDY_IMAGE` in `.env` to your recorded digest.
2. Recreate Caddy:

   ```sh
   docker compose up -d --no-deps caddy
   ```

Overlays remain fully compatible; rules revert to linear search without requiring UI changes.
