# Security & Privacy

## Trust Boundaries

| Credential / Interface | Principal | Capabilities |
| --- | --- | --- |
| `CADDY_UI_TOKEN` | Operators | Web UI authentication and REST API authorization: modifying WAF modes, policies, exclusions, and IP rules for all managed sites. |
| Caddy Admin Socket | Caddy, UI | Full replacement of Caddy configuration. The UI mounts the socket directory read-only, but retains full client connectivity over the Unix domain socket. |
| `GRAFANA_CLOUD_LOGS_READ_TOKEN` | UI | Reading remote logs stored in Loki. |
| `GRAFANA_CLOUD_LOGS_WRITE_TOKEN` | Alloy | Pushing collected log streams to Loki. |
| `CADDY_UI_METRICS_TOKEN` | Alloy / Scrapers | Scraping Prometheus `/metrics`. |

The UI token grants WAF administrator privileges; the Admin socket grants Caddy gateway administrator privileges. Mount the Admin socket exclusively to trusted sidecar processes; Alloy does not mount the Admin socket or the Docker socket.

## Authentication & Sessions

- Generate `CADDY_UI_TOKEN` using `openssl rand -hex 32`. Store it in `.env` (permissions `0600`, excluded from Git) or your secret manager.
- Browser authentication issues session cookies marked `HttpOnly`, `Secure`, and `SameSite=Strict`, valid for 12 hours. All state-mutating UI operations require valid CSRF tokens.
- Sessions are stateless. **Sign out** clears the local browser cookie but does not revoke previously signed tokens. If token leakage is suspected, rotate `CADDY_UI_TOKEN` and restart the container.
- Endpoints under `/api/*` require `Authorization: Bearer <CADDY_UI_TOKEN>` and reject session cookies.
- Token comparisons use constant-time operations (`subtle.ConstantTimeCompare`) to resist timing attacks.

In-memory rate limiting:

| Endpoint | Limit |
| --- | --- |
| `POST /login` | 5 requests/minute per source IP, 60 requests/minute globally |
| `/api/*`, `/metrics` | 120 requests/minute per source IP, with a burst capacity of 30 |

When running behind a reverse proxy, all requests share the proxy's IP address and rate quota unless trusted proxy forwarding is configured.

## Network Exposure

Docker Compose binds the UI exclusively to loopback address `127.0.0.1:8080`. `Secure` cookies require HTTPS or loopback origins; accessing over plaintext HTTP from remote hosts prevents login and transmits API tokens in cleartext. For remote administrative access:

| Method | Implementation |
| --- | --- |
| Tailscale / WireGuard | Bind to internal interface: `CADDY_UI_BIND=<tailscale IP>:8080`, accessible strictly within your tailnet. |
| Authenticated Reverse Proxy | Configure a dedicated site block in caddy-with-auth using caddy-security authentication, reverse-proxying internally to the UI. Never expose the UI port directly to the public internet. |

`CADDY_UI_ACTOR_HEADER` records operator usernames in audit trails and does not grant authorization. Enable it only when your authenticating edge proxy reliably strips and overrides client-supplied headers.

## Data Redaction & Privacy

| Data Category | Local Storage | Uploaded to Grafana Cloud |
| --- | --- | --- |
| Raw audit log (URIs; request headers, Cookies, and Authorization if using `ABHKZ`) | Yes, mode 0640, restricted to UID/GID 65532 | No |
| Client IP, Host, HTTP method, request path (decoded, max 512 chars) | Yes | Yes |
| Query parameter keys (up to 20 keys) | Yes | Yes |
| Query parameter values, matched fragments, request headers (headers require `ABHKZ`) | Evaluated under local policy (`strict` discards; `standard` masks credentials; `full` retains) | Evaluated under cloud policy (defaults to `strict`, never broader than local) |
| Matched Rule IDs, messages, target variables (e.g., `ARGS:q`) | Yes | Yes |
| Local match context (viewed on demand in event details) | Read on demand from raw logs; not written to event databases | No |
| Change history actor, reason, error messages, diffs | Yes | No |
| Policy drafts, snapshots, false-positive annotations | Yes | No |

Local and cloud pipelines apply `strict`, `standard`, or `full` levels with shared `HIDE` and `KEEP` overrides. See [Configurable Redaction](redaction.md). Raw audit logs on disk are not altered.

## Automation Safety Boundaries

- False-positive candidates and suspected threat actors are advisory indicators. The system will never generate automatic rule exclusions or IP bans.
- Web UI policy changes require explicit diff previews; changes are applied via SHA256-hashed drafts valid for 30 minutes.
- Automated API endpoints apply changes directly with input validation, automated snapshotting, change journaling, and compensating rollback.
- Health probe endpoints derive strictly from operator-configured `CADDY_UI_PROBE_URLS`, sending GET requests without following redirects and verifying TLS certificates.
- Loki endpoints, selectors, and tokens are set by operators and cannot be pointed to arbitrary external targets via request inputs.

## IP Group Feed Security

- Only `https://` URLs without embedded basic auth credentials are accepted. Feeds follow at most 5 redirects while strictly preserving HTTPS, and TLS certificates are verified.
- Single downloads are capped at 32 MiB; decompressed binary rule-sets are capped at 64 MiB; lists cannot exceed `CADDY_UI_IPGROUP_MAX_PREFIXES`.
- `CADDY_UI_IPGROUP_PROXY` applies strictly to IP group downloads.
- File-based sources must reside within `CADDY_UI_IPGROUP_DIR` and cannot navigate directory paths.
- Empty or malformed lists are rejected. Updates dropping more than 50% of prefixes are staged for manual approval.
