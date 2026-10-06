# Security Policy - caddy-waf-ui

## Supported Versions

| Version | Supported |
|---|---|
| 1.2.x (latest: v1.2.0) | ✅ |
| 1.1.x | ❌ |
| 1.0.x | ❌ |
| older releases | ❌ |

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Report via:
- GitHub Security Advisory: [New Advisory](https://github.com/Developmi/caddy-waf-ui/security/advisories/new)
- Email: miguel@developmi.com (include `[SECURITY]` in subject)

Include in your report:
- Description of the vulnerability and its potential impact.
- Steps to reproduce or a proof-of-concept.
- Affected versions.
- Any suggested mitigations.

### Response timeline

| Stage | Target |
|---|---|
| Acknowledgment | 48 hours |
| Triage and severity assessment | 5 business days |
| Fix and coordinated disclosure | 30 days (critical), 90 days (others) |

## Disclosure Policy

This project follows **coordinated disclosure**. We ask that you give us reasonable time to address the vulnerability before public disclosure:

- **Critical issues:** fix or mitigation targeted within 7 days; disclosure only after the fix is available.
- **Other issues:** disclosure no earlier than the fix or mitigation, within the 30/90-day response window.

We will credit reporters in the release notes unless anonymity is requested.

## Scope

In-scope for this project:

- Authentication bypass or token leakage
- Arbitrary file write outside `ui-managed/` volume
- Token or secret exposure in logs or HTTP responses
- Directory traversal in file path construction
- SSRF via Caddy Admin API URL parameter

Out of scope:

- Vulnerabilities in Caddy, Coraza, or OWASP CRS (report to their respective projects)
- Issues requiring physical access to the host
- Social engineering

## Supply Chain Verification

Images are signed with Cosign (keyless, GitHub OIDC):

```bash
cosign verify \
  --certificate-identity "https://github.com/Developmi/caddy-waf-ui/.github/workflows/docker-build-scan-sign.yml@refs/heads/main" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  ghcr.io/developmi/caddy-waf-ui@sha256:<digest>
```

Always pull by digest in production. Do not use `:latest` in production compose files.

## Caddy Admin API authority

Default Compose administration uses an owner-restricted Unix socket, mounted only into Caddy and the UI. The socket directory is owned by UID 65532 and mode 0700. The UI's mount is read-only, which prevents filesystem edits but still allows connecting to the socket. Its API authority remains full Caddy configuration control; treat the UI and any other socket-mounting process as trusted operators.

HTTP/HTTPS endpoints remain supported for existing deployments. This transport carries no admin credential or configured client certificate. Do not publish its port or assume that different Docker bridge memberships prevent connectivity; verify firewall/routing boundaries on the actual platform. Host/Origin checks do not authenticate callers. The CADDY_ADMIN_URL value is operator-controlled, schemes and paths are validated, redirects are refused, and Unix transport ignores proxies.

The read-back check verifies literal hosts and WAF revisions after /load. An operator-configured origin probe additionally checks the revision and engine in the audit log; without a probe URL the journal explicitly records that request verification was skipped. Neither check proves full TLS/auth equivalence. On verification failure after a successful load, the service restores files and reloads the restored configuration. Recovery failure is returned explicitly; actual request validation is still necessary.

## UI Bind Default - LAN Exposure (SC-8)

The UI listens on `0.0.0.0:8080` by default (SC-8 row of the README "Security
Model" table). In a bare deployment without a host firewall this exposes the
UI to every client on the LAN over plain HTTP: the UI does not terminate TLS
itself — HTTPS is terminated by the reverse proxy in front of it (the
documented deployment fronts the UI with Caddy `reverse_proxy` + mTLS, or
restricts host exposure via the compose port mapping).

Why it matters: the session cookie is marked `Secure`, which browsers only
honor in a secure context (HTTPS; loopback is exempt, LAN addresses are not).
Served over plain HTTP on a LAN address, the cookie is not honored and the
bearer token used by `/api/*` crosses the LAN in cleartext — a LAN attacker
can sniff admin traffic.

Recommended mitigation — narrow the listener when LAN-wide access is not
needed:

- Loopback-only access (UI and browser on the same host):
  `CADDY_UI_BIND=127.0.0.1:8080`. `Secure` cookies keep working over HTTP
  loopback (secure context).
- Tailnet-only remote access: bind to the Tailscale interface IP
  (`CADDY_UI_BIND=<tailscale-ip>:8080`, shown by `tailscale ip -4`) — remote
  traffic then rides the encrypted Tailnet only. The documented Tailscale
  pattern remains a valid option and is unchanged.
- TLS fronting: when the UI must be reachable beyond loopback/Tailnet, keep it
  behind Caddy+mTLS as documented.

The `0.0.0.0:8080` default is intentionally unchanged; exposure is restricted
per deployment via `CADDY_UI_BIND`.

## Known Limitations - Auth Notes & Rate Limiting

Documented design decisions, not defects:

- **Logout is client-side only.** The session token is stateless: a
  high-entropy bearer token compared in constant time
  (`subtle.ConstantTimeCompare`), with no server-side session store. Logout
  clears the cookie but **cannot revoke or expire tokens already issued** -
  anyone who captured a valid token keeps using it until the service
  redeploys with a rotated `CADDY_UI_TOKEN`. This is the accepted trade-off
  of a single-operator admin console: treat the token as full admin access
  and rotate it when it may have been exposed.
- Login and API sliding-window rate limits are implemented in this UI process. Keep any independent ingress protections required by the deployment.

## Fork deployment defaults

The supplied Compose uses an owner-restricted shared Unix socket for administration, with no TCP admin listener. Applications do not mount this volume. HTTP/HTTPS remains an operator-selected compatibility transport; separate bridge membership alone is not a routing/firewall guarantee. Caddy and UI run as UID/GID 65532; the UI receives only the audit directory read-write for rename/reopen rotation, not certificate data. New logs/overlays are 0640 with 0750 directories. The default AHKZ audit parts omit request headers; the optional ABHKZ keeps them locally. Raw rule messages may still expose sensitive data. Alloy ships only redacted normalized events and allowlisted metadata. UI authentication does not authenticate the Caddy Admin API; its socket ownership or operator-selected network remains an independent trust boundary. Upstream signature examples above apply to upstream images; this fork builds its own UI from source.

## Telemetry and retained data

The UI audit-directory mount is read-write solely for raw-log rename/reopen rotation; it has no certificate-volume mount. Raw audit files contain URIs and, with the optional ABHKZ parts, request headers and credentials; they must remain local with access restricted. The cloud profile ships only normalized WAF events and allowlisted metadata. Strict omits values; standard masks recognized credential names and unclassified data; explicit full retains credentials except name-list exclusions. Local and cloud policies are separate, cloud cannot exceed local detail, and runtime diagnostic text stays local. See [REDACTION.md](REDACTION.md). Reviewed draft content, diffs, operator reasons, feedback and raw audit records are not cloud inputs.

Use separate Loki read and write tokens, supplied through environment/secret management. The local UI holds the read token; Alloy holds the write token. Alloy has no Docker/Admin socket. IP, transaction ID, path and rule CSV are JSON fields, not indexed labels. Metrics export is optional and drops per-rule counters by default to constrain series count.

Probe destinations are operator-controlled JSON configuration, never derived from Host headers or UI requests. HTTP/HTTPS URLs are validated, redirects are refused and TLS verification stays enabled. Probes perform GET requests, so choose a safe origin path without side effects. Authenticated UI policy/exclusion forms apply an exact reviewed artifact and reject edited intent, expired drafts or changed overlay/base/custom-file hashes. The direct authenticated API remains an automation interface with validation, journaling and compensation.
