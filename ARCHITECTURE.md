# Architecture

The stdlib-only Go sidecar manages configuration alongside the existing caddy-with-auth backend. It writes only its managed overlay and backup volumes; the base Caddyfile and operator-owned rules stay read-only. Caddy's Admin API is the control plane, while application traffic flows directly through Caddy.

## Components

- `internal/config`: operator environment, paths, baseline CRS/audit/response settings.
- `internal/waf`: embedded/disk CRS template, ordered compiled exclusions, per-render revision, snapshot refresh.
- `internal/service`: input validation, offline initialization, serialized backup/write/reload/restore transaction and compensation after an applied reload fails verification.
- `internal/caddy`: standard `/load` and live host read-back, with applied-error reporting.
- `internal/iprules`: validated IP/CIDR lists using Caddy client_ip.
- `internal/files`: atomic 0640 writes and typed backup/restore retention.
- `internal/domain`: slug/header contract and site discovery from managed WAF files.
- `internal/logs`: recent Coraza JSON audit parsing; actual interruptions take priority over configured disruptive actions.
- `internal/ui`, `internal/auth`, `internal/ratelimit`: server-rendered forms, API, cookie/bearer authentication, CSRF and request limits.

## Update flow

1. Validate the requested domain/mode/exclusion/IP list.
2. Lock the complete mutation transaction and snapshot previous files.
3. Write the canonical data and refresh any derived WAF overlay. Runtime exclusion rules precede CRS execution; configure-time removals follow rule loading.
4. Change the revision comment inside the directives block, invalidating the process-global Coraza WAF pool even for changes to external include contents.
5. Send the read-only base Caddyfile to Caddy's `/load` and read back literal hosts.
6. On error, restore the previous files; if Caddy already accepted the load, reload restored files as compensation. Audit the result and return any recovery failure explicitly.

A WAF rollback restores baseline/mode while compiling the current independently managed exclusion list. An exclusion rollback also refreshes the WAF. Legacy snapshots lacking the managed regions retain their bytes for compatibility. Only one UI writer should own an overlay volume: the lock is process-local, not distributed.

## Files and container boundaries

- `waf-{slug}.conf`: the generated handler, mode header, revision and compiled exclusions.
- `exclusions-{slug}.conf`: canonical exclusion list, read by the UI and generator; not a Caddyfile/Coraza import.
- `ip-rules-{slug}.conf`: Caddy client_ip allow/deny matchers.
- `/backups/{slug}/{timestamp}.{type}.conf`: independent typed snapshots with nanosecond precision and exclusive creation; legacy second-resolution names remain readable.

Caddy sees managed files read-only; the UI sees them read-write. Both run as UID/GID 65532. The UI receives only the audit log directory read-only, not Caddy's certificate volume. Initialization prepares roots and existing UI-owned files before seeding new sites. It never replaces existing active rules with placeholders.

Application containers and public ingress use the edge network. The UI uses a separate bridge to publish its loopback-only port. Caddy and UI alone mount a dedicated Unix admin socket volume; no TCP management endpoint is exposed. HTTP/HTTPS management URLs remain supported for existing deployments with their own network boundary. UI health and backend connectivity are separate checks.

## Limits

Read-back checks literal site hosts; it does not prove equivalence of all live rules/auth/TLS settings, and environment-based addresses are skipped. Generated configuration and actual request behavior both need validation. Audit classification uses Coraza's actual is_interrupted flag; legacy formats without it fall back to explicit actions. Default AHKZ omits request headers/bodies, so URI may be absent. The viewer reads the last 2 MiB, not full retained history. URI-specific exclusions, one-click exclusions from logs and SSE log streaming are not implemented.

See [INTEGRATION.md](INTEGRATION.md) for deployment, UID migration, trusted proxy boundaries and recovery procedures.
