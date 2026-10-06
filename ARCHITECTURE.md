# Architecture

The stdlib-only Go sidecar manages configuration alongside the existing caddy-with-auth backend. It writes managed overlays, backups, normalized data and raw-audit rotation state. The base Caddyfile and custom rules are read-only. Application traffic flows directly through Caddy; Alloy is an optional telemetry collector, and Grafana Cloud Loki is optional history storage.

## Components

- `internal/waf`: baseline, policy, signature/revision, path/target/expiry exclusions and synthetic origin probe.
- `internal/service`: reviewed artifacts, baseline hashes, serialized publish/compensation, last-good metadata and raw-log rename/reopen rotation.
- `internal/caddy`: Admin API load and live host/revision read-back, over the default owner-restricted Unix socket.
- `internal/files`, `internal/domain`, `internal/iprules`: atomic files, typed backups, site discovery and validated client-IP lists.
- `internal/events`: audit normalization/redaction, restartable cursors, daily JSONL files, compact disk-offset index, bounded event cache, retained-file queries, rollups and direct paginated Loki queries.
- `internal/crs`, `internal/analysis`: versioned rule dictionary/source notes, CSV lookup, match/score explanations, bounded retrospective analysis and approximate impact estimates.
- `internal/feedback`, `internal/journal`: local operator decisions and staged change evidence.
- `internal/ui`, `internal/auth`, `internal/ratelimit`: embedded server-rendered pages, API, cookie/bearer authentication, CSRF and request limits.
- `alloy`: allowlisted WAF/access/runtime/change streams; optional metrics collection with a series budget.

## Update flow

1. Validate intent, render a candidate and save its SHA256 with the overlay/base/custom-file hashes and a 30-minute draft ID.
2. Display the generated diff and bounded impact estimate from the selected local/cloud history source.
3. On Apply, lock the complete transaction and reject stale/edited intent before writing or reloading.
4. Snapshot previous files; publish the exact reviewed bytes. Runtime exclusions precede custom/CRS execution, while configure-time removals follow loading.
5. The revision inside `directives` invalidates Coraza's process-global pool, including external-include content changes.
6. Load the base Caddyfile, read back site/revision and optionally verify an origin request plus its audit signature. Record each stage independently.
7. On failure, restore files and reload them if Caddy accepted the candidate. Return compensation failure explicitly. On success, retain last-good content/checksum and metadata.

WAF and exclusion snapshots are independent. WAF rollback restores the snapshot's mode and policy and regenerates with the current baseline and canonical exclusion list; exclusion rollback refreshes the WAF. Legacy snapshots without a policy line restore their mode with the default CRS policy. API automation uses the same validated publish chain without the browser's mandatory saved preview. Run one UI writer per overlay volume; the mutation lock is process-local.

## Data and authority

Caddy and UI share UID/GID 65532. Caddy reads managed overlays; UI writes them. Caddy/UI alone mount the Admin socket. The UI sees the audit directory read-write for rename/reopen rotation, not the certificate-bearing `/data` volume. A dedicated internal network permits origin probes; telemetry cloud egress uses the UI network. Alloy has no Docker/Admin socket, reads event/log files and writes only its own position directory.

`events-*.jsonl` are local normalized events sent by Alloy; `imported-*.jsonl` are optional local copies that are never re-sent. Normal cloud viewing queries Loki directly and does not import the whole retention window. Restart rebuilds the retained index and day counters from durable events. Records without any rule match are skipped: Coraza's `RelevantOnly` engine also logs 4xx/5xx responses through the baseline `SecAuditLogRelevantStatus`, which are not WAF events. Disk-full errors stop the raw cursor. Rotation preserves renamed archives and separate cursors for late records, with a 48-hour grace period before deletion after EOF.

## Limits

Admin read-back and synthetic probes verify limited properties, not complete auth/TLS/application equivalence. No probe destination means request verification is skipped. Raw local audit logs contain URIs (and request headers with the optional ABHKZ parts); only redacted normalized records are cloud WAF inputs. Rule-version mismatch, truncated/early/missing hits and unknown custom rules remain visible. Analysis covers audited matches only, with a 2,000-event ceiling, and cannot reconstruct unexecuted rules or perform complete body/method policy replay. Cloud access/runtime streams are inspected in Grafana Explore; local UI forensic views use WAF events and the local change journal.

See [LOCAL-CLOUD.md](LOCAL-CLOUD.md), [INTEGRATION.md](INTEGRATION.md) and [SECURITY.md](SECURITY.md) for deployment and operational boundaries.
