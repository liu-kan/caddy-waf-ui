# Audit Logs & Rotation

Coraza writes audit logs to `CADDY_UI_AUDIT_LOG` (defaults to `/data/logs/coraza-audit.log`). The UI tails this file to populate local events and manages automated log rotation. Raw audit logs reside strictly on the local origin node and are never forwarded off-host.

## What Gets Recorded

Each managed site's WAF overlay enforces the following audit directives, generated automatically by the UI (immutable from the UI):

| Directive | Value | Purpose |
| --- | --- | --- |
| `SecAuditEngine` | `RelevantOnly` | Selects transactions based on HTTP status codes; tuning mode and origin probes force audit logging per request. |
| `SecAuditLogFormat` | `JSON` | Formatted as one JSON object per transaction. |
| `SecAuditLogParts` | `CADDY_UI_AUDIT_LOG_PARTS` | Defaults to `AHKZ`: Request line, URI, and triggered rule metadata; `ABHKZ` adds request headers (Part B). |
| `SecAuditLogFileMode` / `DirMode` | `0640` / `0750` | Restricted to UID/GID 65532. |

Under Coraza 3.8, `RelevantOnly` evaluates HTTP status codes: the base `@coraza.conf-recommended` configuration sets `SecAuditLogRelevantStatus` to `^(?:(5|4)(0|1)[0-9])$`, logging requests returning 400–419 or 500–519. Consequently:

| Request Scenario | Written to Raw Log | Recorded as WAF Event |
| --- | --- | --- |
| Blocked (403, 400) or DetectionOnly would-block | Yes | Yes |
| Rules matched but below threshold, returning 200 | No (Yes if Tuning Mode active) | Yes in Tuning Mode (`DETECTED`) |
| Rules matched but below threshold, upstream returns 404, 401, 502, etc. | Yes | Yes (`DETECTED`) |
| No rules matched, upstream returns 404, 401, 502, etc. | Yes | No (Skipped during ingestion) |

The final category—benign errors matching zero rules—can be substantial on scan-heavy sites. These records consume raw disk space on the logging volume, but are discarded by the UI and never consume event storage, analysis quotas, or cloud bandwidth.

All UI features work fully with `AHKZ`. Switch to `ABHKZ` only when debugging issues that require inspecting request headers via the **Raw Audit Log** view: headers contain sensitive credentials (Cookies, Authorization tokens) and remain strictly on local disk. Once troubleshooting concludes, revert to `AHKZ`.

## Ingestion Tailer

Every `CADDY_UI_INGEST_INTERVAL` (default 2s), the UI polls for newly appended audit records:

- Read byte offsets are persisted in `/ui-data/state/ingest.json`, ensuring uninterrupted progress across restarts.
- File replacements (inode changes) or external truncations (`copytruncate`) trigger a read reset; existing events are deduplicated by transaction ID without duplication.
- Transactions with zero matched rules and no interruption flag, as well as UI origin probes, are discarded.
- Unparseable lines are skipped and increment the Prometheus metric `waf_ingest_errors_total{kind="parse"}`.

Status bars at the top of the **Events** and **Analysis** tabs display live ingestion progress (read bytes / total file size), last poll timestamp, and active error warnings.

## Rotation Lifecycle

When the raw audit file exceeds `CADDY_UI_AUDIT_ROTATE_MB` (default 32 MiB, checked every 30 seconds):

1. The active file is renamed to `coraza-audit.log.rotated-<UTC-Timestamp>`, and a new empty file is created.
2. The UI re-applies the active WAF mode for all managed sites. The resulting new policy revision prompts Coraza to instantiate fresh WAF engines and reopen log file descriptors.
3. A change journal entry is recorded under actor `audit-maintenance` with the description "reopen rotated audit log".

The UI continues tailing existing rotated archives until fully read. Archives are deleted only after their last modification exceeds `CADDY_UI_AUDIT_ARCHIVE_HOURS` (default 48h, minimum 48h) **and** the ingestion cursor has reached EOF. Retaining archives for 48 hours ensures long-lived connections that flush only upon termination are captured; raising this setting extends the lookback window for **Show matched values** on historical events.

Operational reminders:

- Rotation requires at least one managed site overlay to prompt Coraza log reopening.
- Run only a single UI sidecar instance per shared data volume.
- If the daemon crashes mid-rotation, the presence of `/ui-data/audit-reopen.pending` prompts a retry upon restart.
- Do not attach external logrotate daemons to the same audit log file. If external rotation is mandatory, disable internal rotation via `CADDY_UI_AUDIT_ROTATE_MB=0`.

## Disk Budget & Ceilings

| Data Category | Path | Limits and Cleanup Policy |
| --- | --- | --- |
| Raw Audit Logs & Archives | `/data/logs/` | Rotates at ~32 MiB; archives retained for `CADDY_UI_AUDIT_ARCHIVE_HOURS` (min 48h) and pruned once consumed. |
| Normalized Local Events | `/ui-data/events/` | Retained for `CADDY_UI_EVENTS_RETENTION_DAYS` (14 days); capped at `CADDY_UI_EVENTS_DISK_MAX_MB` (128 MiB). |
| Daily Rollups | `/ui-data/rollups/` | Partitioned monthly, retained indefinitely (very small footprint). |
| Snapshots | `/backups/` | Up to `CADDY_UI_BACKUP_KEEP` (10) snapshots per site per overlay type. |
| Change Logs, Drafts, Annotations, `last_good` | `/ui-data/` | Minimal footprint. |

When normalized events reach their disk ceiling, the UI **pauses ingestion** from the audit log rather than deleting unsent events; the status bar displays "event disk budget reached". Raw logs continue to accumulate, and unread archives are protected from deletion. To recover: decrease retention days, raise the disk limit, or expand disk capacity.

Size the audit logging volume to accommodate at least 48 hours of normal traffic.

## Raw Audit Log View

The **Raw Audit Log** tab (`/?tab=logs`) displays the trailing 2 MiB of the active raw audit log (including benign 4xx/5xx requests with zero rule matches), rendering 50 entries per page. Supports filtering by IP, URI, Rule ID, or Message, and status toggles for BLOCKED / DETECTED. It inspects only the currently open log file (excluding rotated archives) and is intended for raw syntax debugging. For day-to-day operations, use [WAF Events](events.md).

## Operational Metrics

| Metric | Description |
| --- | --- |
| `waf_ingest_lag_bytes` | Bytes pending ingestion; sustained growth signals stalled tailing. |
| `waf_ingest_last_poll_timestamp_seconds` | Unix timestamp of most recent tailer poll. |
| `waf_ingest_errors_total{kind}` | Ingestion errors categorized by `read`, `parse`, or `store` (including disk limit stops). |

See [Metrics](metrics.md) for Prometheus configuration details.
