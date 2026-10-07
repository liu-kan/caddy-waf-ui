# Change History & Rollback

The **Rollback & History** tab (`/?tab=rollback&domain=<site>`) audits configuration snapshots and the immutable change journal for a site, providing one-click rollback to restore any previous snapshot as the active configuration.

## Change History Journal

All state-mutating actions are appended to `/ui-data/changes/changes.jsonl`. The UI displays the 100 most recent operations for the selected site:

| Column | Description |
| --- | --- |
| Change | Action and summary, per-stage deployment results (hover for details), and expandable **Diff** view (truncated at 16 KiB). |
| Reason | Operator rationale supplied in forms or API payloads. |
| By | Username passed via `CADDY_UI_ACTOR_HEADER`, or client source IP if unset. |
| Result | `success` or `failed` (hover to view error messages). |
| Revision | Generated WAF overlay revision ID, cross-referencing event logs. |

Tracked actions:

| Action | Source |
| --- | --- |
| `mode` | WAF mode toggles; log rotation maintenance under actor `audit-maintenance`. |
| `policy`, `exclusions` | Policy and exclusion updates (draft applications noted as "applied reviewed ... draft"). |
| `iprules` | IP rules modifications. |
| `rollback` | Snapshot restoration. |
| `feedback` | Operator triage annotations (does not alter Caddy configuration). |
| `ipgroup` | Overlay re-deployments triggered by feed updates; feed CRUD operations recorded globally without site binding. |

Failed attempts are recorded along with failure stages and detailed errors. When Grafana Cloud is enabled, entries are forwarded with `kind="change"` (omitting operator names, reasons, diffs, and errors) for dashboard annotations.

## Publishing Stages & Compensating Rollback

| Stage | Operational Definition |
| --- | --- |
| `validate` | Syntactic and semantic validation of input parameters. |
| `load` | Caddy Admin API accepts new configuration via `/load`. |
| `readback` | Configuration readback confirms domain registration and active revision. |
| `request` | Synthetic probe verifies the origin responds under the new revision; reported as `skipped` if unconfigured. |
| `compensate` | Compensating reload restoring previous files if probing fails. |

If any stage fails, the UI automatically restores files to their pre-change state and re-executes `/load` with the restored files. Mutations within a UI instance execute serially.

## Snapshots

Prior to applying modifications, the UI saves pre-change configuration files to `/backups/<slug>/<UTC-Timestamp>.<type>.conf`. Up to `CADDY_UI_BACKUP_KEEP` (default 10) snapshots are preserved per site per type.

| Snapshot Type | Restored Scope |
| --- | --- |
| `waf` | Restores the snapshot's **mode and policy parameters**; overlays are recompiled using current baseline settings and **current** exclusions. |
| `exclusions` | Restores the historical exclusion list and recompiles overlays. |
| `ip-rules` | Restores the historical IP rules configuration file. |

WAF snapshots and exclusion snapshots operate independently: rolling back a WAF policy snapshot does not revert rule exclusions added subsequently. Restorations execute through the standard deployment pipeline and generate fresh pre-change snapshots, making rollbacks themselves reversible.

## last_good State

Whenever a publication succeeds across all stages, the validated overlay is saved to `/ui-data/releases/<slug>/last_good.conf`, and metadata (revision, SHA256, timestamps, stage results) is saved to `last_good.json`. This serves as the authoritative, verified configuration for recovery.

## Manual Disaster Recovery

If automated compensating rollbacks fail (e.g., Caddy crashes during a reload):

1. Check **Rollback & History** to identify the failing stage and error.
2. Once Caddy recovers, restore the most recent `waf` snapshot or re-apply the current mode in the UI.
3. If recovery fails, validate syntax using `caddy validate`, or manually copy the `last_good` configuration back to the managed volume and trigger a mode refresh:

   ```sh
   docker compose exec caddy-waf-ui \
     cp /ui-data/releases/chat_example_com/last_good.conf /ui-managed/waf-chat_example_com.conf
   ```

To completely reset a single domain, back up its three overlay files, remove only `waf-<slug>.conf`, and re-run `docker compose run --rm ui-config-init`. Never delete the entire volume, as it contains active certificates and historical snapshots.

## REST API

| Endpoint | Description |
| --- | --- |
| `GET /api/changes` | Query change history (`site`, `limit`). |
| `GET /api/sites/{domain}/backups` | List snapshots for a site. |
| `POST /api/sites/{domain}/rollback` | Restore snapshot: `{"backup":"<snapshot_file>","reason":"..."}`. |

```sh
curl -s -H "Authorization: Bearer $CADDY_UI_TOKEN" \
  "http://127.0.0.1:8080/api/changes?site=chat.example.com&limit=20"
```
