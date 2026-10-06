# Configurable event redaction

The local retention policy and cloud export policy are independent. Configure them in `.env`, then recreate the UI. There is no new database or service. The event page and pipeline status show the selected levels; the event records its applied level.

Recommended investigation settings:

```dotenv
CADDY_UI_REDACTION_LOCAL=standard
CADDY_UI_REDACTION_CLOUD=strict
CADDY_UI_REDACTION_HIDE=customer_email,internal_note
CADDY_UI_REDACTION_KEEP=pass_rate,x-correlation-id
CADDY_UI_CLOUD_DISK_MAX_MB=128
```

```sh
docker compose --profile cloud up -d --build caddy-waf-ui alloy
```

The Compose fallback is strict for both destinations; `.env.example` explicitly recommends local standard and cloud strict. Standalone runs default to strict. Invalid levels stop startup; they never silently turn off masking.

## Levels

| Level | Match values | Query values | Request headers | Credential handling |
| --- | --- | --- | --- | --- |
| `strict` | Hidden | Names only | Omitted | All values hidden |
| `standard` | Diagnostic values retained | Non-credential values retained | Diagnostic allowlist and explicit keep entries | Recognized credential names and cookies hidden; unclassified logdata and unknown variables hidden |
| `full` | Available values retained | Available values retained | All collected headers retained | Credentials retained unless an explicit hide entry matches |

Full is an explicit choice to retain collected credential material. It still uses bounded excerpts: match data 160 bytes, value 200 bytes, query 1,024 bytes, at most 40 headers with 256-byte values. It does not enable request/response-body logging. `CADDY_UI_AUDIT_LOG_PARTS=AHKZ` omits headers; use `ABHKZ` only if you want to collect them in the raw local audit log. A redaction level cannot recover a field that Coraza did not record.

Standard is a name-based diagnostic filter, not a general detector of every secret embedded in arbitrary prose. Names such as password, access_token, Authorization, Cookie and apiKey are recognized. Ordinary names such as max_tokens and author are not mistaken for credentials. URI credentials, structured JSON (including escaped keys and object/array values), and named form values are masked. If a composite value is masked, its matched fragment is hidden too, so the fragment cannot reveal the removed credential. Unknown/opaque data is conservative under standard; inspect it locally with an explicitly selected full policy when necessary.

The cloud level is capped at the local level. Requesting cloud full while local standard produces effective cloud standard. Querying an older full event under current local strict also yields a strict view. This filtering does not rewrite the underlying retained files.

## Name overrides

`CADDY_UI_REDACTION_HIDE` and `CADDY_UI_REDACTION_KEEP` accept comma/space-separated names, case-insensitively (at most 64 names, each at most 128 bytes).

- Hide always wins, including at full. Entries match a complete parameter/header/cookie name, its final dotted segment, or one name word.
- Keep overrides standard's built-in credential classification for an exact name or final dotted segment. It also adds a header to the diagnostic allowlist and can permit a named cookie match.
- Keep does not override strict or hide. Selecting keep=authorization would deliberately permit that header at standard unless hide also names it.
- Overrides apply to both local and cloud transformations. Recognized JSON members and form/query fields are processed structurally where possible. Full unclassified text cannot reliably associate every free-form fragment with a name; use strict when that uncertainty is unacceptable.

For example, `hide=password keep=password` still hides it. `keep=pass_rate` permits a business metric whose name would otherwise contain the word pass. `keep=x-correlation-id` retains that header under standard. Wildcards and regular expressions are not supported in these name lists.

## Data flow and failure handling

1. Coraza writes its existing raw local audit log. These settings do not rewrite or mask that source file.
2. The UI normalizes it with the local policy before truncation and persistence, writing `/ui-data/events/events-*.jsonl`.
3. A copy receives the effective cloud policy, then is written to `/ui-data/cloud/events/events-*.jsonl`.
4. Alloy reads only the cloud directory. Local event files and `imported-*.jsonl` are never outbound inputs. Access/runtime/change streams retain their separate fixed allowlists.
5. On first upgrade, retained local events are migrated to the cloud queue without re-exporting imported history. A durable marker and node/transaction deduplication make interrupted migration retryable.
6. Local and export writes must both succeed before the raw cursor advances. Export-disk failure leaves the cursor at the record; retry uses its existing retained local representation, not more detailed raw input. Both stores have independent disk ceilings, and the export cache holds one full event.

The cloud queue defaults to the same 14-day retention and a separate 128 MiB ceiling. Local normalized retention has its own 128 MiB ceiling. Raw audit archives, rollups, backups, drafts and Alloy positions are additional disk use. Export counts describe retained queue records, not unacknowledged deliveries: Alloy owns delivery positions, and no infinite-outage lossless guarantee is made.

## Local viewing and historical data

The event page, API event/detail/explain endpoints, legacy Raw Audit Log page and on-demand local match lookup follow the current local policy. The raw lookup does not bypass strict and never writes or uploads its response. It supports compact/formatted/concatenated JSON, checks event identity/clock/Host, and limits scans to one at a time, five seconds, 64 MiB total and 8 MiB per record. Sensitive UI/API responses use Cache-Control: no-store.

Changing levels affects newly collected events and the current view. It does not recover removed fields, rewrite raw/retained/queued records, or delete already uploaded cloud history. Previously queued records keep the policy chosen when they were created; changing from full to strict does not retroactively erase them. Address existing retained/queued/cloud material separately if reducing a previously permissive policy.

`CADDY_UI_MATCHED_VALUES` is deprecated. Standalone startup without an explicit local level maps legacy true to standard and false/unset to strict. Compose uses the new explicit levels; replace the old variable in your `.env`. On-demand raw lookup can recover available context only under the configured local policy while the raw record still exists.

See [LOCAL-CLOUD.md](LOCAL-CLOUD.md) and the [Chinese guide](documentation/zh/redaction.md). Real-cloud account credentials are still needed for production tenant validation.
