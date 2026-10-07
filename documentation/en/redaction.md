# Configurable Redaction

Local data retention and cloud forwarding policies are configured independently; active levels are displayed across event detail pages and pipeline status banners. We recommend retaining diagnostic match fragments locally while shipping only rule IDs, paths, and scores to the cloud:

```dotenv
CADDY_UI_REDACTION_LOCAL=standard
CADDY_UI_REDACTION_CLOUD=strict
CADDY_UI_REDACTION_HIDE=customer_email,internal_note
CADDY_UI_REDACTION_KEEP=pass_rate,x-correlation-id
CADDY_UI_CLOUD_DISK_MAX_MB=128
```

After modifying `.env`, recreate the containers:

```sh
docker compose --profile cloud up -d --build caddy-waf-ui alloy
```

When unconfigured in Compose, both ends default to `strict`; `.env.example` explicitly recommends local `standard` and cloud `strict`. Invalid level values halt server startup immediately to prevent silent privacy degradation.

| Level | Retained Information | Credential Handling |
| --- | --- | --- |
| `strict` | Rule IDs, matched variable names, request path, query parameter names, scores, and policy metadata. | Matched values hidden; query parameter values and request headers discarded. |
| `standard` | Additionally retains classifiable matched values, ordinary query parameter values, and diagnostic request headers. | Masks detected passwords, tokens, Authorization headers, Cookies, etc.; unrecognized variables and unclassified log data fragments remain hidden. |
| `full` | Retains all captured values and headers (subject to excerpt length limits). | **Credentials are retained**, masked only if matched against explicit `HIDE` lists. |

Setting `full` does not automatically enable request or response body capture, nor does it recover uncollected headers. Coraza's default `AHKZ` audit parts do not capture request headers; header collection requires configuring `CADDY_UI_AUDIT_LOG_PARTS=ABHKZ`. Raw audit files on disk are never altered by these settings.

`standard` identifies credentials using name heuristics rather than unbounded natural-language classification. Business attributes such as `max_tokens` or `author` are not falsely redacted due to substring matching. URIs, parsed JSON structures (including escaped names, objects, and arrays), and form bodies are sanitized; when a composite value is redacted, its matched fragments are also masked to prevent secondary leaks. Supplement the `HIDE` list based on your specific application schemas.

## Granular Overrides

- `CADDY_UI_REDACTION_HIDE`: Comma- or space-separated, case-insensitive list. Matches exact names, the final segment of dotted paths, or discrete words within camelCase/snake_case names. Enforced at all levels (including `full`), taking precedence over `KEEP`.
- `CADDY_UI_REDACTION_KEEP`: Matches exact names or the final dotted segment, overriding built-in credential classifiers in `standard`, or whitelisting specific Cookie values and request headers. **Cannot bypass `strict` or `HIDE`**.
- Both lists accept at most 64 entries of up to 128 bytes each. Wildcards and regular expressions are not supported. Overrides apply to both local and cloud processing pipelines.
- Examples: `hide=password keep=password` keeps passwords masked; `keep=pass_rate` preserves business metrics; `keep=authorization` permits `standard` to retain Authorization headers.

The effective cloud export level cannot exceed the local retention level: if local is `standard` and cloud is `full`, the effective cloud level is clamped to `standard`. Information stripped at ingestion cannot be recovered by raising levels later.

## Files and Inspection

Local events are written to `/ui-data/events/events-*.jsonl`; events processed under cloud export policies are written to `/ui-data/cloud/events/events-*.jsonl`. **Alloy reads exclusively from the latter**, ignoring local rich event files and imported `imported-*.jsonl` files. Upon upgrading, existing local events are migrated to the export queue under the cloud policy without duplicate shipping.

Local and cloud queues each default to a 128 MiB ceiling with 14-day retention. If not uploading to Grafana Cloud, setting `CADDY_UI_CLOUD_EXPORT=false` stops writing the export queue. Ingestion offsets advance only after both local and export writes succeed. Export errors are logged with automatic retry; retries operate strictly on retained local records and will never expand detail from raw audit logs.

Event details, REST APIs, raw audit log viewers, and **Show matched values** lookups adhere strictly to the currently configured local level. On-demand raw audit inspections never bypass `strict`; lookups are bounded to 64 MiB scan budgets, 8 MiB single-record limits, 5-second timeouts, and a single concurrent worker. Web and API responses return `Cache-Control: no-store`.

Modifying redaction levels impacts newly ingested events and current views; it does not rewrite existing historical files on disk or delete events already forwarded to remote storage.
