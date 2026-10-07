# WAF Policy

The **Policy** tab (`/?tab=policy&domain=<site>`) configures CRS paranoia levels, anomaly thresholds, tuning mode, and HTTP request limits on a per-site basis. Modifications require diff and impact previews before application; every change is journaled and reversible.

Policies are rendered as `SecAction` directives with IDs `9001000–9001005`, positioned after CRS setup and before custom rules. Engine modes are configured separately under [Sites & WAF Modes](sites.md).

## Paranoia Levels

| Setting | Range | Description |
| --- | --- | --- |
| Blocking level | 1–4, default 1 | Rules at or below this level contribute to the blocking anomaly score and trigger blocks. |
| Detection level | Blocking level–4, default equals Blocking level | Rules at higher levels are evaluated and logged for observation, but do not contribute to blocking scores or block traffic. |

| PL | Characteristics |
| --- | --- |
| 1 | Recommended default; low false-positive rate. |
| 2 | Adds enhanced encoding, evasion, and protocol inspection; moderate false positives. |
| 3 | Strict inspection for specialized apps; high false positives. |
| 4 | Extremely strict; suitable only for highly controlled APIs. |

Recommended procedure for raising paranoia levels: Set Detection level to Blocking level + 1, enable Tuning mode, and observe for 7–14 days. Rules at the higher level will be logged for detection only, allowing impact simulation to predict unblocks or new blocks before enforcement.

## Anomaly Score Thresholds

| Setting | Range | Default | Associated Decision Rules |
| --- | --- | --- | --- |
| Inbound threshold | 1–10000 | 5 | 949110 / 949111 |
| Outbound threshold | 1–10000 | 4 | 959100 / 959101 |

CRS severity scores: CRITICAL = 5, ERROR = 4, WARNING = 3, NOTICE = 2. A threshold of 5 blocks on a single CRITICAL match. Raising thresholds globally permits combinations of lower-severity rules; targeting specific false positives via [Rule Exclusions](exclusions.md) is generally preferred.

**Early blocking**: Enforces evaluation checkpoints at the end of Phase 1 (request headers) and Phase 3 (response headers), blocking requests before reading entire request bodies (Rules `949111`, `959101`).

## Tuning Mode

Coraza's default `RelevantOnly` logs transactions returning 4xx/5xx responses; sub-threshold requests returning HTTP 200 are not logged. Enabling **Tuning mode** injects Rule `9001100`, logging transactions where inbound or outbound detection scores are greater than 0 as `DETECTED` events.

Benefits:
- Captures baseline data required to simulate the impact of lowering thresholds or raising paranoia levels.
- Exposes all rule matches during initial `DetectionOnly` evaluation.

Disable tuning mode after rule tuning to optimize disk space and cloud logging quotas.

## Request Limits

| Setting | Default Behavior | Description |
| --- | --- | --- |
| Allowed methods | CRS default: `GET HEAD POST OPTIONS` | Other methods trigger Rule `911100`. REST services typically require adding `PUT PATCH DELETE`. |
| Allowed request content types | CRS defaults (forms, multipart, XML, JSON) | Specifying custom types **replaces** the defaults; enter all required MIME types (`type/subtype`). |
| Request body limit | Base config 13107200 bytes (12.5 MiB) | Maximum 1 GiB. In `On` mode, requests exceeding this limit return HTTP 413. Not blocked in `DetectionOnly`. |

For endpoints handling file uploads, adjust the body limit to accommodate maximum expected payload sizes, or enforce upload size controls at the Caddy reverse proxy layer.

## Disabling Rule Groups

Specific CRS rule categories can be disabled in bulk (`SecRuleRemoveById NNN000-NNN999`): `911`, `913`, `920`, `921`, `922`, `930`, `931`, `932`, `933`, `934`, `941`, `942`, `943`, `944`, `950–956`. Setup rules (`901`), decision rules (`949`/`959`), and correlation rules (`980`) cannot be disabled.

Disabling an entire group removes all defenses for that category (e.g., disabling `933` PHP injection on a Node.js service is reasonable; disabling `942` SQLi is rarely recommended). For specific false positives, use [Rule Exclusions](exclusions.md).

## IP Group Rules

**IP group rules** apply specialized policies based on client membership in [IP Groups](ip-groups.md) (`inside any` or `outside all`), evaluated before CRS rules (Phase 1). Multiple groups can be evaluated simultaneously (e.g., `cn`, `jp` · `outside all` · `ban`):

| Action | Behavior |
| --- | --- |
| `block` | Returns HTTP 403; recorded as an event. |
| `ban` | Returns HTTP 403 without generating audit events (for high-volume whitelists). |
| `trial` | Does not block; logs requests that would have been blocked to the audit log for observation. |
| `engine` | Overrides the rule engine: `On`, `DetectionOnly`, or `Off`. |
| `tune` | Overrides PL and anomaly thresholds for matched clients. |

See [IP Groups](ip-groups.md#group-rules) for execution semantics, ordering, and examples.

## Preview & Application

1. Edit policy fields, select **Impact history** (Local or Grafana Cloud Loki), and click **Preview diff and impact**.
2. Review the generated overlay diff and simulated impact based on the past 14 days of site events (up to 2,000 records): projected unblocks, new blocks, distinct client IPs, and suspected attacker breakdowns.
3. Provide a mandatory operational reason and click **Apply reviewed policy**.

The UI verifies draft integrity upon application:
- Drafts expire after 30 minutes.
- Submitted form data must match the previewed draft.
- If underlying files (overlays, exclusions, IP rules, Caddyfiles, custom rules, or IP group lists) mutate between preview and apply, the operation is safely rejected.

## REST API

The REST API applies changes directly without draft stages, enforcing validation, snapshotting, and compensating rollbacks:

| Endpoint | Description |
| --- | --- |
| `GET /api/sites/{domain}/policy` | Returns active mode, policy, revision, and exclusions. |
| `PUT /api/sites/{domain}/policy` | Apply policy: `{"policy":{...},"reason":"..."}`. |
| `POST /api/sites/{domain}/impact` | Simulate impact without applying: `{"policy":{...}}`, `{"exclusions":[...]}`, or `{"mode":"On"}`. |

Supported policy fields: `blocking_pl`, `detection_pl`, `inbound_threshold`, `outbound_threshold`, `early_blocking`, `tuning`, `allowed_methods`, `allowed_content_types`, `request_body_limit`, `disabled_groups`, and `ip_groups`.

```sh
curl -s -X POST -H "Authorization: Bearer $CADDY_UI_TOKEN" -H "Content-Type: application/json" \
  -d '{"policy":{"blocking_pl":2,"detection_pl":2,"inbound_threshold":5,"outbound_threshold":4,"tuning":true}}' \
  http://127.0.0.1:8080/api/sites/chat.example.com/impact
```
