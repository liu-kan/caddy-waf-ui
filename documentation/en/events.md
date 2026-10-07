# WAF Events

The **Events** tab (`/?tab=events`) lists WAF events parsed from the Coraza audit log. Inspecting an individual event reveals why the request was intercepted, which rules were triggered, how many anomaly points each rule contributed, and granular rule exclusion recommendations to resolve false positives.

## Event Pipeline Lifecycle

Every 2 seconds (`CADDY_UI_INGEST_INTERVAL`), the UI reads new entries from the raw audit log, normalizes them, and appends them to local daily files at `/ui-data/events/events-<YYYY-MM-DD>.jsonl`. The read cursor is persisted across restarts. During normalization:

- Events are deduplicated by `(transaction_id, node)`.
- The rule dictionary enriches each matched rule with its type, severity, paranoia level (PL), category, and inbound/outbound score contributions.
- The `SecComponentSignature` embedded in the overlay recovers the active WAF mode, paranoia policy, and revision at the moment of request evaluation.
- The local redaction policy (`CADDY_UI_REDACTION_LOCAL`) sanitizes matches, queries, and headers: `strict` retains only rule IDs, variable names, and query parameter keys; `standard` additionally preserves matched excerpts, non-credential query values, and diagnostic request headers; `full` retains all collected data. Request bodies never enter event records. See [Configurable Redaction](redaction.md).

Events are classified into three distinct actions:

| Action | UI Badge | Definition |
| --- | --- | --- |
| `blocked` | BLOCKED | Coraza actively interrupted the transaction (based on the internal interruption flag rather than merely evaluating a deny action). |
| `would_block` | WOULD BLOCK | In `DetectionOnly` mode, the anomaly score exceeded threshold or matched a direct blocking rule, but the request was permitted through to upstream. |
| `detected` | DETECTED | Rules were matched, but cumulative anomaly score remained below threshold. Occurs primarily when tuning mode is active (see [WAF Policy](policy.md#tuning-mode)); without tuning mode, sub-threshold events are recorded only if the upstream returns 4xx/5xx errors. |

Benign audit entries (upstream 404, 401, or 5xx responses that matched zero WAF rules) and UI origin health probes (Rule `9001200`) are discarded during ingestion. See [Audit Logs & Rotation](audit-log.md#what-gets-recorded).

## Events List & Filters

| Filter | Description |
| --- | --- |
| Storage | Query local files or Grafana Cloud Loki. Time ranges exceeding 24 hours query Loki by default when configured. |
| Site | Filter by specific managed domain. |
| Action | Filter by `blocked`, `would_block`, or `detected`. |
| Range | Last 1 hour, 24 hours, 7 days, 14 days, or 30 days. |
| Client IP | Exact IP address match. |
| Rule ID | Matches events containing the specific rule ID. |
| Path Prefix | URL path prefix match. |
| Text | Case-insensitive search across Client IP, Path, Host, Rule IDs, Transaction ID, Rule Messages, and Variable Names. (Redacted payload values cannot be queried). |

Events are displayed 50 per page, sorted newest first. The score column displays "blocking score / inbound threshold". Each rule ID links to the [Rule Dictionary](rules.md). Rules with detailed notes feature expandable **Meaning** panels.

The status header displays ingestion offsets, local event counts, rule dictionary CRS version, and remote Loki connectivity status.

## Root Cause Analysis: Why a Request Was Blocked

Opening an event displays:

- **Four Core Metrics**: Inbound score / threshold, Outbound score / threshold, active mode and policy (PL, thresholds, tuning, revision), CRS version, and engine status. Scores are recomputed from triggered rules; if Coraza's decision rule recorded a total score, it is cross-referenced here. Scores contributed by rules above the blocking PL (logged for detection only) are highlighted separately.
- **Matched Rules Breakdown**: Rule ID, message, rule type and category, score contribution, target variable (e.g., `ARGS:q`, `REQUEST_FILENAME`), plain-language explanation, and upstream CRS reference comments.

Rule types dictate their role in the security decision:

| Rule Type | Role in Evaluation | Example |
| --- | --- | --- |
| detection | Increments anomaly score when triggered | `930130` Restricted file access (+5) |
| decision | Compares total score against threshold and halts execution | `949110` Inbound anomaly score exceeded |
| blocking | Immediately blocks regardless of anomaly score | `200002` Request body parse failure |
| control / correlation | Lifecycle management, initialization, correlation | `901xxx` Initialization, `980xxx` Correlation |

Example: `930130,949110`. Rule `930130` detects access to sensitive paths (such as `/.env`), contributing 5 points. Rule `949110` evaluates the inbound score (5 >= 5) and issues the blocking decision. To permit this request legitimately, you exclude detection rule `930130`; decision rule `949110` cannot and must not be excluded.

Truncated records (exceeding 50 matches) or records missing variable context are explicitly flagged when scores cannot be deterministically re-calculated.

If an event is marked BLOCKED without a decision rule, direct blocking rule, or custom rule, the UI explains the cause: typically the request body exceeded site body limits (returning HTTP 413 in `On` mode; see [WAF Policy](policy.md#request-limits)), or a custom rule executed with `nolog`.

Quick navigation links on the right panel: **Same path**, **Same client**, **Review site policy**, **Analyze this site**, and **Open in Grafana Explore** (when `CADDY_UI_GRAFANA_URL` is set).

## Local Raw Match Context

How much match detail is retained in event records is governed by `CADDY_UI_REDACTION_LOCAL`. On the origin node where the transaction occurred, clicking **Show matched values** queries the raw audit log or its rotated archives (retained for `CADDY_UI_AUDIT_ARCHIVE_HOURS`, default 48h) to extract exact matched variables, payload snippets, values, and the sanitized request URI.

- Queries are read strictly on demand; output is never stored in event databases or transmitted off-host.
- Output adheres to the currently configured local policy (`strict`, `standard`, `full`). `standard` masks credential fields; explicit `full` permits credentials.
- If raw files were purged or the transaction originated on a peer node, the UI explains that local raw context is unavailable.
- Show matched values adheres strictly to the active local policy; `strict` mode cannot be bypassed through this view. See [Configurable Redaction](redaction.md).

## IP Groups

When the client IP belongs to one or more [IP Groups](ip-groups.md), an **Client IP groups** label appears under the event title. Group-specific rules also appear in the rule list: rule IDs starting at `9002000` represent group blocks and trials ("IP group policy: inside office blocked", "IP group policy (trial): outside cn+jp would be blocked"), while rules starting at `9002500` denote engine and threshold overrides. Requests dropped by `ban` actions do not generate events (except on `DetectionOnly` sites, where they log "would block" events).

## Operator Review

The **Operator review** section logs human triage decisions:

| Decision | Meaning |
| --- | --- |
| Unreviewed | Reset triage status |
| Confirmed false positive | Legitimate traffic wrongly flagged |
| Confirmed attack | Genuine malicious attempt |

Entering a reason is mandatory. Review annotations are stored locally (`/ui-data/feedback/`) and appended to the change journal; they do not automatically generate exclusion rules or IP bans, nor are they uploaded to the cloud.

## Handling False Positives

The **If this was a false positive** section analyzes candidate detection rules (excluding decision rules, UI rules, and rules above the blocking PL), offering proposals from narrowest to widest scope:

| Scope | Generated Exclusion |
| --- | --- |
| narrowest | Rule ID + Exact Path + Matched Parameter (e.g., skip `ARGS:content` for Rule 942100 on `/api/posts` only) |
| path prefix | Same rule and parameter, broadened to parent path prefix (e.g., all paths under `/api/`) |
| parameter, whole site | Same rule skips the parameter across the entire domain |

The UI avoids proposing global, unconditional rule disablement across an entire site; if strictly necessary, add it manually on the [Rule Exclusions](exclusions.md) tab.

Each proposal includes an impact simulation: using the past 14 days of site events (up to 2,000 records), it calculates how many blocked requests would be permitted, how many distinct client IPs would be affected, and what percentage represents suspected attackers. If multiple rules tripped the threshold simultaneously, excluding one rule alone may report 0 unblocks; the UI also models the combined impact of all narrowest exclusions applied together.

Clicking **Review →** navigates to the [Rule Exclusions](exclusions.md) tab with the form pre-filled. Operators must preview diffs and impacts before applying.

## REST API

All API endpoints require `Authorization: Bearer <CADDY_UI_TOKEN>`.

| Endpoint | Description |
| --- | --- |
| `GET /api/events` | List events. Supports `range` (`1h`, `24h`, `7d`, `14d`, `30d`), `from`/`to`, `site`, `action`, `ip`, `rule`, `path`, `q`, `limit` (1–1000, default 100), `offset`, `source=loki`, and `cursor`. Returns `{"total":..., "events":[...]}`. |
| `GET /api/events/{tx}` | Fetch single event. Add `node` parameter in multi-node clusters. |
| `GET /api/events/{tx}/explain` | Explanations for each hit (`note_zh`, `contribution`, `excludable`) and proposed exclusions with simulated impact. |

```sh
curl -s -H "Authorization: Bearer $CADDY_UI_TOKEN" \
  "http://127.0.0.1:8080/api/events?range=24h&action=would_block&rule=930130"

curl -s -H "Authorization: Bearer $CADDY_UI_TOKEN" \
  "http://127.0.0.1:8080/api/events/YqBrJkwPrpHwOYMd/explain"
```
