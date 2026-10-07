# Rule Dictionary

The **Rules** tab (`/?tab=rules`) explains every rule ID that may be logged by the backend: what it inspects, its paranoia level (PL), its anomaly score contribution, and its role in the security decision. Rule IDs throughout event lists and detail pages link directly here.

## Searching the Dictionary

The search bar accepts flexible input formats:

| Input | Match Behavior |
| --- | --- |
| `930130,949110` or `930130 949110` | Lists matching rules in sequence |
| `"rule_ids_csv":"930130,949110"` | Parses directly from raw JSON event or Loki log snippets |
| `93013` | Partial prefix/substring search, matching rules like `930130` |
| `sql`, `attack-lfi`, `lfi` | Case-insensitive search across rule messages, categories, and tags |

When querying rule lists, unrecognized numbers are listed explicitly as **Unknown**, prompting you to check your backend CRS version or custom rule definitions rather than silently ignoring them.

Filter by rule **Kind**:

| Kind | Purpose | Count in CRS 4.25.0 |
| --- | --- | --- |
| Detection | Increments anomaly score when triggered; eligible for exclusion | 341 |
| Decision | Evaluates total score against threshold: 949110, 949111 (inbound); 959100, 959101 (outbound) | 4 |
| Direct block | Immediately blocks regardless of score: 200002 (body parse error), 200003 (multipart validation error), 901001, 901500 (CRS config errors) | 4 |
| Control flow | Lifecycle initialization, PL skipping, setup rules | 269 |
| Correlation | End-of-request logging and summary correlation | 13 |

## Dictionary Sources

| Source | Content |
| --- | --- |
| Embedded Dictionary | Compiled directly from the `coraza-coreruleset` module bundled with the backend image (currently 4.25.0), including upstream rule comments and source code links (631 rules total including Coraza recommended base rules). |
| Plain-Language Notes | Explanations for 132 common rules and descriptions across all 22 attack categories. Rules lacking individual notes display category summaries. |
| UI Generated Rules | `9000001–9000999` (Path/Expiry exclusions), `9001000–9001005` (Policy), `9001100` (Tuning), `9001200` (Origin probes), `9002000–9002499` (IP Group block/ban/trial), `9002500–9002999` (IP Group engine/threshold overrides). |
| Custom Rules | Parsed at startup from `CADDY_UI_WAF_BEFORE_FILE` and `CADDY_UI_WAF_AFTER_FILE`, displaying custom `msg` and tag metadata. |
| Mounted Rule Directories | When `CADDY_UI_CRS_RULES_DIR` is set, rules in that directory override the embedded dictionary to support non-standard CRS versions. |

Custom rule files are read at server startup; restart the UI after editing custom rule definitions.

If the backend image's CRS version diverges from the dictionary, a warning appears in the status banners on the **Events** and **Analysis** pages. See [Backend Image](backend-image.md#upgrading-coraza-or-crs).

## Inspecting a Single Rule

Click any rule ID or navigate to `/?tab=rules&id=930130`:

- **Header**: Kind, Category, Paranoia Level, Severity, Score Contribution (Inbound or Outbound), Execution Phase.
- **Explanation**: Plain-language description and category summary.
- **Definition**: Target variables, operator, chained conditions, actions, tags, source file, and line numbers; **CRS description** displays verbatim upstream comments.
- **Last 14 Days**: Frequency in local events, distinct client IPs, suspected attacker count, first and last seen timestamps, action distribution (blocked / would block / sub-threshold), top paths, target variables, and affected sites. If flagged as a false-positive candidate, the reason is displayed.
- **Events with this rule**: One-click filter navigating to events from the past 14 days containing this rule.
- **Rule source**: Direct link to the upstream CRS repository at the exact line of code.

Rules not present in the dictionary display "Not part of the CRS 4.25.0 dictionary", indicating custom rules or version mismatches.

## Interpreting Common Rule Combinations

| Combination | Explanation |
| --- | --- |
| `930130,949110` | Rule 930130 detects access to restricted files (`.env`, `.git/`, etc.), adding 5 points. Decision rule 949110 evaluates that the score (5) meets the threshold (5), blocking the request. |
| `942100,949110` | libinjection flags SQL injection syntax (+5 points) and triggers a block. Verify whether the matched parameter legitimately receives rich text, code snippets, or SQL-like syntax. |
| `913100,949110` | User-Agent matches known security scanner tools (+5 points). Indicates automated scanning. |
| Only `920350` | Host header is a raw numeric IP address (+3 points). Below threshold 5, resulting in `DETECTED` (logged only in tuning mode or if upstream returns 4xx/5xx). Typical of IP-based internet scanners or load balancer health checks. |
| Detection rules only, without `949110` | Total anomaly score remained below threshold. Recorded in tuning mode or when upstream returns 4xx/5xx errors. |
| `200002` alone | Request body parsing failed; immediately rejected with HTTP 400 regardless of anomaly score. |

Decision rules (`949110`, etc.) cannot be excluded: disabling them removes inbound blocking capabilities across the entire site. Exclude the underlying detection rule instead, keeping the scope as narrow as possible. See [Rule Exclusions](exclusions.md).

## REST API

| Endpoint | Description |
| --- | --- |
| `GET /api/rules?q=930130,949110` | Search rules (optional `kind` filter). Returns `{"crs_version":"4.25.0","rules":[...]}`. |
| `GET /api/rules/{id}` | Inspect a single rule with metadata and `excludable` status. |

```sh
curl -s -H "Authorization: Bearer $CADDY_UI_TOKEN" \
  --get --data-urlencode 'q=930130,949110' http://127.0.0.1:8080/api/rules
```
