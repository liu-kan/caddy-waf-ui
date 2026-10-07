# Retrospective Analysis

The **Analysis** tab (`/?tab=analysis`) aggregates WAF telemetry over a selected time window to identify likely false positives, suspected threat actors, newly triggered rules, and high-frequency attack paths. It serves as the primary starting point for policy and exclusion tuning. (The "WAF events — last 24 hours" card on the **Overview** tab is a 24-hour summary of this same engine).

Analysis examines only audited events, which do not represent total HTTP traffic; each execution analyzes up to the 2,000 most recent matching events. Findings are heuristic suggestions: all configuration adjustments require human review and diff preview before being applied.

## Scope Selection

| Option | Description |
| --- | --- |
| Storage | Local retained events or Grafana Cloud Loki. Time ranges greater than 24 hours query Loki by default when configured. |
| Site | Analyze all sites or select an individual managed domain. |
| Range | Last 1 hour, 24 hours, 7 days (default), 14 days, or 30 days. |

## Dashboard Breakdown

| Section | Content |
| --- | --- |
| Overview Metrics | Total event count and distinct client IPs; blocked vs would-block counts; sub-threshold events (present when tuning mode is active); suspected attacker and false-positive candidate counts. |
| Daily Events | Daily event distribution over the past 14 days, color-coded by blocked, would-block, and sub-threshold. Data is pulled from daily rollups (`/ui-data/rollups/`), which persist after raw event files expire. (Rendered for local storage only). |
| False-Positive Candidates | Rules suspected of false alarms (detailed below). |
| Rules | Per-detection-rule breakdown: event frequency, action distribution, distinct client IPs, suspected attacker count, and most common paths and variables. Decision and control rules are excluded. Rules labeled **FP?** strongly exhibit false-positive patterns. |
| Likely Attackers | Suspected malicious IP addresses along with triggering rationale. |
| Top Sources | The 10 most frequent client IP addresses, detailing block counts and matched attack categories. |
| Top Paths | The 10 most targeted URL paths, distinct client counts, and top 5 triggered rules. |
| New Rules | Rules triggered for the first time within the final 24 hours of the selected range, highlighting novel attack techniques or regressions following software deployments. |

If recomputed event scores diverge from Coraza's reported totals (due to chained rules or custom anomaly scoring), a footer notice clarifies that simulations are approximations.

## Classification Heuristics

**False-Positive Candidates**: Identified when the same site, rule ID, path, and variable are triggered by at least 3 distinct client IPs, where at least 80% of those clients are not classified as suspected attackers. Non-excludable rules (decision, setup rules) are excluded. Candidates that actually caused blocking decisions rank first, followed by distinct client and event counts.

**Suspected Attackers**: A client IP is classified as an attacker if it meets any of the following criteria:

| Criterion | Reason Shown in UI |
| --- | --- |
| Matches automated security scanner signatures (Rule series 913xxx, `reputation-scanner` category) | `security scanner signature` |
| Triggers detection rules across at least 3 distinct attack categories (e.g., SQLi, XSS, LFI) | `matched N attack categories` |
| Probes at least 5 distinct paths using sensitive file/extension rules (930130, 930140, 920500, 920440) | `probed N restricted files or extensions` |

These heuristics are deterministic. A legitimate API endpoint used heavily by real users will not lose false-positive candidate status if a single automated scanner probes it, because over 80% of client traffic remains clean. Conversely, rules triggered by only one or two isolated IPs will not surface as candidates; inspect these directly via individual event views.

## Transitioning from Candidate to Exclusion

1. In **False-positive candidates**, click **Review →** to open [Rule Exclusions](exclusions.md) with pre-filled narrow parameters: Rule ID + Exact Path + Matched Variable.
2. Click **Preview** to evaluate diffs and simulate impact: verify how many events would be permitted, the number of distinct client IPs impacted, and the proportion of suspected attackers.
3. If suspected attackers constitute a significant portion of matches, narrow the exclusion scope or restrict it to a specific parameter name.
4. Provide a mandatory operational reason and apply the reviewed policy.

You can also annotate individual events as "Confirmed false positive" on the event details page to document review decisions. Annotations are stored locally and will not automatically generate exclusions.

## Estimation Limitations

- Impact analysis models only audited transactions. When tuning mode is disabled, sub-threshold requests are not logged; the UI cannot predict how many requests would be newly blocked if thresholds were lowered or paranoia levels raised.
- Rules belonging to paranoia levels higher than the active setting were never executed; their impact can only be inferred if a higher "Detection PL" was configured (see [WAF Policy](policy.md#paranoia-levels)).
- Truncated events, events with omitted variable details, or early blocking events cannot be deterministically replayed.
- Changes to HTTP methods, allowed Content-Types, or request body limits are noted in estimates but cannot be re-simulated against raw request payloads.

## REST API

| Endpoint | Description |
| --- | --- |
| `GET /api/analysis` | Parameters: `range` (default `7d`), `site`, `source=loki`. Returns complete report: `rules`, `fp_candidates`, `attackers`, `top_sources`, `paths`, `new_rules`, and dataset `coverage`. |

```sh
curl -s -H "Authorization: Bearer $CADDY_UI_TOKEN" \
  "http://127.0.0.1:8080/api/analysis?range=7d&site=chat.example.com"
```
