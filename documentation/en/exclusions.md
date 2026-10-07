# Rule Exclusions

The **Exclusions** tab (`/?tab=exclusions&domain=<site>`) configures exceptions for verified false positives, exempting a specific rule (or all rules matching a tag) from inspecting a subset of requests while keeping all other rules active. Always preview diffs and simulated impacts before applying exclusions.

Exclusion entries are maintained in `exclusions-<slug>.conf` (the UI canonical store; not imported directly by Caddy). Every modification regenerates the site's WAF overlay.

## Scoping Exclusions

| Parameter | Path | Scope | Generated Directive |
| --- | --- | --- | --- |
| — | — | Removes rule site-wide | `SecRuleRemoveById 942100` (Post-CRS) |
| `q` | — | Site-wide: skips `ARGS:q` for this rule; other parameters inspected | `SecRuleUpdateTargetById 942100 "!ARGS:q"` |
| — | `/api/posts/` | Removes rule only for requests matching path | Rule `900000x`: `REQUEST_FILENAME` match triggers `ctl:ruleRemoveById` (Pre-CRS) |
| `content` | `/api/posts/` | Skips parameter on matching path only (Narrowest) | Rule `900000x`: `ctl:ruleRemoveTargetById=942100;ARGS:content` |

Always prefer the narrowest combination. Disabling a rule globally removes that defense across your entire application.

### Exclusion Fields

| Field | Description |
| --- | --- |
| Exclude by | Rule ID, or Rule Tag (e.g., `attack-xss`, `attack-sqli`). Tag exclusions apply to all rules bearing that tag. |
| Parameter | Exact target variable name as shown in event details, including query keys, form keys, and nested JSON paths (e.g., `json.messages.0.content`). Accepts regular expressions enclosed in slashes, e.g., `/^json\.messages\.\d+\.content$/`. Restricts only request parameters; cannot exclude headers or cookies. |
| Path | Must begin with `/`, matching decoded request URI paths without query strings. |
| Path match | `Prefix` (matches paths starting with this prefix) or `Exact` (exact path match). |
| Expires at | Optional UTC expiration timestamp. Evaluated per request by Coraza using `TIME_EPOCH`; expires automatically without requiring config reloads. Expired entries remain visible until deleted. |
| Note | Operational description saved with the rule (up to 200 characters). |
| Reason | Mandatory audit rationale recorded in the change history. |

Path-scoped or expiring exclusions generate dynamic pre-CRS rules (`9000001–9000999`), capped at 999 rules per site.

### Non-Excludable Rules

| Rules | Rationale |
| --- | --- |
| `949110`, `949111`, `959100`, `959101` | Decision rules. Excreting decision rules disables blocking entirely; exclude the specific detection rule contributing the anomaly score instead. |
| Control flow & correlation (`901xxx`, `980xxx`) | These rules govern engine setup and scoring pipelines rather than inspecting user payloads; excluding them breaks engine integrity. |
| `9000000–9009999` | Internal rules generated dynamically by the UI. |

## Adding Exclusions

The recommended workflow starts from the event view: In [WAF Events](events.md#handling-false-positives) or [Retrospective Analysis](analysis.md#transitioning-from-candidate-to-exclusion), click **Review →** to open the exclusion form pre-filled with the narrowest scope.

1. Inspect or refine parameters, select **Impact history**, and click **Preview diff and impact**.
2. Evaluate the simulation: verify how many historical events over the past 14 days would be permitted, distinct client IPs, and suspected attacker proportions. If suspected attackers represent a high proportion, narrow the path or parameter scope.
3. Verify the generated directive diff. An empty diff indicates that an equivalent exclusion already exists.
4. Provide a mandatory reason and click **Add exclusion**.

## Removing Exclusions

Under **Active exclusions**, click **Remove** on any rule. Deletions apply immediately and are logged to the change history. If the list was modified concurrently by another operator, the deletion is safely rejected.

## Common False Positives

| Rule Series | Typical Scenario | Recommended Remediation |
| --- | --- | --- |
| `942100` (942xxx) | Rich text editors, code snippets, or markdown containing SQL syntax | Apply narrowest exclusion: exact path + parameter name |
| `941xxx` | Form fields containing raw HTML, markdown, or BBCode | Apply narrowest exclusion: exact path + parameter name |
| `932xxx` | Shell command snippets (developer tools, terminal outputs, AI prompts) | Apply narrowest exclusion: exact path + parameter name |
| `920420` | Upload endpoints receiving `application/octet-stream` or custom MIME types | Add the MIME type to Allowed request content types under [Policy](policy.md#request-limits) rather than disabling the rule |
| `920450` | Clients sending `Expect: 100-continue` (curl, cloud SDKs) | Exclude Rule 920450 on upload paths |
| `911100` | REST clients sending PUT, PATCH, or DELETE | Add HTTP methods under [Policy](policy.md#request-limits) |

## Rollback

Exclusion lists and WAF overlays maintain independent snapshot streams. Rolling back an exclusion snapshot restores the list and recompiles overlays. Rolling back a WAF snapshot does not discard exclusions. See [Change History & Rollback](changes-and-rollback.md).

## REST API

| Endpoint | Description |
| --- | --- |
| `PUT /api/sites/{domain}/exclusions` | **Replaces** the active exclusion list: `{"exclusions":[...],"reason":"..."}`. |
| `GET /api/sites/{domain}/policy` | Returns current policy and `exclusions` list. |
| `POST /api/sites/{domain}/impact` | Simulates the impact of proposed exclusions without applying them. |

```sh
curl -s -X POST -H "Authorization: Bearer $CADDY_UI_TOKEN" -H "Content-Type: application/json" \
  -d '{"exclusions":[{"type":"id","value":"942100","param":"content","path":"/api/posts","path_match":"exact"}]}' \
  http://127.0.0.1:8080/api/sites/chat.example.com/impact
```
