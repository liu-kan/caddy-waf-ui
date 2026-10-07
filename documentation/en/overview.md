# Overview

The **Overview** page (`/?tab=overview`, the default landing view upon logging in) provides a consolidated summary of all managed sites and WAF activity over the last 24 hours.

## Dashboard Components

| Section | Content |
| --- | --- |
| Admin API Readback | Verification results from the most recent policy publication since server startup. If validation fails, missing domains are highlighted: this indicates that the running Caddy configuration diverged from the overlays and an automatic rollback was executed. Consult **Rollback & History** for diagnostic details. Hidden if no publications have occurred since startup. |
| Managed Domains | Total number of managed sites, broken down by active mode (`On`, `DetectionOnly`, `Off`). |
| Active CRS Exclusions | Total number of active rule exclusions configured across all sites. |
| IP Rule Engine | Total count of explicitly denied and allowed IP addresses. |
| WAF Events (24h) | Cumulative event count over the past 24 hours, separating blocked requests from detection-only matches. |
| WAF Events — Last 24 Hours | Visual summary of blocked, would-block, and sub-threshold events; distinct client source counts; suspected attackers and false-positive candidates; top 8 triggered rules (Rule ID × event frequency) with click-through rule dictionary explanations. Click **Analyze →** to jump into 24-hour [Retrospective Analysis](analysis.md). |
| Managed Per-Site WAF Domains | Per-site status cards displaying active WAF mode and last updated timestamp. Quick-action buttons allow direct mode switching (switching to `Off` requires confirmation); **WAF Conf** opens [Sites & WAF Modes](sites.md); **Rules** opens the site's [Rule Exclusions](exclusions.md). |
| Recent WAF Events | The 5 most recent events recorded in the last 24 hours. Click any request path to open event details, or click a rule ID to inspect its explanation. Click **All events →** to navigate to [WAF Events](events.md), or **Raw audit log →** to inspect the live audit log. |

A site card labeled **degraded** indicates that the WAF mode header inside the site overlay file is unreadable or unrecognized. See [Sites & WAF Modes](sites.md#managed-sites).

## Routine Inspection Checklist

1. Verify that the Admin API Readback banner indicates no configuration divergence or errors.
2. Confirm that no production domains are unexpectedly in `Off` or `DetectionOnly` mode.
3. Review the 24-hour event timeline: check for sudden spikes in block decisions or unfamiliar rule IDs among the top triggers.
4. If the False-Positive Candidates counter is greater than zero, proceed to **Analysis** to review potential rule tuning opportunities.

If no events appear on the dashboard, check the status banner at the top of the **Events** or **Analysis** pages to verify that the audit log tailer is actively running and has encountered no file read or offset errors.
