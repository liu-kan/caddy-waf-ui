# caddy-waf-ui Documentation

caddy-waf-ui is a dedicated WAF management sidecar for [caddy-with-auth](https://github.com/liu-kan/caddy-with-auth): the backend container image is reused as-is, while the UI manages Coraza WAF configurations via volume-mounted overlay files and the Caddy Admin API. WAF events can be forwarded via Grafana Alloy to Grafana Cloud Loki, with event inspection, rule explanation, retrospective analysis, and rule tuning all accessible within the local UI.

All web UI endpoints follow the pattern `/?tab=<page>`. Web authentication and API access share a single token (`CADDY_UI_TOKEN`): web browsers use session cookies established upon login, while automated scripts use `Authorization: Bearer <token>`.

## Table of Contents

**Installation & Deployment**

- [Quick Start](quick-start.md): Get up and running quickly with the bundled Docker Compose example.
- [Integrating with an Existing Deployment](deployment.md): Integrate the sidecar into an existing caddy-with-auth deployment.
- [Deployment with coraza-ipset Image](ipset-image-deployment.md): Step-by-step guide to deploying or migrating to images featuring the IP matching plugin (`liukan/caddy-with-auth:coraza-plugins-ipset`), configuring country whitelists, verification, and rollbacks.
- [Configuration Reference](configuration.md): Complete reference of environment variables, defaults, and usage.
- [Backend Image](backend-image.md): Image prerequisites, runtime mounts vs image baking, CRS versions, and rule dictionaries.
- [Grafana Cloud & Alloy](grafana-cloud.md): Telemetry data scope, token permission segregation, free-tier budgets, and querying remote Loki history locally.
- [Configurable Redaction](redaction.md): Three-tier local and cloud redaction policies, hide/keep lists, and historical retention boundaries.
- [Security & Privacy](security.md): Trust boundaries, token handling, redaction mechanisms, and local raw audit log safety.
- [Upgrade Notes](upgrade-notes.md): Behavioral changes relative to upstream versions and earlier releases.

**Inspection & Analysis**

- [Overview](overview.md): Summary of managed sites and WAF telemetry over the last 24 hours.
- [WAF Events](events.md): Event log viewer, blocking explanations, local raw match context, and false-positive triage.
- [Rule Dictionary](rules.md): CRS rule explanations and meanings (e.g., `930130,949110`).
- [Retrospective Analysis](analysis.md): False-positive candidates, suspected threat origins, newly triggered rules, and traffic trends.
- [Audit Logs & Rotation](audit-log.md): Coraza raw audit logs, read offsets, rotation and retention archives, and disk budgets.
- [Metrics](metrics.md): Prometheus `/metrics` endpoint and optional metric shipping.

**Policy Tuning**

- [Sites & WAF Modes](sites.md): Managing `On`, `DetectionOnly`, and `Off` modes, with post-deployment origin verification.
- [WAF Policy](policy.md): Paranoia levels, anomaly score thresholds, tuning mode, request limits, and disabling rule groups.
- [Rule Exclusions](exclusions.md): Scoped rule exceptions (Rule ID + Path + Parameter) with expiry tracking.
- [IP Rules](ip-rules.md): Per-visitor-IP block and allow lists.
- [IP Groups](ip-groups.md): Named dynamic blocklists imported from sing-box rule-sets (.srs/JSON) or CIDR lists, automated updates, match engines, country whitelists, and threshold strategies.
- [Change History & Rollback](changes-and-rollback.md): Release pipeline stages, compensating rollbacks, configuration snapshots, and `last_good` recovery.

Additional English documentation in the repository root includes [README.md](../../README.md), [LOCAL-CLOUD.md](../../LOCAL-CLOUD.md), [INTEGRATION.md](../../INTEGRATION.md), and [ARCHITECTURE.md](../../ARCHITECTURE.md).
