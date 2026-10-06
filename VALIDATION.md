# Local/cloud implementation validation

## 2026-10-06 follow-up

This run reviewed the 2026-10-05 changes, fixed the issues below and repeated the checks against the same backend image (`liukan/caddy-with-auth:latest`, image `3a4bf970ed0c`, digest `sha256:ae47447d…ba1c2c`) and `grafana/alloy:v1.20.0`. The backend image was not modified or rebuilt.

| Check | Result and scope |
| --- | --- |
| gofmt / go vet / golangci-lint | Passed; zero lint findings |
| `go test -race ./...` | Passed, all packages |
| Native request test | `CADDY_TEST_BINARY` built from Caddy v2.11.6, coraza-caddy/v2 v2.6.1, Coraza v3.8.0, CRS v4.25.0 (the image's module versions): passed |
| `make crs-version` | Reported Caddy v2.11.6, coraza-caddy/v2 v2.6.1, coraza-coreruleset v4.25.0, Coraza v3.8.0 from the image |
| Coraza `RelevantOnly` behavior | Native Coraza v3.8.0 logged plain 404/401/502 responses without any rule match (baseline `SecAuditLogRelevantStatus`). The UI now skips such records; in the Compose run three rule-less upstream 500 responses stayed in the raw log but produced no events |
| Request body limit | On mode rejected a 14 MB JSON body with HTTP 413 (DetectionOnly passed it). The event was stored as a blocked event without rules and its page explained the likely cause |
| Real-image Compose run (`ABHKZ`, the previous default) | init services, Caddy, UI and Alloy started; DetectionOnly/On/Off/DetectionOnly changes recorded validate, load, readback and request stages as successful with origin probes |
| Events and pages | `/.env` produced 930130 + 949110; Overview listed recent stored events; local match context showed `.env` in `REQUEST_FILENAME`; IP Rules and Policy copy rendered as corrected; `/api/analysis` returned snake_case fields |
| Alloy | Pushed snappy protobuf batches with basic auth to a local Loki protocol fixture |
| Audit parts default | Compose now defaults to `AHKZ`, since `AHKZ` records already carry method, URI and matches. A second real-image run with `AHKZ` passed the On-mode probe, blocked `/.env` with 403, showed local match context, and the raw audit log contained no request Cookie value |
| Chinese documentation | All relative links and heading anchors in `documentation/zh/` resolve |

Light-load memory after this run: Caddy 112 MiB, UI 10 MiB, Alloy 123 MiB, within the Compose limits. Grafana Cloud credentials were still unavailable; the real cloud account was not exercised. The disposable Compose project, its volumes and networks, and the fixture process were removed after validation.

## 2026-10-05


The existing `liukan/caddy-with-auth:latest` backend was reused, not rebuilt. This run implemented direct cloud-history viewing and reviewed policy/exclusion workflow, then tested them in isolated local environments. No production service, certificate volume or real Grafana Cloud account was changed.

### Runtime identities

- Backend local image: `3a4bf970ed0c`; repository digest `liukan/caddy-with-auth@sha256:ae47447d47ec0573210ef64a38c089758f452f23e0fed71b53cbbd3df9ba1c2c`.
- Backend: Caddy v2.11.6, coraza-caddy/v2 v2.6.1, Coraza v3.8.0, embedded CRS v4.25.0, UID 65532, shell-free DHI runtime.
- Alloy: actual `grafana/alloy:v1.20.0`, digest `sha256:f111cce835516c5f99166342be7038496b52ced16667be5a11e19258a3e4cd30`.
- Opt-in native request test: Caddy v2.11.4 with the same Coraza module versions.

### Checks in this run

| Check | Result and scope |
| --- | --- |
| Complete Go race suite | Passed, including the native request test |
| go vet / golangci-lint | Passed; zero lint findings |
| Go formatting / shell syntax / Compose config | Passed |
| UI Docker image | Built and exercised in the isolated project |
| Alloy logs plus optional metrics configuration | Validated by the pinned Alloy runtime |
| Caddy → normalized files → Alloy → Loki protocol fixture → local UI | Passed with actual Caddy and Alloy; Loki storage/query was a stdlib test fixture |
| Four shipped streams | WAF event, access, runtime, change records all received |
| Privacy | Synthetic query token, Authorization and Cookie values absent from all received records; high-cardinality IP/tx/path/rule CSV absent from indexed labels |
| CSV/JSON rule lookup and event meanings | 930130 and 949110 resolved together, with detection/decision distinction and curated Chinese notes rendered locally |
| Local HTML workflow | Cloud event detail, retrospective links, operator feedback, cloud impact preview and exact reviewed policy Apply passed using synthetic authenticated requests |
| Origin request stages | On probe verified, ordinary restricted-file request 403; DetectionOnly and Off requests 200, with distinct verification evidence |
| Compensation | Failed origin response restored disk configuration and triggered a compensating live reload in an isolated Admin API fixture |
| Draft consistency | Edited intent and baseline drift rejected before reload; reviewed artifact bytes matched the published file |
| Actual temporary exclusion expiry | Scoped exemption allowed a request before expiry and blocked it afterwards without reloading |
| Actual raw-audit rotation | Native Coraza writer reopened after rename/revision reload; new audit records appeared in the new file |
| Late archive writes / restart | Durable archive cursors retained late records without duplicate ingestion |
| Cache eviction / restart / node identity | Evicted detail remained retrievable; dedup survived restart; equal transaction IDs on different nodes stayed separate |
| Torn event append | A partial final JSON record did not swallow the next complete event after restart |
| Cloud pagination | Shared-timestamp pagination regression passed; dense/duplicate boundary uncertainty is explicitly reported |
| Impact analysis | Disabled-group regression corrected; truncated/early/unexecuted-rule and unsupported replay caveats visible |
| Streaming and application contract | Native SSE timing, WebSocket upgrade/frame, multipart upload, OAuth/MCP paths and validated client-IP rejection passed |

Light-load Docker memory after these tests was approximately Caddy 91.8 MiB, UI 16.1 MiB and Alloy 79.7 MiB. These are observations from a small synthetic fixture, not sizing guarantees. Compose limits are Caddy 512 MiB, UI 256 MiB and Alloy 256 MiB; normalized history is bounded separately. See [LOCAL-CLOUD.md](LOCAL-CLOUD.md) for limits and additional disk needs.

The local HTML workflow used a synthetic bearer credential. Cookie/CSRF/session protections retain their existing tests and were not weakened to accommodate HTTP test clients. The repository's historical compatibility checks remain represented by the preserved integration tests.

### Verification limits

Grafana Cloud credentials were unavailable, so a real cloud account's access-policy scope, tenant endpoint, retention and ingestion behavior were not exercised. The test fixture implements the Loki push/query protocol used here; it does not prove every production LogQL/backend limit. Existing live Cloudflare, LibreChat auth, user uploads, OAuth/MCP integrations and production traffic were not exercised. Analysis is bounded and approximate, and there is no complete request replay or guarantee of lossless telemetry during indefinite outages.

The disposable test project's containers, networks and volumes were removed after validation. Source and the locally built UI test image remain. Configure your actual Grafana credentials and merge sidecars into the existing topology following [INTEGRATION.md](INTEGRATION.md) and [LOCAL-CLOUD.md](LOCAL-CLOUD.md).
