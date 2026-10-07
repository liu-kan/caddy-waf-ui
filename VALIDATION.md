# Validation

Runs are listed newest first. No run modified or rebuilt the backend image (`liukan/caddy-with-auth:latest`, local image `3a4bf970ed0c`).

## 2026-10-06 coraza-ipset: binary search for IP lists

caddy-with-auth gained a Coraza operator plugin (`plugins/coraza-ipset`) that replaces `@ipMatchFromFile` and `@ipMatchF` with a binary search over sorted ranges. The UI and its overlays are unchanged.

| Check | Result and scope |
| --- | --- |
| Plugin tests | Edge cases, 30 random rounds, fuzz seeds, both operator names replaced, the shared list released after the last WAF closes, relative paths, missing file: passed on Coraza v3.8.0 and v3.8.1 with the race detector; golangci-lint 0 issues |
| Fuzzing | 933,409 executions in 60 seconds, no difference from Coraza's algorithm |
| Mutation checks | Removing the IPv4-mapped mask handling or the operator registration fails the tests |
| Coraza drift guard | The `ipMatch` sources of v3.8.1 equal v3.8.0; the image build runs the hash test against the Coraza it links |
| Lookup cost | 67 ns for 10,000 networks and 82 ns for 280,000, against 96 µs and 2.18 ms for Coraza's scan. Parsing 280,000 networks takes about 90 ms. Retained memory is 0.31 MiB for CN+JP and 1.97 MiB for CN+JP+US, shared per process |
| Native Caddy, same configuration, one core | Banned requests: 3,333/s to 18,254/s (CN+JP) and 364/s to 18,236/s (CN+JP+US). Allowed requests: 2,191/s to 2,658/s and 940/s to 2,686/s, equal to a site without a group rule (2,648/s) |
| UI native tests with the plugin build | `TestRealCaddyIPGroupRules` and `TestRealCaddyWAFUpdatesAndStreaming` passed unchanged |
| Image build (`docker build --target final`) | Go 1.27.1, Caddy v2.11.7, coraza-caddy v2.6.1, Coraza v3.8.1, CRS v4.25.0. The plugin tests (drift test included), the dependency check and the plugin assertion passed in the builder |
| Image tests | `tests/test_coraza_ipset.py` passed 4 of 4 and `tests/test_coraza_cves.py` 2 of 2 on the new image. On the old image the request tests also pass and only the build-info check fails |
| Compose e2e with the new image | URL groups `jp` and `cn` with a ban outside both: JP and CN clients (IPv4, IPv6, IPv4-mapped) 200, US and DE 403, a JP client requesting `/.env` 403 by CRS. All publish stages succeeded; bans left no audit record and no CRS reporting error. Banned requests ran at 8,400/s against 2,835/s on the old image (one-CPU Caddy through Docker port forwarding) |
| Rollback | The old image loaded the same overlays and lists, returned the same results, and a later publish succeeded |
| UI image | Alpine v3.23 replaced tzdata 2026d-r0 with 2026e-r0; the pin was updated so the image builds again |

## 2026-10-06 lint tools, public lists and country allowlists

This run installed the pinned quality tools, imported real country lists from public URLs, added multi-group rules and the `ban` action for country allowlists, and measured IP matching cost.

| Check | Result and scope |
| --- | --- |
| Quality tools | `make tools`: actionlint 1.7.12, hadolint 2.15.1 and golangci-lint 2.12.2 sha256-verified, govulncheck 1.7.0 through the Go checksum database; yamllint 1.38.0 and zizmor 1.29.0 through uv |
| `make lint` | Passed: yamllint, actionlint, zizmor, hadolint (one info-level DL3066 note under the warning threshold) and golangci-lint with 0 issues. The pinned golangci-lint (built with go1.26.2) could not type-check the local go1.27.0 standard library; `make lint-go` and the CI lint job now run it on the `go.mod` toolchain |
| `make vuln` | No vulnerabilities, with the go1.27.0 and go1.26.6 standard libraries |
| gofmt / go vet / `go test -race ./...` | Passed, all packages, including the native Caddy tests |
| Public rule-sets | MetaCubeX `geoip/jp.srs` (68,673 bytes) and `cn.srs` (36,417 bytes), rule-set version 2: parsed prefixes equal sing-box's own decoding (17,385 and 9,648). A refresh revalidated with the ETag (HTTP 304, no republish); a forced download found the same content |
| Native Caddy test | A `ban` outside two groups passed their clients, denied others with 403 before CRS and wrote no audit record. Without the fix below, the test fails on CRS reporting errors in the Caddy log |
| CRS reporting errors | A request denied in phase 1 never runs the CRS initialization, and rule 980099 then logged three errors per request. Block and ban rules and the On-mode origin probe now start the four CRS anomaly scores at 0; no CRS rule is skipped. A DetectionOnly would-be ban still recorded its full CRS detection (920350, 930130, 949110); one coraza-caddy line per denied request remains |
| Real-image Compose run | The container downloaded both URL groups. One `ban` rule outside `cn` and `jp`: JP and CN clients (IPv4 and IPv6) 200, US and DE clients 403 with no event or audit record, a JP client requesting `/.env` still blocked by CRS. Validate, load, readback and request stages succeeded in On and DetectionOnly; DetectionOnly recorded the would-be ban. The IP Groups and Policy pages showed the URL groups and the two-group rule |
| Matching cost (one Caddy core, Apple M1 Max, loopback) | A normal request through CRS: about 0.41 ms. Allowlist of CN+JP (26,730 merged prefixes): 0.50 ms per allowed request, 0.31 ms per ban; CN+JP+US (281,382): 1.14 ms per allowed request, 2.9 ms per ban. Zeroing the scores costs about 4 µs per ban over skipping the 980 rules. Per lookup over CN+JP+US: Coraza `@ipMatch` 2.9 ms, Caddy `client_ip` 1.1 ms, sorted ranges 55 ns, an MMDB-layout trie 80 ns |

Not exercised: the real Grafana Cloud tenant (no credentials). The disposable Compose project, its volumes and networks were removed.

## 2026-10-06 redaction review and IP groups

This run reviewed the configurable redaction round (commits 1343f53 and f4a6865), completed the paused items and added IP groups.

| Check | Result and scope |
| --- | --- |
| gofmt / go vet / golangci-lint | Passed; zero lint findings |
| `go test -race ./...` | Passed, all packages |
| Redaction review | Probes at standard: truncated JSON objects and arrays and escaped keys were hidden; a multipart body kept its `name="password"` part value. Fixed: standard and strict hide multipart bodies whole, and so does full when a hide list is set (as for XML), with a regression test |
| Raw audit archives | Retention is configurable (`CADDY_UI_AUDIT_ARCHIVE_HOURS`, minimum 48 hours); match lookup picks the archive by event time before the newest-first fallback |
| sing-box rule-set parser | Fixtures compiled with sing-box v1.14.2's encoder; parsed prefixes equal sing-box's own decoding for rule-set versions 1, 3 and 5, including skipped domain, AdGuard, port, process and interface-address rules and 3,600 random prefixes. Mixed-condition, inverted and `and` rules are rejected; truncated, trailing-data, bad-zlib, bad-family, decompression-bomb and over-limit inputs fail |
| Group registry | File and HTTPS sources (local TLS servers): conditional requests, size, redirect and status limits, proxy through CONNECT, shrink hold/approve/discard, a failed import keeps the active list, unreferenced lists are collected |
| Native request test (`CADDY_TEST_BINARY`: Caddy v2.11.6, coraza-caddy/v2 v2.6.1, Coraza v3.8.0, CRS v4.25.0) | Passed. Through the trusted-proxy client address: block from a `.srs` list (range and single address; an adjacent address passed), DetectionOnly for one group while non-members were still blocked by CRS, a raised inbound threshold, trial with audit messages, and a refreshed source republished and applied |
| Real-image Compose run | Groups created through the API from a mounted `.srs` (4 prefixes) and a text list. Block 403, trial 200 with a would-block event, engine Off 200 on `/.env`, outside-group block 403; validate, load, readback and request stages succeeded; DHI Caddy read the UI-written 0640 lists; events carried the group messages. Editing a source and refreshing republished the site (journal action `ipgroup`) and lifted the block |
| Redaction in the real image | Local standard kept the SQL injection fragment and the query with `access_token=[redacted]`; the cloud queue copy was strict; the secret marker appeared in neither event file. `CADDY_UI_CLOUD_EXPORT=false` stopped queue writes, removed the migration marker and kept recording local events; the event page showed the configured 96-hour archive window |
| Matching cost | Coraza's `@ipMatchFromFile` checks every prefix: about 0.15 ms per request for 10,000 prefixes and 0.9 ms for 100,000 (worst case, Apple M1 Max) |
| Chinese documentation | All relative links and heading anchors in `documentation/zh/` resolve |

Not exercised: the real Grafana Cloud tenant (no credentials) and downloads from a real Internet URL; the HTTPS path is covered by local TLS servers. The disposable Compose project, its volumes and networks were removed.

## 2026-10-06 configurable privacy

Opus's committed baseline passed its race suite. Review found that the new level engine was not connected to runtime/persistence/export, and on-demand raw viewing exposed query credentials and unclassified fragments. Those paths now share the configured policy; a separate cloud queue prevents richer local data from being an Alloy input. Opus's dictionary lookup fix, unmatched-audit filtering, deployment ownership and Chinese guides were preserved.

Current validation:

- New regression tests cover all three levels, independent export, disk-full retry, imported-event exclusion, configuration rejection, name overrides, structured/escaped JSON and composite-fragment leakage, old full-event view filtering and bounded formatted/concatenated raw lookup.
- Complete race suite passed, including native Coraza mode/expiry/rotation/streaming tests. Vet/lint, format, Compose/YAML, shell and actual Alloy configuration checks passed.
- Actual existing Caddy image plus Alloy and a Loki protocol fixture proved: local full retained synthetic query/Auth/Cookie markers; cloud strict contained none; rule IDs and scores matched; cloud history remained viewable locally. Header testing explicitly used audit part B; full cannot invent uncollected headers. A second actual-runtime check verified standard credential masking, hide/keep overrides, cloud-full clamping to local-standard, and current strict views of older full records.
- Privacy changes preserve raw-source cursor retry when export fails. First-upgrade migration and export use durable node/transaction deduplication; imported history is never re-sent.
- Local UI/API responses use no-store. On-demand viewing does not bypass local strict and does not create an export.

The actual Grafana Cloud tenant was not exercised because no account credentials were present. Production services were not changed. The isolated project's resources were removed after validation. Previous runs are recorded below.

## 2026-10-06 review follow-up

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
