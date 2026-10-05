# Compatibility validation — 2026-10-05

Changes were tested locally against the existing `liukan/caddy-with-auth:latest` image. The backend was not rebuilt.

## Tested backend

- Local image ID: `3a4bf970ed0c`.
- Repository digest: `liukan/caddy-with-auth@sha256:ae47447d47ec0573210ef64a38c089758f452f23e0fed71b53cbbd3df9ba1c2c`.
- Caddy v2.11.6; coraza-caddy/v2 v2.6.1; Coraza v3.8.0; embedded CRS v4.25.0.
- Runtime UID 65532; shell-free DHI image.

## Results

| Check | Result |
| --- | --- |
| Complete Go suite with race detector | Passed, including opt-in real-Caddy request test |
| go vet / golangci-lint | Passed; lint reported zero issues |
| Compose validation / shell syntax / Git whitespace check | Passed |
| Final UI Docker image build | Passed |
| First boot from new isolated volumes | Passed; real DetectionOnly handler seeded before Caddy |
| UI API over shared Unix admin socket | Passed on the existing backend image |
| On / DetectionOnly requests and audit classification | Passed; probe rejected only under On |
| Exclusion update and rapid same-second rollback | Passed; changes immediately affected requests |
| External custom-file refresh at the same WAF mode | Passed in the native Caddy request test |
| Parameter-conditioned rule execution order | Passed in the native Caddy request test |
| Shared UID / file permissions | UI UID/GID 65532; WAF and audit files 0640; log directory 0750 |
| Admin socket boundary | Directory 0700, socket owner 65532; UI connected through a read-only mount; no TCP 2019 listener from the app network |
| UI certificate-volume exposure | No certificate-bearing /data mount in the UI; audit directory only, read-only |
| Session login and actual audit log page | Passed with synthetic test credentials and records |
| SSE on the existing backend image | First event arrived in about 4 ms, before the second event sent 600 ms later; both events intact |
| Multipart upload on the existing backend image | Passed; echoed file contents intact under On |
| WebSocket on the existing backend image | Upgrade 101 and frame forwarding passed under On |
| Callback-path forwarding | OAuth and MCP test paths returned 200 under On |
| Trusted visitor IP rejection | Simulated trusted proxy header: listed visitor rejected, unlisted visitor accepted |
| Large newline-less audit log tail | Regression passed; complete recent records recovered after the 2 MiB window cuts a JSON object |

The native request test used a temporary Caddy v2.11.4 binary with the same Coraza module versions. Docker checks used the actual v2.11.6 backend image listed above, an isolated Compose project, localhost high ports and disposable volumes. Proxy headers and callback routes were synthetic fixtures, not a live Cloudflare/OAuth/MCP integration. Actual LibreChat login/authentication, production traffic and production deployment were not exercised.

The isolated test containers/networks/volumes were removed after validation. Source changes, the reusable opt-in native request test and the local UI test image remain available. No existing production service or certificate volume was changed.
