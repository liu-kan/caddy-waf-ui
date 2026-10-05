# caddy-waf-ui

## Stack
- **Type**: Management binary (`cmd/server`) and Web UI sidecar for caddy-with-auth + Coraza WAF
- **Language**: Go 1.26.4 (toolchain 1.26.6), stdlib-only (zero external Go dependencies, no vendor)
- **Frontend / UI**: Server-rendered HTML via `embed.FS` (`internal/ui/templates`, `internal/ui/static/app.js`, `app.css`)
- **Orchestration / Runtime**: Docker Compose sidecar with Caddy, shared volume `/ui-managed`

## Commands
- **Run**: `go run ./cmd/server` or `docker compose up`
- **Test**: `make test` (`go test ./...`)
- **Test Race**: `make test-race` (`go test -race ./...`)
- **Integration**: `go test ./tests/integration/...`
- **Lint**: `make lint` (`lint-go`, `lint-yaml`, `lint-actions`, `lint-docker`, `lint-security`)
- **Format**: `make fmt` (`gofmt -l .`)
- **Vet**: `make vet` (`go vet ./...`)
- **Vuln**: `make vuln` (`govulncheck ./...`)
- **Build**: `make build` (`go build ./...`)
- **Docker**: `make docker-build` (`docker build -t caddy-waf-ui:local .`)
- **Validate Compose**: `make compose-config` (`docker compose config --quiet`)
- **Release Gate**: `make release-ready` (fmt vet lint vuln test-race compose-config build docker-build)

## SDD Context
- **CodeGraph indexed**: yes (`.codegraph/` present)
- **Testing framework**: Go stdlib `testing` + `net/http/httptest` (tests/integration)
- **Strict TDD**: enabled (`go test -race ./...` / `make test-race`)
- **Quality tools**: `golangci-lint` | `govulncheck` | `hadolint` | `actionlint` | `yamllint` | `zizmor`

## Security Posture & Architecture
- **License**: MIT - open source
- **Maintainer**: Miguel Lozano / Developmi
- **Architecture**: Sidecar writes configuration overlays (`coraza_waf`, IP rules) to `/ui-managed` and triggers reloads via Caddy Admin API (`:2019/load`)
- **Container Hardening**: Non-root user `uiuser` (UID 65532), read-only rootfs, drop capabilities ALL, no-new-privileges, pinned packages in Dockerfile (`openssl=3.5.9-r0`)
- **App Security**: Constant-time password comparison (`subtle.ConstantTimeCompare`), session token generation (`crypto/rand`), login/API sliding rate limiting, CSRF tokens, strict path sanitization against directory traversal

## CI/CD
- **Workflows**: GitHub Actions in `.github/workflows/` (`docker-build-scan-sign.yml`, `lint.yml`, `test.yml`)
- **Registry**: repository-derived GHCR path in GitHub Actions; Compose builds the UI locally
- **Triggers**: tags `v*` (releases) + PRs to `main`

## Conventions
- **Language & Tone**: 100% English for all identifiers, comments, error strings, UI copy, and test case names (aligned in v1.1.0)
- **Commit style**: Conventional Commits (`feat:`, `fix:`, `docs:`, `chore:`, `ci:`)
- **Error handling**: Return errors upstream, never swallow; structured logging with `log/slog`
- **Stdlib-only**: Zero third-party Go dependencies; preserve stdlib purity
- **Git authority**: The user (`migueldevops`) exclusively executes git/gh mutation commands (commits, pushes, tags, PR creation). Agents operate in read-only mode for git/gh.

## Key Gotchas
- Templates and static assets are embedded via `embed.FS` in `internal/ui/embed.go`
- Config overlays in `/ui-managed` must be atomically written and syntactically valid before notifying Caddy Admin API
- Rate limiter runs in-memory (`internal/ratelimit`)
- Dockerfile pins specific base alpine packages to mitigate upstream CVEs
