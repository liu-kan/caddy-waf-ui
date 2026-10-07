# Makefile - development workflow for caddy-waf-ui.
# Every quality target is a verifier: it fails on findings instead of fixing.
# Follow the pattern of the sibling repo (caddy-waf): tool pins live in
# tools/versions.mk and binaries are installed by tools/install.sh into tools/bin.

include tools/versions.mk

TOOLS := tools/bin
UV := uv run
# golangci-lint type-checks with the Go release it was built for, so lint
# runs on the go.mod toolchain even when a newer Go is installed (Go fetches
# it on first use, as in CI).
GO_TOOLCHAIN := $(shell sed -n 's/^toolchain //p' go.mod)

.DEFAULT_GOAL := help

.PHONY: help
help:
	@echo ""
	@echo "Development Commands"
	@echo "===================="
	@echo ""
	@echo "Setup"
	@echo "-----"
	@echo "  make tools            Install development tools"
	@echo "  make reinstall        Reinstall development tools"
	@echo "  make doctor           Verify development environment"
	@echo ""
	@echo "Testing & Quality (Unified)"
	@echo "---------------------------"
	@echo "  make test             Run full verification: format, vet, all linters, race tests"
	@echo ""
	@echo "Granular Testing"
	@echo "----------------"
	@echo "  make test-unit        Run unit tests (fast)"
	@echo "  make test-race        Run unit tests with race detector"
	@echo "  make test-coverage    Run tests and output statement coverage"
	@echo "  make test-integration Run integration tests with race detector"
	@echo "  make test-pkg PKG=... Run tests for a specific package (e.g. PKG=internal/logs)"
	@echo ""
	@echo "Granular Quality & Linters"
	@echo "--------------------------"
	@echo "  make fmt              Check Go formatting (gofmt -l)"
	@echo "  make fmt-fix          Format Go code in-place (gofmt -w)"
	@echo "  make vet              Run go vet"
	@echo "  make lint             Run all linters (Go, YAML, Actions, Docker, Security)"
	@echo "  make lint-go          Run golangci-lint"
	@echo "  make lint-yaml        Lint YAML files"
	@echo "  make lint-actions     Lint GitHub Actions workflows"
	@echo "  make lint-docker      Lint Dockerfile"
	@echo "  make lint-security    Scan GitHub Actions for security issues (zizmor)"
	@echo "  make vuln             Check for known vulnerabilities (govulncheck)"
	@echo ""
	@echo "Build & Runtime"
	@echo "---------------"
	@echo "  make build            Compile all packages"
	@echo "  make docker-build     Build the Docker image"
	@echo "  make compose-config   Validate the docker-compose configuration"
	@echo "  make crs-version      Print the Caddy, Coraza, CRS and coraza-ipset versions compiled into CADDY_IMAGE"
	@echo "  make crs-dict         Regenerate the embedded rule dictionary (CRS_VERSION=...)"
	@echo "  make clean            Remove test and build artifacts"
	@echo ""
	@echo "Release"
	@echo "-------"
	@echo "  make release-ready    Run full pre-push gate: test, vuln, compose, build, docker"
	@echo ""

.PHONY: tools
tools:                                   # Install pinned development tools into tools/bin
	@ACTIONLINT_VERSION=$(ACTIONLINT_VERSION) \
	HADOLINT_VERSION=$(HADOLINT_VERSION) \
	GOLANGCI_VERSION=$(GOLANGCI_VERSION) \
	./tools/install.sh
	@echo "✓ Development tools are ready."

.PHONY: reinstall
reinstall:                               # Force reinstall of all development tools
	@REINSTALL=1 $(MAKE) tools
	@echo "✓ Development tools reinstalled."

.PHONY: doctor
doctor:                                  # Print toolchain and tool versions
	@test -x $(TOOLS)/actionlint || $(MAKE) --no-print-directory tools
	@printf "\n"
	@printf "Development Environment\n"
	@printf "=======================\n\n"
	@printf "%-18s %s\n" "go" "$$(go version | awk '{print $$3}')"
	@printf "%-18s %s\n" "uv" "$$(uv --version | awk '{print $$2}')"
	@printf "%-18s %s\n" "Docker" "$$(docker version --format '{{.Client.Version}}')"
	@printf "%-18s %s\n" "golangci-lint" "$$($(TOOLS)/golangci-lint version | awk '{print $$4}')"
	@printf "%-18s %s\n" "hadolint" "$$($(TOOLS)/hadolint --version | awk '{print $$NF}')"
	@printf "%-18s %s\n" "actionlint" "$$($(TOOLS)/actionlint -version | head -1)"
	@printf "%-18s %s\n" "govulncheck" "$$($(TOOLS)/govulncheck -version 2>/dev/null | head -1)"
	@printf "%-18s %s\n" "yamllint" "$$(uv run yamllint --version | awk '{print $$2}')"
	@printf "%-18s %s\n" "zizmor" "$$(uv run zizmor --version | awk '{print $$2}')"
	@echo

.PHONY: fmt
fmt:                                     # Check Go formatting; lists unformatted files and exits 1 (fix with gofmt -w)
	@echo "==> Go format"
	@unformatted="$$(gofmt -l .)"; \
	if [ -n "$$unformatted" ]; then \
		echo "gofmt: the following files are not formatted:"; \
		echo "$$unformatted"; \
		exit 1; \
	fi
	@echo "✓ Go formatting passed."

.PHONY: fmt-fix
fmt-fix:                                 # Format all Go files in-place
	@echo "==> Formatting Go files"
	@gofmt -w .
	@echo "✓ Go formatting applied."

.PHONY: vet
vet:                                     # Run go vet static analysis
	@echo "==> Go vet"
	@go vet ./...
	@echo "✓ go vet passed."

.PHONY: lint-go
lint-go:                                 # Run golangci-lint on all Go packages
	@echo "==> Go"
	@GOTOOLCHAIN=$(GO_TOOLCHAIN) $(TOOLS)/golangci-lint run ./...
	@echo "✓ Go lint passed."

.PHONY: lint-yaml
lint-yaml:                               # Lint all YAML files
	@echo "==> YAML"
	@$(UV) yamllint .
	@echo "✓ YAML lint passed."

.PHONY: lint-actions
lint-actions:                            # Lint GitHub Actions workflows (no-op until .github/workflows exists)
	@echo "==> GitHub Actions"
	@if [ -d .github/workflows ]; then \
		$(TOOLS)/actionlint; \
	else \
		echo "No .github/workflows directory yet; skipping actionlint."; \
	fi
	@echo "✓ GitHub Actions lint passed."

.PHONY: lint-docker
lint-docker:                             # Lint the Dockerfile
	@echo "==> Docker"
	@$(TOOLS)/hadolint --failure-threshold warning Dockerfile
	@echo "✓ Docker lint passed."

.PHONY: lint-security
lint-security:                           # Scan GitHub Actions for security issues (no-op until .github/workflows exists)
	@echo "==> Security"
	@if [ -d .github/workflows ]; then \
		$(UV) zizmor .; \
	else \
		echo "No .github/workflows directory yet; skipping zizmor."; \
	fi
	@echo "✓ Security lint passed."

.PHONY: lint
lint: lint-go lint-yaml lint-actions lint-docker lint-security   # Run all linters
	@echo
	@echo "✓ All lint checks passed."

.PHONY: test-unit
test-unit:                               # Run unit tests (fast)
	@echo "==> Tests (unit)"
	@go test ./...
	@echo "✓ Unit tests passed."

.PHONY: test-race
test-race:                               # Run unit tests with the race detector
	@echo "==> Tests (race)"
	@go test -race ./...
	@echo "✓ Race tests passed."

.PHONY: test-coverage
test-coverage:                           # Run tests with race and statement coverage report
	@echo "==> Tests (coverage)"
	@go test -race -coverprofile=coverage.out ./...
	@go tool cover -func=coverage.out
	@echo "✓ Coverage report generated."

.PHONY: test-integration
test-integration:                        # Run integration tests with race detector
	@echo "==> Tests (integration)"
	@go test -race ./tests/integration/...
	@echo "✓ Integration tests passed."

.PHONY: test-pkg
test-pkg:                                # Run tests for a specific package: make test-pkg PKG=internal/logs
	@if [ -z "$(PKG)" ]; then \
		echo "Usage: make test-pkg PKG=<package-path>"; \
		exit 1; \
	fi
	@echo "==> Tests (pkg: $(PKG))"
	@go test -race -cover ./$(PKG)/...
	@echo "✓ Package tests passed."

.PHONY: test
test: fmt vet lint test-race             # Run full test & quality suite (fmt, vet, all linters, race tests)
	@echo
	@echo "✓ All tests and quality checks passed."

.PHONY: vuln
vuln:                                    # Check dependencies for known vulnerabilities
	@echo "==> Vulnerabilities"
	@$(TOOLS)/govulncheck ./...
	@echo "✓ Vulnerability scan passed."

.PHONY: build
build:                                   # Compile all packages
	@echo "==> Build"
	@go build ./...
	@echo "✓ Build passed."

.PHONY: docker-build
docker-build:                            # Build the local Docker image
	@echo "==> Docker build"
	@docker build -t caddy-waf-ui:local .
	@echo "✓ Docker build passed."

# CRS version compiled into the backend image (coraza-coreruleset module).
# Regenerate the embedded rule dictionary whenever the backend changes it:
#   make crs-version && make crs-dict CRS_VERSION=4.26.0
# Then update the expected version in internal/crs/dict_test.go.
CRS_VERSION ?= 4.25.0

.PHONY: crs-version
crs-version:                             # Print the Caddy, Coraza, coraza-coreruleset and coraza-ipset versions inside CADDY_IMAGE
	@docker run --rm --entrypoint /usr/local/bin/caddy $${CADDY_IMAGE:-liukan/caddy-with-auth:latest} build-info | grep -E 'caddyserver/caddy/v2[[:space:]]|coraza-coreruleset|coraza/v3|coraza-caddy|coraza-ipset'

.PHONY: crs-dict
crs-dict:                                # Regenerate internal/crs/data/crs-dictionary.json.gz for CRS_VERSION
	@set -eu; tmp=$$(mktemp -d); trap 'rm -rf "$$tmp"' EXIT; \
	rules=$$(cd "$$tmp" && go mod download -json github.com/corazawaf/coraza-coreruleset/v4@v$(CRS_VERSION) | sed -n 's/.*"Dir": "\(.*\)".*/\1/p'); \
	git clone --quiet --depth 1 --branch v$(CRS_VERSION) https://github.com/coreruleset/coreruleset "$$tmp/crs"; \
	go run ./cmd/crsdict \
	  -rules "$$rules/rules" -source github.com/corazawaf/coraza-coreruleset/v4@v$(CRS_VERSION) \
	  -url https://github.com/corazawaf/coraza-coreruleset/blob/v$(CRS_VERSION)/rules/ \
	  -docs "$$tmp/crs" -docs-source github.com/coreruleset/coreruleset@v$(CRS_VERSION) \
	  -docs-url https://github.com/coreruleset/coreruleset/blob/v$(CRS_VERSION)/

.PHONY: compose-config
compose-config:                          # Validate the docker-compose configuration
	@echo "==> Compose config"
	@CADDY_UI_TOKEN=$${CADDY_UI_TOKEN:-compose-validation-only} docker compose config --quiet
	@echo "✓ Compose config passed."

.PHONY: clean
clean:                                   # Remove temporary test and coverage artifacts
	@rm -f coverage.out cover.out
	@echo "✓ Cleaned temporary artifacts."

.PHONY: release-ready
release-ready: test vuln compose-config build docker-build   # Run the full pre-push gate
	@echo
	@echo "✓ Release-ready gate passed."
