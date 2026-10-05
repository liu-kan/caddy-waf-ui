# Stage 1: Build (builder)
# Exact builder toolchain pin; it satisfies the minimum in go.mod.
FROM golang:1.27.1-alpine AS builder

# Enable Go modules and configure the working directory
ENV GO111MODULE=on
WORKDIR /app

# Copy the module file
COPY go.mod ./
# If you add dependencies later and a go.sum is generated, uncomment the next line:
# COPY go.sum ./
RUN go mod download

# Copy the rest of the source code
COPY . .

# Build the static binary
# CGO_ENABLED=0 ensures the binary does not depend on dynamic C libraries
# -ldflags="-w -s" reduces the binary size by stripping debug information
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o caddy-waf-ui ./cmd/server/

# Stage 2: Final image (runtime)
# Alpine 3.23.5: same line as the caddy:2.11.4 base (caddy-waf v3.5.5 image).
# NEVER use :latest - immutable pin, aligned with the ecosystem.
FROM alpine:3.23.5

# Static OCI metadata (supply chain: trace the artifact origin and license)
LABEL org.opencontainers.image.title="caddy-waf-ui"
LABEL org.opencontainers.image.description="Sidecar management UI for Caddy with Coraza: WAF mode, exclusions, client IP rules, logs, and rollback"
LABEL org.opencontainers.image.source="https://github.com/liu-kan/caddy-waf-ui"
LABEL org.opencontainers.image.licenses="MIT"

# Install root certificates and timezone data (useful for logs and Cloudflare API calls),
# create the UI non-root user and the managed directories with user ownership:
# named volumes inherit the directory ownership on first mount, avoiding permission
# errors (EACCES) in ui-managed/ and backups/. Pinned package versions (DL3018).
#
# Pin versions currently available in Alpine v3.23/main. OpenSSL 3.5.9
# supersedes the removed 3.5.8 package pin; refresh pins with repository updates.
RUN apk --no-cache add ca-certificates=20260909-r0 openssl=3.5.9-r0 tzdata=2026d-r0 \
    && addgroup -g 65532 -S uiuser \
    && adduser -u 65532 -S -D -G uiuser -g '' uiuser \
    && mkdir -p /ui-managed /backups /data/logs /config /run/caddy-admin \
    && chown -R uiuser:uiuser /ui-managed /backups /data /config /run/caddy-admin

USER uiuser

WORKDIR /app

# Copy the compiled binary from the previous stage
COPY --from=builder --chown=uiuser:uiuser /app/caddy-waf-ui .

# Expose the default UI port
EXPOSE 8080

# Healthcheck: GET /health is public (no auth) - busybox wget ships in alpine.
# wget returns exit != 0 when it cannot connect, which marks the container unhealthy.
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD ["wget", "-qO-", "http://127.0.0.1:8080/health"]

# Entry point
CMD ["./caddy-waf-ui"]
