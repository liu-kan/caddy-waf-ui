#!/bin/sh
# Compatibility wrapper: the Go initializer validates sites, seeds real WAF
# configurations, verifies imports, and preserves existing operator settings.
set -eu
exec /app/caddy-waf-ui init "$@"
