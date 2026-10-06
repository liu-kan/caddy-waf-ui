#!/bin/sh
# Run only in the one-shot initialization container, with CHOWN/FOWNER.
set -eu

for dir in /data /config /data/logs /ui-managed /backups /ui-data /alloy-data; do
  mkdir -p "$dir"
  chown 65532:65532 "$dir"
  chmod 0750 "$dir"
done

mkdir -p /run/caddy-admin
chown 65532:65532 /run/caddy-admin
chmod 0700 /run/caddy-admin

# Migrate only UI-owned overlays/backups from the original UID 1000.
# Certificate contents and existing application/access logs are untouched.
find /ui-managed /backups /ui-data /alloy-data -type d -exec chown 65532:65532 {} + -exec chmod 0750 {} +
find /ui-managed /backups /ui-data /alloy-data -type f -exec chown 65532:65532 {} + -exec chmod 0640 {} +
