# Backend Image

The backend uses [liukan/caddy-with-auth](https://github.com/liu-kan/caddy-with-auth), running as-is without requiring custom rebuilding. All configurations required by the UI are provided via volume mounts. You only need to follow this guide if you are deploying "immutable container images", upgrading the compiled Coraza/CRS versions within the image, or adopting the [IP matching plugin (`coraza-ipset`)](#ip-matching-plugin-coraza-ipset).

## Image Requirements

| Requirement | Purpose | Verification Command |
| --- | --- | --- |
| Caddy module `http.handlers.waf` (`github.com/corazawaf/coraza-caddy/v2`) | Executes UI-generated `coraza_waf` overlays | `caddy list-modules \| grep http.handlers.waf` |
| Standard Admin API (`/load`, `/config/`) | Configuration publishing and revision readback | Enabled by default |
| `log_append` directive support | Example Caddyfile appends request URI to access logs; removable if access logging is unused | Verified via `caddy validate` |
| Non-root runtime: UID/GID 65532 | Shares permissions for overlays, audit directories, and Admin socket with the UI | Default in DHI runtime |
| Optional: `coraza-ipset` plugin | Binary search matching for IP group rules; performance does not degrade with large lists | `caddy build-info \| grep coraza-ipset` |

Verified version combination (`liukan/caddy-with-auth:latest`, image ID `3a4bf970ed0c`): Caddy 2.11.6, coraza-caddy/v2 2.6.1, Coraza 3.8.0, coraza-coreruleset 4.25.0 (CRS 4.25.0). Inspect the active image with:

```sh
make crs-version                      # Reads CADDY_IMAGE (defaults to liukan/caddy-with-auth:latest)
CADDY_IMAGE=caddy-with-auth:pinned make crs-version
```

This prints compiled versions of Caddy, coraza-caddy, Coraza, and coraza-coreruleset; it also reports `coraza-ipset` if present.

## Runtime Mounts

| Content | Mounted into Caddy | Description |
| --- | --- | --- |
| Caddyfile | `/etc/caddy/Caddyfile:ro` | `admin {$CADDY_ADMIN_LISTEN:unix//run/caddy-admin/admin.sock}`, per-site dual imports, optional access/error logging |
| Managed overlays | `/etc/caddy/ui-managed:ro` (Named volume) | Written by UI, read-only for Caddy |
| Custom rules | `/etc/caddy/waf-custom:ro` | `before.conf` (pre-CRS) and `after.conf` (post-CRS), managed by operators |
| Audit & access logs | `/data/logs` (Named volume) | Coraza audit log, optional `access.json` / `error.json` |
| Admin socket | `/run/caddy-admin` (Named volume, 0700) | Strictly accessible to Caddy and the UI |
| Environment variables | `CADDY_ADMIN_LISTEN=unix//run/caddy-admin/admin.sock` | Referenced in Caddyfile |

Because the DHI runtime contains no shell, Compose disables shell-based container healthchecks. Validate configuration syntax using the binary bundled inside the image:

```sh
docker compose run --rm --no-deps --entrypoint /usr/local/bin/caddy caddy \
  validate --config /etc/caddy/Caddyfile --adapter caddyfile
```

## Baking Configuration into Immutable Images

If your deployment platform restricts host volume mounts and requires baking Caddyfile and custom rules into immutable images, build a derived Dockerfile in your own repository without modifying caddy-with-auth upstream:

```dockerfile
FROM liukan/caddy-with-auth:latest
COPY --chown=65532:65532 --chmod=0640 Caddyfile /etc/caddy/Caddyfile
COPY --chown=65532:65532 --chmod=0640 waf-custom/ /etc/caddy/waf-custom/
```

Keep these three critical points in mind:

1. **The UI must read the identical Caddyfile.** When issuing reloads, the UI transmits the full text of its loaded Caddyfile to `/load`. If the file inside the container differs from the one mounted to the UI, the first publication from the UI will overwrite Caddy's active configuration with the UI's copy. Source both from the same file.
2. **Overlay directories must not be baked into the image.** `/etc/caddy/ui-managed` must remain a shared volume writable by the UI and readable by Caddy.
3. **Re-apply site policies after changing `waf-custom`.** Coraza only recompiles included custom rules when a new policy revision is published in the UI.

## IP Matching Plugin (coraza-ipset)

The `plugins/coraza-ipset` module in the caddy-with-auth repository is an optimized Coraza plugin. When compiled into Caddy, it overrides Coraza's built-in `@ipMatchFromFile` (and `@ipMatchF`) operator: IP lists are merged into sorted address ranges and matched using binary search.

- Existing IP group rules require no syntax changes; match outcomes match Coraza's original implementation byte-for-byte.
- Per-request evaluation latency is completely independent of list size.
- An identical list is parsed and stored only once per process.

For benchmarks, see [IP Groups](ip-groups.md#performance-and-list-size).

| Topic | Description |
| --- | --- |
| Published image | `liukan/caddy-with-auth:coraza-plugins-ipset`. See [Deployment with coraza-ipset Image](ipset-image-deployment.md). |
| Compilation | Built with xcaddy in caddy-with-auth: `--with github.com/liu-kan/caddy-with-auth/plugins/coraza-ipset=/build/plugins/coraza-ipset`. Unit tests cross-verify boundary conditions and fuzzy inputs against Coraza's reference implementation before compiling. |
| Verification | Check that `make crs-version` lists `coraza-ipset`. CI also validates build info and runtime requests via `tests/test_coraza_ipset.py`. |
| Rollback | Reverting to images without the plugin works seamlessly with identical overlays; matching reverts to linear evaluation without UI changes. |
| Upgrading Coraza | If upstream Coraza modifies `ipMatch` internals, plugin unit tests fail the build to avoid silent behavioral drift. |

## Upgrading Coraza or CRS

caddy-with-auth's Dockerfile defaults to `CORAZA_CADDY_VERSION=latest` and `CORAZA_VERSION=latest`. The bundled CRS version is determined by coraza-caddy dependencies (e.g., coraza-caddy 2.6.1 depends on coraza-coreruleset 4.25.0). Rebuilding may pull newer CRS versions with altered rule IDs, paranoia levels, or anomaly scores, causing the UI to flag a version mismatch.

To pin reproducible versions during image builds:

```sh
docker login dhi.io
docker build \
  --build-arg CADDY_VERSION=2.11.6 \
  --build-arg CORAZA_CADDY_VERSION=v2.6.1 \
  --build-arg CORAZA_VERSION=v3.8.0 \
  --target final -t caddy-with-auth:pinned .
```

When the CRS version in the image changes, regenerate the UI rule dictionary:

```sh
make crs-version                          # Read coraza-coreruleset version from new image
make crs-dict CRS_VERSION=4.26.0          # Regenerate internal/crs/data/crs-dictionary.json.gz
# Update expected version in internal/crs/dict_test.go, then:
go test ./internal/crs/ && docker compose build caddy-waf-ui
```

`make crs-dict` reads rule files directly from Go module cache and supplements metadata from upstream coreruleset repositories. The output is deterministic and bit-for-bit reproducible.

Alternatively, mount the new rules directory into the UI as read-only and set `CADDY_UI_CRS_RULES_DIR` to refresh explanations dynamically without rebuilding the UI.

## Post-Upgrade Checklist

1. Verify `http.handlers.waf` appears in `caddy list-modules`.
2. Run the example stack (see [Quick Start](quick-start.md)), trigger a match on `/.env`, and verify that the event's CRS version matches the header on the **Rules** tab.
3. Switch a site mode and verify `load`, `readback`, and `request` stages succeed in the change history.
4. Optional: Run integration tests against real Caddy binaries:

```sh
CADDY_TEST_BINARY=/absolute/path/to/caddy go test ./tests/integration -run TestRealCaddyWAFUpdatesAndStreaming -v
```
