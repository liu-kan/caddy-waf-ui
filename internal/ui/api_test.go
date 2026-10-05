package ui

import (
	"bytes"
	"encoding/json"
	"github.com/developmi/caddy-waf-ui/internal/waf"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// liveServers mirrors Caddy's GET /config/apps/http/servers for the fixture
// host. Caddy keeps coraza_waf directives verbatim, so the revision comment
// of every managed WAF overlay appears in the live config.
func liveServers() []byte {
	var directives []string
	paths, _ := filepath.Glob(filepath.Join(os.Getenv("CADDY_UI_MANAGED_DIR"), "waf-*.conf"))
	for _, p := range paths {
		if content, err := os.ReadFile(p); err == nil {
			if rev := waf.Revision(content); rev != "" {
				directives = append(directives, "# waf-config-revision: "+rev)
			}
		}
	}
	handle, _ := json.Marshal([]map[string]string{{"handler": "waf", "directives": strings.Join(directives, "\n")}})
	return []byte(`{"srv0":{"routes":[{"match":[{"host":["example.com"]}],"handle":` + string(handle) + `}]}}`)
}

// adminStubUI simulates the Caddy Admin API (:2019) so the service chain
// completes the reload in the REST handler tests (package ui).
type adminStubUI struct {
	reloads int
}

func (s *adminStubUI) handler(t *testing.T) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Read-back (D3): after every POST /load the UI verifies the live
		// config via GET /config/apps/http/servers. The stub mirrors that
		// contract: it serves the fixture host (example.com).
		if r.Method == http.MethodGet && r.URL.Path == "/config/apps/http/servers" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(liveServers())
			return
		}
		if r.Method != http.MethodPost || r.URL.Path != "/load" {
			t.Errorf("the stub expected POST /load, received %s %s", r.Method, r.URL.Path)
		}
		s.reloads++
		w.WriteHeader(http.StatusOK)
	})
}

// setupUIEnv prepares the files/env environment for the REST handlers of the
// ui package (same D2 convention as the integration tests) and returns the
// mounted router. Without auth: the handlers are exercised directly.
func setupUIEnv(t *testing.T) *http.ServeMux {
	t.Helper()
	tmp := t.TempDir()
	managedDir := filepath.Join(tmp, "ui-managed")
	backupDir := filepath.Join(tmp, "backups")
	if err := os.MkdirAll(managedDir, 0750); err != nil {
		t.Fatalf("failed creating managedDir: %v", err)
	}
	t.Setenv("CADDY_UI_MANAGED_DIR", managedDir)
	t.Setenv("CADDY_UI_DATA_DIR", filepath.Join(tmp, "data"))
	t.Setenv("CADDY_UI_BACKUP_DIR", backupDir)

	caddyfile := filepath.Join(tmp, "Caddyfile")
	if err := os.WriteFile(caddyfile, []byte("example.com {\n}\n"), 0600); err != nil {
		t.Fatalf("failed to write test Caddyfile: %v", err)
	}
	t.Setenv("CADDY_UI_CADDYFILE", caddyfile)

	server := httptest.NewServer((&adminStubUI{}).handler(t))
	t.Cleanup(server.Close)
	t.Setenv("CADDY_ADMIN_URL", server.URL)

	return NewRouter()
}

// seedUISnapshot seeds a snapshot in the backups dir of the slug.
func seedUISnapshot(t *testing.T, slug, name, content string) {
	t.Helper()
	slugDir := filepath.Join(os.Getenv("CADDY_UI_BACKUP_DIR"), slug)
	if err := os.MkdirAll(slugDir, 0750); err != nil {
		t.Fatalf("failed creating backups dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(slugDir, name), []byte(content), 0640); err != nil {
		t.Fatalf("failed seeding snapshot %s: %v", name, err)
	}
}

func apiRequest(t *testing.T, method, path, body string) *http.Request {
	req, err := http.NewRequest(method, path, bytes.NewBufferString(body))
	if err != nil {
		t.Fatalf("failed creating request: %v", err)
	}
	return req
}

// TestAPISetModeMalformedJSONReturns400: a body that is not valid JSON is
// rejected with 400 (W2, decode branch of HandleSetMode).
func TestAPISetModeMalformedJSONReturns400(t *testing.T) {
	handler := setupUIEnv(t)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, apiRequest(t, http.MethodPut, "/api/sites/example.com/mode", `{`))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 with a malformed payload, got %d", rec.Code)
	}
}

// TestAPISetModeOversizedBodyReturns413: a body over the 1 MiB limit
// (MaxBytesReader) is rejected with 413, not with a generic 400 (finding J1,
// defense against memory DoS).
func TestAPISetModeOversizedBodyReturns413(t *testing.T) {
	handler := setupUIEnv(t)

	body := `{"mode":"On","pad":"` + strings.Repeat("a", 1<<20) + `"}`
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, apiRequest(t, http.MethodPut, "/api/sites/example.com/mode", body))

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413 with a body > 1MiB, got %d", rec.Code)
	}
}

// TestAPISetModeInvalidModeReturns400: an invalid mode is translated to 400
// (REST contract ErrInvalidMode).
func TestAPISetModeInvalidModeReturns400(t *testing.T) {
	handler := setupUIEnv(t)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, apiRequest(t, http.MethodPut, "/api/sites/example.com/mode", `{"mode":"BlockAll"}`))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 with an invalid mode, got %d", rec.Code)
	}
}

// TestAPISetModeInvalidDomainReturns400: a domain that does not pass the
// strict validation is translated to 400 via service.ErrInvalidDomain
// (handoff F2, same pattern as ErrInvalidMode) - it is a client error, not a
// server one.
func TestAPISetModeInvalidDomainReturns400(t *testing.T) {
	handler := setupUIEnv(t)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, apiRequest(t, http.MethodPut, "/api/sites/bad%20domain/mode", `{"mode":"On"}`))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 with an invalid domain, got %d", rec.Code)
	}
}

// TestAPISetModeServiceErrorReturns500: a service error that is NOT a
// validation one is translated to 500 (W2, generic error branch).
func TestAPISetModeServiceErrorReturns500(t *testing.T) {
	handler := setupUIEnv(t)
	// managedDir points at a file: the previous-state read fails with ENOTDIR.
	file := filepath.Join(t.TempDir(), "managed-es-un-archivo")
	if err := os.WriteFile(file, []byte("x"), 0640); err != nil {
		t.Fatalf("failed seeding file: %v", err)
	}
	t.Setenv("CADDY_UI_MANAGED_DIR", file)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, apiRequest(t, http.MethodPut, "/api/sites/example.com/mode", `{"mode":"On"}`))

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 with a service error, got %d", rec.Code)
	}
}

// TestAPISetModeSuccess: a valid PUT regenerates the overlay and responds
// with the confirmation contract.
func TestAPISetModeSuccess(t *testing.T) {
	handler := setupUIEnv(t)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, apiRequest(t, http.MethodPut, "/api/sites/example.com/mode", `{"mode":"On"}`))

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (%s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"status":"success"`) {
		t.Errorf("the body does not confirm the success: %s", rec.Body.String())
	}
	overlay, err := os.ReadFile(filepath.Join(os.Getenv("CADDY_UI_MANAGED_DIR"), "waf-example_com.conf"))
	if err != nil {
		t.Fatalf("the overlay was not generated: %v", err)
	}
	if !strings.Contains(string(overlay), "SecRuleEngine On") {
		t.Errorf("the overlay does not contain the sent mode:\n%s", overlay)
	}
}

// TestAPISetExclusionsMalformedJSONReturns400: decode branch of
// HandleSetExclusions (W2).
func TestAPISetExclusionsMalformedJSONReturns400(t *testing.T) {
	handler := setupUIEnv(t)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, apiRequest(t, http.MethodPut, "/api/sites/example.com/exclusions", `{"exclusions":[`))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 with a malformed payload, got %d", rec.Code)
	}
}

// TestAPISetExclusionsValidationErrorReturns400: an exclusion that does not
// pass the validation is an invalid client payload → 400, not a server
// failure (SUGGESTION #4 of the verify: validation before the chain, like
// HandleSetMode).
func TestAPISetExclusionsValidationErrorReturns400(t *testing.T) {
	handler := setupUIEnv(t)

	body := `{"exclusions":[{"type":"id","value":"941100","param":"q\nSecRuleEngine Off"}]}`
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, apiRequest(t, http.MethodPut, "/api/sites/example.com/exclusions", body))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 with an invalid exclusion, got %d", rec.Code)
	}
}

// TestAPISetExclusionsUnknownTypeReturns400 (triangulation): an unknown
// exclusion type is also rejected with 400 before touching the chain.
func TestAPISetExclusionsUnknownTypeReturns400(t *testing.T) {
	handler := setupUIEnv(t)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, apiRequest(t, http.MethodPut, "/api/sites/example.com/exclusions", `{"exclusions":[{"type":"bogus","value":"1"}]}`))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 with an unknown exclusion type, got %d", rec.Code)
	}
}

// TestAPISetExclusionsInvalidDomainReturns400: an invalid domain is 400 via
// service.ErrInvalidDomain (handoff F2) even with a valid exclusions
// payload.
func TestAPISetExclusionsInvalidDomainReturns400(t *testing.T) {
	handler := setupUIEnv(t)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, apiRequest(t, http.MethodPut, "/api/sites/bad%20domain/exclusions", `{"exclusions":[{"type":"id","value":"941100"}]}`))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 with an invalid domain, got %d", rec.Code)
	}
}

// TestAPISetExclusionsServiceErrorReturns500: with a VALID payload, a real
// chain error (managedDir is a file → ENOTDIR when reading the previous
// state) still returns 500 - only the payload validation is 400.
func TestAPISetExclusionsServiceErrorReturns500(t *testing.T) {
	handler := setupUIEnv(t)
	file := filepath.Join(t.TempDir(), "managed-es-un-archivo")
	if err := os.WriteFile(file, []byte("x"), 0640); err != nil {
		t.Fatalf("failed seeding file: %v", err)
	}
	t.Setenv("CADDY_UI_MANAGED_DIR", file)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, apiRequest(t, http.MethodPut, "/api/sites/example.com/exclusions", `{"exclusions":[{"type":"id","value":"941100"}]}`))

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 with a service error, got %d", rec.Code)
	}
}

// TestAPISetExclusionsSuccess: a valid PUT of exclusions → 200.
func TestAPISetExclusionsSuccess(t *testing.T) {
	handler := setupUIEnv(t)

	body := `{"exclusions":[{"type":"id","value":"941100","param":"q"}]}`
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, apiRequest(t, http.MethodPut, "/api/sites/example.com/exclusions", body))

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (%s)", rec.Code, rec.Body.String())
	}
	overlay, err := os.ReadFile(filepath.Join(os.Getenv("CADDY_UI_MANAGED_DIR"), "exclusions-example_com.conf"))
	if err != nil {
		t.Fatalf("the exclusions overlay was not generated: %v", err)
	}
	if !strings.Contains(string(overlay), "ARGS:q") {
		t.Errorf("the overlay does not contain the targeted exclusion:\n%s", overlay)
	}
}

// TestAPISetIPRulesMalformedJSONReturns400: decode branch of
// HandleSetIPRules (W2).
func TestAPISetIPRulesMalformedJSONReturns400(t *testing.T) {
	handler := setupUIEnv(t)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, apiRequest(t, http.MethodPut, "/api/sites/example.com/iprules", `{"denylist":`))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 with a malformed payload, got %d", rec.Code)
	}
}

// TestAPISetIPRulesValidationErrorReturns400: an invalid IP entry is an
// invalid client payload → 400, not a server failure (SUGGESTION #4).
func TestAPISetIPRulesValidationErrorReturns400(t *testing.T) {
	handler := setupUIEnv(t)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, apiRequest(t, http.MethodPut, "/api/sites/example.com/iprules", `{"denylist":["not-an-ip"]}`))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 with an invalid IP entry, got %d", rec.Code)
	}
}

// TestAPISetIPRulesAllowlistInvalidReturns400 (triangulation): the
// validation also covers the allowlist, not only the denylist.
func TestAPISetIPRulesAllowlistInvalidReturns400(t *testing.T) {
	handler := setupUIEnv(t)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, apiRequest(t, http.MethodPut, "/api/sites/example.com/iprules", `{"allowlist":["300.300.300.300"]}`))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 with an invalid allowlist entry, got %d", rec.Code)
	}
}

// TestAPISetIPRulesInvalidDomainReturns400: an invalid domain is 400 via
// service.ErrInvalidDomain (handoff F2) even with a valid IP payload.
func TestAPISetIPRulesInvalidDomainReturns400(t *testing.T) {
	handler := setupUIEnv(t)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, apiRequest(t, http.MethodPut, "/api/sites/bad%20domain/iprules", `{"denylist":["192.0.2.5"]}`))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 with an invalid domain, got %d", rec.Code)
	}
}

// TestAPISetIPRulesServiceErrorReturns500: with a VALID payload, a real
// chain error (managedDir is a file → ENOTDIR) still returns 500 - only the
// payload validation is 400.
func TestAPISetIPRulesServiceErrorReturns500(t *testing.T) {
	handler := setupUIEnv(t)
	file := filepath.Join(t.TempDir(), "managed-es-un-archivo")
	if err := os.WriteFile(file, []byte("x"), 0640); err != nil {
		t.Fatalf("failed seeding file: %v", err)
	}
	t.Setenv("CADDY_UI_MANAGED_DIR", file)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, apiRequest(t, http.MethodPut, "/api/sites/example.com/iprules", `{"denylist":["192.0.2.5"]}`))

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 with a service error, got %d", rec.Code)
	}
}

// TestAPISetIPRulesSuccess: a valid PUT of IP rules → 200.
func TestAPISetIPRulesSuccess(t *testing.T) {
	handler := setupUIEnv(t)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, apiRequest(t, http.MethodPut, "/api/sites/example.com/iprules", `{"denylist":["192.0.2.5"]}`))

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (%s)", rec.Code, rec.Body.String())
	}
	overlay, err := os.ReadFile(filepath.Join(os.Getenv("CADDY_UI_MANAGED_DIR"), "ip-rules-example_com.conf"))
	if err != nil {
		t.Fatalf("the ip-rules overlay was not generated: %v", err)
	}
	if !strings.Contains(string(overlay), "192.0.2.5/32") {
		t.Errorf("the overlay does not contain the normalized IP:\n%s", overlay)
	}
}

// TestAPIListBackupsCorruptDirReturns500: a corrupt backup dir (file instead
// of directory) produces 500 - never an invented JSON (W2).
func TestAPIListBackupsCorruptDirReturns500(t *testing.T) {
	handler := setupUIEnv(t)
	file := filepath.Join(t.TempDir(), "backup-es-un-archivo")
	if err := os.WriteFile(file, []byte("x"), 0640); err != nil {
		t.Fatalf("failed seeding file: %v", err)
	}
	t.Setenv("CADDY_UI_BACKUP_DIR", file)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, apiRequest(t, http.MethodGet, "/api/sites/example.com/backups", ""))

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 with a corrupt backup dir, got %d", rec.Code)
	}
}

// TestAPIListBackupsEmptyReturns200: without backups it responds 200 with []
// (honest empty state).
func TestAPIListBackupsEmptyReturns200(t *testing.T) {
	handler := setupUIEnv(t)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, apiRequest(t, http.MethodGet, "/api/sites/example.com/backups", ""))

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 without backups, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "[]") {
		t.Errorf("without backups the body must be an empty array: %s", rec.Body.String())
	}
}

// TestAPIListBackupsSuccess (triangulation): with snapshots the listing
// includes them in the JSON.
func TestAPIListBackupsSuccess(t *testing.T) {
	handler := setupUIEnv(t)
	seedUISnapshot(t, "example_com", "2020-01-01T00-00-00Z.waf.conf", "waf-2020")

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, apiRequest(t, http.MethodGet, "/api/sites/example.com/backups", ""))

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "2020-01-01T00-00-00Z") || !strings.Contains(rec.Body.String(), "waf") {
		t.Errorf("the listing must include the snapshots: %s", rec.Body.String())
	}
}

// TestAPIRollbackMalformedJSONReturns400: decode branch of HandleRollback
// (W2).
func TestAPIRollbackMalformedJSONReturns400(t *testing.T) {
	handler := setupUIEnv(t)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, apiRequest(t, http.MethodPost, "/api/sites/example.com/rollback", `{"backup":`))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 with a malformed payload, got %d", rec.Code)
	}
}

// TestAPIRollbackMissingBackupReturns400: a nonexistent backup (but with a
// valid canonical name) is translated to 400 via ErrInvalidBackup (W2).
func TestAPIRollbackMissingBackupReturns400(t *testing.T) {
	handler := setupUIEnv(t)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, apiRequest(t, http.MethodPost, "/api/sites/example.com/rollback", `{"backup":"2099-01-01T00-00-00Z.waf.conf"}`))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 with a nonexistent backup, got %d", rec.Code)
	}
}

// TestAPIRollbackInvalidDomainReturns400: an invalid domain is 400 via
// service.ErrInvalidDomain (handoff F2) before touching the chain.
func TestAPIRollbackInvalidDomainReturns400(t *testing.T) {
	handler := setupUIEnv(t)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, apiRequest(t, http.MethodPost, "/api/sites/bad%20domain/rollback", `{"backup":"2020-01-01T00-00-00Z.waf.conf"}`))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 with an invalid domain, got %d", rec.Code)
	}
}

// TestAPIRollbackServiceErrorReturns500: a service error other than
// ErrInvalidBackup is translated to 500 (W2, generic error branch).
func TestAPIRollbackServiceErrorReturns500(t *testing.T) {
	handler := setupUIEnv(t)
	file := filepath.Join(t.TempDir(), "backup-es-un-archivo")
	if err := os.WriteFile(file, []byte("x"), 0640); err != nil {
		t.Fatalf("failed seeding file: %v", err)
	}
	t.Setenv("CADDY_UI_BACKUP_DIR", file)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, apiRequest(t, http.MethodPost, "/api/sites/example.com/rollback", `{"backup":"2099-01-01T00-00-00Z.waf.conf"}`))

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 with a service error, got %d", rec.Code)
	}
}

// TestAPIRollbackSuccess: a valid rollback restores the overlay and responds
// 200.
func TestAPIRollbackSuccess(t *testing.T) {
	handler := setupUIEnv(t)

	overlayPath := filepath.Join(os.Getenv("CADDY_UI_MANAGED_DIR"), "waf-example_com.conf")
	if err := os.WriteFile(overlayPath, []byte("current state"), 0640); err != nil {
		t.Fatalf("failed seeding overlay: %v", err)
	}
	seedUISnapshot(t, "example_com", "2020-01-01T00-00-00Z.waf.conf", "# Caddy WAF UI managed - do not edit manually\n# domain: example.com | mode: Off | updated: 2020-01-01T00:00:00Z\n")

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, apiRequest(t, http.MethodPost, "/api/sites/example.com/rollback", `{"backup":"2020-01-01T00-00-00Z.waf.conf"}`))

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (%s)", rec.Code, rec.Body.String())
	}
	overlay, err := os.ReadFile(overlayPath)
	if err != nil {
		t.Fatalf("the overlay was not restored: %v", err)
	}
	if !strings.Contains(string(overlay), "SecRuleEngine Off") || !strings.Contains(string(overlay), "coraza_waf {") {
		t.Errorf("the overlay must restore the snapshot's mode in a regenerated overlay: %q", overlay)
	}
}

// TestAPIHealthReturnsOK: HealthHandler responds 200 with the readiness
// contract. /health is NOT a route of the API mux (main.go mounts it apart,
// outside the auth): the handler is exercised directly.
func TestAPIHealthReturnsOK(t *testing.T) {
	rec := httptest.NewRecorder()
	HealthHandler().ServeHTTP(rec, apiRequest(t, http.MethodGet, "/health", ""))

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `"status":"ok"`) {
		t.Errorf("the body of /health is not the expected one: %s", rec.Body.String())
	}
}
