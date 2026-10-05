package integration_test

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

	"github.com/developmi/caddy-waf-ui/internal/auth"
	"github.com/developmi/caddy-waf-ui/internal/ui"
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

// adminStub simulates the Caddy Admin API (:2019) so the service chain
// completes the reload step without touching a real Caddy.
type adminStub struct {
	reloads int
}

func (s *adminStub) handler(t *testing.T) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Read-back (D3): after every POST /load the UI verifies the live
		// config via GET /config/apps/http/servers. The stub mirrors that
		// contract: it serves the fixture host (example.com).
		if r.Method == http.MethodGet && r.URL.Path == "/config/apps/http/servers" {
			w.Header().Set("Content-Type", "application/json")
			w.Write(liveServers())
			return
		}
		if r.Method != http.MethodPost || r.URL.Path != "/load" {
			t.Errorf("the stub expected POST /load, received %s %s", r.Method, r.URL.Path)
		}
		s.reloads++
		w.WriteHeader(http.StatusOK)
	})
}

// setupEnv prepares the complete environment: token, temp directories, a
// Caddyfile and the stub of the Admin API. It returns the mux protected by
// Bearer.
func setupEnv(t *testing.T, admin *adminStub) http.Handler {
	t.Setenv("CADDY_UI_TOKEN", "super-secret-token")

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

	server := httptest.NewServer(admin.handler(t))
	t.Cleanup(server.Close)
	t.Setenv("CADDY_ADMIN_URL", server.URL)

	return auth.Middleware(ui.NewRouter())
}

func bearerRequest(t *testing.T, method, path string, body []byte) *http.Request {
	req, err := http.NewRequest(method, path, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("failed creating request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer super-secret-token")
	return req
}

func TestAPISetModeRequiresBearer(t *testing.T) {
	handler := setupEnv(t, &adminStub{})

	// The Bearer middleware rejects before reaching the mux: 401 without a
	// header.
	req, _ := http.NewRequest(http.MethodPut, "/api/sites/test.com/mode", bytes.NewBufferString(`{"mode":"On"}`))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 without Bearer, got %d", recorder.Code)
	}
}

func TestAPISetModeSuccessRegeneratesOverlay(t *testing.T) {
	admin := &adminStub{}
	handler := setupEnv(t, admin)

	req := bearerRequest(t, http.MethodPut, "/api/sites/example.com/mode", []byte(`{"mode":"On"}`))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (%s)", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), `"status":"success"`) {
		t.Errorf("the body does not confirm the success: %s", recorder.Body.String())
	}

	// The overlay was regenerated with the new mode and the real domain in
	// the header.
	overlay, err := os.ReadFile(filepath.Join(os.Getenv("CADDY_UI_MANAGED_DIR"), "waf-example_com.conf"))
	if err != nil {
		t.Fatalf("the waf-example_com.conf overlay was not generated: %v", err)
	}
	if !strings.Contains(string(overlay), "SecRuleEngine On") {
		t.Errorf("the overlay does not contain the sent mode:\n%s", overlay)
	}
	if !strings.Contains(string(overlay), "# domain: example.com") {
		t.Errorf("the overlay does not keep the domain in the header:\n%s", overlay)
	}

	if admin.reloads != 1 {
		t.Errorf("expected exactly 1 Caddy reload, %d made", admin.reloads)
	}
}

// TestAPISetExclusionsInvalidPayloadReturns400: exclusions that do not pass
// the validation are an invalid client payload → 400 through the full stack
// (Bearer → router → handler), without reloading Caddy (SUGGESTION #4).
func TestAPISetExclusionsInvalidPayloadReturns400(t *testing.T) {
	admin := &adminStub{}
	handler := setupEnv(t, admin)

	req := bearerRequest(t, http.MethodPut, "/api/sites/example.com/exclusions", []byte(`{"exclusions":[{"type":"bogus","value":"1"}]}`))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 with an invalid exclusion, got %d (%s)", recorder.Code, recorder.Body.String())
	}
	if admin.reloads != 0 {
		t.Errorf("Caddy must not be reloaded with an invalid payload, %d reloads made", admin.reloads)
	}
}

// TestAPISetIPRulesInvalidPayloadReturns400: a non-CIDR IP entry is an
// invalid client payload → 400, not a server failure (SUGGESTION #4).
func TestAPISetIPRulesInvalidPayloadReturns400(t *testing.T) {
	admin := &adminStub{}
	handler := setupEnv(t, admin)

	req := bearerRequest(t, http.MethodPut, "/api/sites/example.com/iprules", []byte(`{"denylist":["not-an-ip"]}`))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 with an invalid IP entry, got %d (%s)", recorder.Code, recorder.Body.String())
	}
	if admin.reloads != 0 {
		t.Errorf("Caddy must not be reloaded with an invalid payload, %d reloads made", admin.reloads)
	}
}

func TestAPIFlatEndpointRemoved(t *testing.T) {
	handler := setupEnv(t, &adminStub{})

	// The old (flat) contract no longer exists: any verb/shape → 404.
	req := bearerRequest(t, http.MethodPost, "/api/mode?domain=example.com", []byte(`{"mode":"On"}`))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusNotFound {
		t.Errorf("the flat /api/mode endpoint must return 404, got %d", recorder.Code)
	}
}

func TestAPIHealth(t *testing.T) {
	// /health is public and is mounted in main.go OUTSIDE the authenticated
	// mux (F1: the route no longer lives in the API router): the handler is
	// exercised directly, without Bearer - the container healthchecks do not
	// carry credentials.
	rec := httptest.NewRecorder()
	ui.HealthHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/health", nil))

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 in /health, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `"status":"ok"`) {
		t.Errorf("the body of /health is not the expected one: %s", rec.Body.String())
	}
}

// seedIntegrationSnapshot seeds a snapshot in the backups dir of the slug.
func seedIntegrationSnapshot(t *testing.T, domain, name, content string) {
	t.Helper()
	slugDir := filepath.Join(os.Getenv("CADDY_UI_BACKUP_DIR"), domain)
	if err := os.MkdirAll(slugDir, 0750); err != nil {
		t.Fatalf("failed creating backups dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(slugDir, name), []byte(content), 0640); err != nil {
		t.Fatalf("failed seeding snapshot %s: %v", name, err)
	}
}

// TestAPIGetBackupsListsSnapshots: GET /api/sites/{domain}/backups returns
// the snapshots of the domain as JSON (backup-recovery spec: backups listed).
func TestAPIGetBackupsListsSnapshots(t *testing.T) {
	handler := setupEnv(t, &adminStub{})
	seedIntegrationSnapshot(t, "example_com", "2020-01-01T00-00-00Z.waf.conf", "waf-2020")
	seedIntegrationSnapshot(t, "example_com", "2020-01-01T00-00-00Z.exclusions.conf", "exc-2020")

	req := bearerRequest(t, http.MethodGet, "/api/sites/example.com/backups", nil)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", recorder.Code)
	}
	body := recorder.Body.String()
	if !strings.Contains(body, "2020-01-01T00-00-00Z") || !strings.Contains(body, "waf") || !strings.Contains(body, "exclusions") {
		t.Errorf("the listing must include the seeded snapshots: %s", body)
	}
	if !strings.Contains(body, `"Size":8`) {
		t.Errorf("the listing must include the real file size: %s", body)
	}
}

// TestAPIGetBackupsEmptyReturnsEmptyArray: without backups the endpoint
// responds 200 with an empty array (honest empty state, never 500).
func TestAPIGetBackupsEmptyReturnsEmptyArray(t *testing.T) {
	handler := setupEnv(t, &adminStub{})

	req := bearerRequest(t, http.MethodGet, "/api/sites/example.com/backups", nil)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Fatalf("without backups expected 200, got %d", recorder.Code)
	}
	if !strings.Contains(recorder.Body.String(), "[]") {
		t.Errorf("without backups the body must be an empty array: %s", recorder.Body.String())
	}
}

// TestAPIRollbackRestoresSnapshot: POST /api/sites/{domain}/rollback restores
// the bytes of the given snapshot over the overlay and reloads Caddy.
func TestAPIRollbackRestoresSnapshot(t *testing.T) {
	admin := &adminStub{}
	handler := setupEnv(t, admin)

	overlayPath := filepath.Join(os.Getenv("CADDY_UI_MANAGED_DIR"), "waf-example_com.conf")
	if err := os.WriteFile(overlayPath, []byte("current state"), 0640); err != nil {
		t.Fatalf("failed seeding overlay: %v", err)
	}
	seedIntegrationSnapshot(t, "example_com", "2020-01-01T00-00-00Z.waf.conf", "# Caddy WAF UI managed - do not edit manually\n# domain: example.com | mode: Off | updated: 2020-01-01T00:00:00Z\n")

	req := bearerRequest(t, http.MethodPost, "/api/sites/example.com/rollback", []byte(`{"backup":"2020-01-01T00-00-00Z.waf.conf"}`))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (%s)", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), `"status":"success"`) {
		t.Errorf("the body does not confirm the success: %s", recorder.Body.String())
	}

	overlay, err := os.ReadFile(overlayPath)
	if err != nil {
		t.Fatalf("the overlay was not restored: %v", err)
	}
	if !strings.Contains(string(overlay), "SecRuleEngine Off") || !strings.Contains(string(overlay), "coraza_waf {") {
		t.Errorf("the overlay must restore the snapshot's mode in a regenerated overlay: %q", overlay)
	}
	if admin.reloads != 1 {
		t.Errorf("expected exactly 1 Caddy reload, %d made", admin.reloads)
	}
}

// TestAPIRollbackInvalidBackupRejected: an unsafe snapshot name is rejected
// with 400 and without reloading Caddy (fail-fast before mutating).
func TestAPIRollbackInvalidBackupRejected(t *testing.T) {
	admin := &adminStub{}
	handler := setupEnv(t, admin)

	req := bearerRequest(t, http.MethodPost, "/api/sites/example.com/rollback", []byte(`{"backup":"../../etc/passwd"}`))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 with an invalid snapshot, got %d", recorder.Code)
	}
	if admin.reloads != 0 {
		t.Errorf("Caddy must not be reloaded with an invalid snapshot, %d reloads made", admin.reloads)
	}
}
