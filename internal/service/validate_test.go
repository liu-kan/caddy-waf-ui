package service_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/developmi/caddy-waf-ui/internal/domain"
	"github.com/developmi/caddy-waf-ui/internal/iprules"
	"github.com/developmi/caddy-waf-ui/internal/service"
	"github.com/developmi/caddy-waf-ui/internal/waf"
)

// adminSpy simulates the Caddy Admin API (:2019) and counts the calls
// received. The D3 read-back (GET /config/apps/http/servers) is not counted
// as a reload. With the domain validation active, the spy never receives
// traffic: the failure happens before reaching the reload.
type adminSpy struct {
	calls int
}

func (s *adminSpy) handler(t *testing.T) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/config/apps/http/servers" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(liveServers())
			return
		}
		s.calls++
		w.WriteHeader(http.StatusOK)
	})
}

// validateEnv groups the files/env environment for the adversarial domain
// tests. Own names (validate prefix) to avoid colliding with the helpers of
// chain_test.go, which the structure fixer refactors.
type validateEnv struct {
	managedDir string
	backupDir  string
	admin      *adminSpy
}

// setupValidateEnv prepares temp directories and a stub of the Admin API;
// the service reads everything from the environment (convention D2).
func setupValidateEnv(t *testing.T) *validateEnv {
	t.Helper()
	tmp := t.TempDir()
	env := &validateEnv{
		managedDir: filepath.Join(tmp, "ui-managed"),
		backupDir:  filepath.Join(tmp, "backups"),
		admin:      &adminSpy{},
	}
	if err := os.MkdirAll(env.managedDir, 0750); err != nil {
		t.Fatalf("failed creating managedDir: %v", err)
	}

	server := httptest.NewServer(env.admin.handler(t))
	t.Cleanup(server.Close)

	t.Setenv("CADDY_UI_MANAGED_DIR", env.managedDir)
	t.Setenv("CADDY_UI_DATA_DIR", t.TempDir())
	t.Setenv("CADDY_UI_BACKUP_DIR", env.backupDir)
	t.Setenv("CADDY_ADMIN_URL", server.URL)
	return env
}

// assertNoMutation verifies that a chain entry with an invalid domain
// produced NO side effects: no overlay written, no backup created and no
// Caddy reload (fail-fast before mutating state).
func assertNoMutation(t *testing.T, env *validateEnv) {
	t.Helper()
	entries, err := os.ReadDir(env.managedDir)
	if err != nil {
		t.Fatalf("failed reading managedDir: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("no overlay must be written with an invalid domain, found: %v", entries)
	}
	if _, err := os.Stat(env.backupDir); !os.IsNotExist(err) {
		t.Errorf("the backups directory must not be created with an invalid domain")
	}
	if env.admin.calls != 0 {
		t.Errorf("Caddy must not be reloaded with an invalid domain, %d calls made", env.admin.calls)
	}
}

// TestValidateDomainRejectsHostileInput: the validator must reject every
// domain that is not a strict hostname [a-zA-Z0-9.-] - including the
// Caddyfile directive injection and path traversal payloads reported by
// judge J2. The error always wraps ErrInvalidDomain (sentinel pattern, same
// style as ErrInvalidMode) so the REST handlers can translate it to 400.
func TestValidateDomainRejectsHostileInput(t *testing.T) {
	tests := []struct {
		name   string
		domain string
	}{
		{"Empty", ""},
		// Caddyfile directive injection via the "# domain:" header of the
		// overlay: a line break + directive would abort the snippet and allow
		// injecting "respond 200" at site level.
		{"Caddyfile directive injection", "foo%0Aabort | mode: On%0Arespond 200%0A# x"},
		// Backup path traversal: with the old slug, ".." and "/" reached
		// filepath.Join(backupDir, slug) (files/backup.go) and
		// os.ReadFile/WriteFile alive. It must be rejected BEFORE reaching
		// the backup.
		{"Relative path traversal", "x/../../tmp/evil"},
		{"Parent directory traversal", "../.."},
		{"Double dot", ".."},
		{"Whitespace", "a b"},
		{"Slash", "a/b"},
		{"Consecutive double dots", "a..b"},
		{"Leading dot", ".example.com"},
		{"Trailing dot", "example.com."},
		{"Label with leading hyphen", "-a.com"},
		{"Label with trailing hyphen", "a-.com"},
		{"Hyphen only", "-"},
		{"Colon", "a:80"},
		{"At sign", "a@b"},
		{"Quotes", `a"b`},
		{"Braces", "a{b}c"},
		{"Dollar sign", "a$b"},
		{"Percent sign", "a%b"},
		{"Wildcard", "*.example.com"},
		{"Backslash", `a\b`},
		{"Underscore", "a_b.com"},
		{"Control char NUL", "a\x00b"},
		{"Control char tab", "a\tb"},
		{"Raw newline", "a\nb"},
		{"Non-ASCII characters", "café.com"},
		{"Excessive total length", strings.Repeat("a.", 127) + "a"},
		{"Excessive label length", "a" + strings.Repeat("b", 63) + ".com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := service.ValidateDomain(tt.domain)
			if err == nil {
				t.Fatalf("ValidateDomain(%q) should fail", tt.domain)
			}
			if !errors.Is(err, service.ErrInvalidDomain) {
				t.Errorf("ValidateDomain(%q) must wrap ErrInvalidDomain, got: %v", tt.domain, err)
			}
		})
	}
}

// TestValidateDomainAcceptsValidHostnames: valid hostnames/FQDNs must pass
// the strict validation (including localhost, single-character labels and
// punycode).
func TestValidateDomainAcceptsValidHostnames(t *testing.T) {
	tests := []struct {
		name   string
		domain string
	}{
		{"Typical FQDN", "api.example.com"},
		{"Localhost", "localhost"},
		{"Short label", "a.io"},
		{"Single label", "a"},
		{"Subdomains", "sub.domain.example.com"},
		{"Internal hyphens", "mi-sitio.com"},
		{"Punycode", "xn--bcher-kva.example"},
		{"Digits only", "127.0.0.1"},
		{"Maximum length", strings.Repeat("a.", 126) + "a"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := service.ValidateDomain(tt.domain); err != nil {
				t.Errorf("ValidateDomain(%q) should not fail: %v", tt.domain, err)
			}
		})
	}
}

// TestChainEntriesRejectHostileDomain: the 4 public chain entries
// (UpdateWAFMode, UpdateExclusions, UpdateIPRules, Rollback) must reject the
// hostile judge payloads with ErrInvalidDomain BEFORE writing files,
// creating backups or reloading Caddy. "x/../../tmp/evil" in particular is
// rejected before reaching the backup path.
func TestChainEntriesRejectHostileDomain(t *testing.T) {
	hostile := []string{
		"foo%0Aabort | mode: On%0Arespond 200%0A# x",
		"x/../../tmp/evil",
		"../..",
		"a b",
		"a/b",
		"a..b",
	}

	for _, d := range hostile {
		t.Run(d, func(t *testing.T) {
			env := setupValidateEnv(t)

			if err := service.UpdateWAFMode(d, domain.ModeOn, "192.0.2.1"); err == nil || !errors.Is(err, service.ErrInvalidDomain) {
				t.Errorf("UpdateWAFMode(%q) must fail with ErrInvalidDomain, got: %v", d, err)
			}
			if err := service.UpdateExclusions(d, []waf.Exclusion{{Type: waf.ExcludeByID, Value: "941100"}}, "192.0.2.1"); err == nil || !errors.Is(err, service.ErrInvalidDomain) {
				t.Errorf("UpdateExclusions(%q) must fail with ErrInvalidDomain, got: %v", d, err)
			}
			if err := service.UpdateIPRules(d, iprules.IPRules{Denylist: []string{"192.0.2.5"}}, "192.0.2.1"); err == nil || !errors.Is(err, service.ErrInvalidDomain) {
				t.Errorf("UpdateIPRules(%q) must fail with ErrInvalidDomain, got: %v", d, err)
			}
			if err := service.Rollback(d, "2020-01-01T00-00-00Z.waf.conf", "192.0.2.1"); err == nil || !errors.Is(err, service.ErrInvalidDomain) {
				t.Errorf("Rollback(%q) must fail with ErrInvalidDomain, got: %v", d, err)
			}

			assertNoMutation(t, env)
		})
	}
}

// TestRollbackInvalidDomainFailsBeforeMutation: a rollback with an invalid
// domain (even if the snapshot is valid) aborts at the domain validation:
// the overlay stays intact, no new snapshots are created and Caddy is not
// reloaded.
func TestRollbackInvalidDomainFailsBeforeMutation(t *testing.T) {
	env := setupValidateEnv(t)

	slug := domain.DomainSlug("api.example.com")
	overlay := filepath.Join(env.managedDir, "waf-"+slug+".conf")
	if err := os.WriteFile(overlay, []byte("previous"), 0640); err != nil {
		t.Fatalf("failed seeding overlay: %v", err)
	}
	backupDir := filepath.Join(env.backupDir, slug)
	if err := os.MkdirAll(backupDir, 0750); err != nil {
		t.Fatalf("failed creating backups dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(backupDir, "2020-01-01T00-00-00Z.waf.conf"), []byte("snapshot"), 0640); err != nil {
		t.Fatalf("failed seeding snapshot: %v", err)
	}

	err := service.Rollback("../..", "2020-01-01T00-00-00Z.waf.conf", "192.0.2.1")
	if err == nil || !errors.Is(err, service.ErrInvalidDomain) {
		t.Fatalf("expected ErrInvalidDomain, got: %v", err)
	}

	content, readErr := os.ReadFile(overlay)
	if readErr != nil || string(content) != "previous" {
		t.Errorf("the overlay must not mutate with an invalid domain (content: %q, err: %v)", content, readErr)
	}
	entries, err := os.ReadDir(backupDir)
	if err != nil {
		t.Fatalf("failed reading backups dir: %v", err)
	}
	if len(entries) != 1 {
		t.Errorf("no snapshots must be created with an invalid domain, found %d", len(entries))
	}
	if env.admin.calls != 0 {
		t.Errorf("Caddy must not be reloaded with an invalid domain, %d calls made", env.admin.calls)
	}
}
