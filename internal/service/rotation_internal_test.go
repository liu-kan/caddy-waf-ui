package service

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/developmi/caddy-waf-ui/internal/domain"
	"github.com/developmi/caddy-waf-ui/internal/files"
	"github.com/developmi/caddy-waf-ui/internal/waf"
)

// setupRotationEnv prepares the managed/backup/data directories, a
// Caddyfile, an audit log of auditBytes and an Admin API stub that reports
// every generated revision as live.
func setupRotationEnv(t *testing.T, auditBytes int) (managed, backups string) {
	t.Helper()
	tmp := t.TempDir()
	managed = filepath.Join(tmp, "ui-managed")
	backups = filepath.Join(tmp, "backups")
	if err := os.MkdirAll(managed, 0o750); err != nil {
		t.Fatal(err)
	}
	caddyfile := filepath.Join(tmp, "Caddyfile")
	if err := os.WriteFile(caddyfile, []byte("example.com {\n}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	audit := filepath.Join(tmp, "audit.log")
	if err := os.WriteFile(audit, []byte(strings.Repeat("x", auditBytes)), 0o600); err != nil {
		t.Fatal(err)
	}
	admin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			var revs []string
			paths, _ := filepath.Glob(filepath.Join(managed, "waf-*.conf"))
			for _, p := range paths {
				if b, err := os.ReadFile(p); err == nil {
					revs = append(revs, "# waf-config-revision: "+waf.Revision(b))
				}
			}
			handle, _ := json.Marshal([]map[string]string{{"handler": "waf", "directives": strings.Join(revs, "\n")}})
			_, _ = w.Write([]byte(`{"srv0":{"routes":[{"match":[{"host":["example.com"]}],"handle":` + string(handle) + `}]}}`))
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(admin.Close)
	t.Setenv("CADDY_UI_MANAGED_DIR", managed)
	t.Setenv("CADDY_UI_BACKUP_DIR", backups)
	t.Setenv("CADDY_UI_DATA_DIR", filepath.Join(tmp, "data"))
	t.Setenv("CADDY_UI_CADDYFILE", caddyfile)
	t.Setenv("CADDY_UI_AUDIT_LOG", audit)
	t.Setenv("CADDY_ADMIN_URL", admin.URL)
	t.Setenv("CADDY_UI_PROBE_URLS", "")
	return managed, backups
}

// TestRotationNeverRevertsAConcurrentModeChange: the audit rotation reopens
// the audit writers by republishing every site. A mode change that completes
// while the rotation waits for the change lock must survive: the rotation
// republishes the state stored when it holds the lock, not a mode it read
// before waiting.
func TestRotationNeverRevertsAConcurrentModeChange(t *testing.T) {
	setupRotationEnv(t, 16)
	if err := ApplyMode(Actor{}, "example.com", domain.ModeDetectionOnly); err != nil {
		t.Fatal(err)
	}

	changeMu.Lock()
	done := make(chan error, 1)
	go func() { done <- RotateAudit(1) }()
	time.Sleep(200 * time.Millisecond) // the rotation now waits for the lock
	on := domain.ModeOn
	if _, err := writeSiteWAF("example.com", wafOverride{mode: &on}); err != nil {
		changeMu.Unlock()
		t.Fatal(err)
	}
	changeMu.Unlock()

	if err := <-done; err != nil {
		t.Fatalf("rotation failed: %v", err)
	}
	state, err := ReadSiteState("example.com")
	if err != nil {
		t.Fatal(err)
	}
	if state.Mode != domain.ModeOn {
		t.Fatalf("the rotation reverted the concurrent change to %s", state.Mode)
	}
}

// TestSystemReapplyKeepsOperatorSnapshots: rotations and IP group refreshes
// republish unchanged operator intent; they must not take snapshots, or a
// few rotations evict the rollback history (CADDY_UI_BACKUP_KEEP).
func TestSystemReapplyKeepsOperatorSnapshots(t *testing.T) {
	_, backups := setupRotationEnv(t, 16)
	t.Setenv("CADDY_UI_BACKUP_KEEP", "2")
	for _, mode := range []domain.WAFMode{domain.ModeDetectionOnly, domain.ModeOn, domain.ModeDetectionOnly} {
		if err := ApplyMode(Actor{}, "example.com", mode); err != nil {
			t.Fatal(err)
		}
	}
	before := snapshotNames(t, backups)
	if len(before) != 2 {
		t.Fatalf("setup: expected 2 operator snapshots, got %v", before)
	}
	for i := 0; i < 3; i++ {
		if err := os.WriteFile(os.Getenv("CADDY_UI_AUDIT_LOG"), []byte("grown"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := RotateAudit(1); err != nil {
			t.Fatalf("rotation %d: %v", i+1, err)
		}
	}
	if after := snapshotNames(t, backups); strings.Join(after, ",") != strings.Join(before, ",") {
		t.Fatalf("rotations replaced operator snapshots: before %v, after %v", before, after)
	}
}

func snapshotNames(t *testing.T, backups string) []string {
	t.Helper()
	entries, err := os.ReadDir(files.BackupDirPath(backups, "example.com"))
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range entries {
		out = append(out, e.Name())
	}
	return out
}
