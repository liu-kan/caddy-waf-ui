package service_test

import (
	"bytes"
	"encoding/json"
	"log/slog"
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

// adminStub simulates the Caddy Admin API (:2019) and records how many times
// POST /load was invoked. With fail=true it responds 500 to exercise the D6
// branch. onFail (optional) runs BEFORE responding 500: it lets the test
// degrade the environment (e.g. creating a directory where the D6
// restoration will try to write) to exercise the failure of the restoration
// itself.
type adminStub struct {
	calls  int
	fail   bool
	onFail func()
}

func (s *adminStub) handler(t *testing.T) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Read-back (D3): after every POST /load the service verifies the
		// live config via GET /config/apps/http/servers. The stub serves the
		// fixture host (example.com). NOT counted as a reload.
		if r.Method == http.MethodGet && r.URL.Path == "/config/apps/http/servers" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(liveServers())
			return
		}
		s.calls++
		if r.Method != http.MethodPost || r.URL.Path != "/load" {
			t.Errorf("the stub expected POST /load, received %s %s", r.Method, r.URL.Path)
		}
		if s.fail {
			if s.onFail != nil {
				s.onFail()
			}
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
}

// chainEnv groups the files/env environment for a chain test.
type chainEnv struct {
	managedDir string
	backupDir  string
	admin      *adminStub
}

// setupChainEnv prepares temp directories, a test Caddyfile and a stub of
// the Admin API; the service reads everything from the environment
// (convention D2).
func setupChainEnv(t *testing.T, failReload bool) *chainEnv {
	tmp := t.TempDir()
	managedDir := filepath.Join(tmp, "ui-managed")
	backupDir := filepath.Join(tmp, "backups")
	if err := os.MkdirAll(managedDir, 0750); err != nil {
		t.Fatalf("failed creating managedDir: %v", err)
	}

	caddyfile := filepath.Join(tmp, "Caddyfile")
	if err := os.WriteFile(caddyfile, []byte("example.com {\n}\n"), 0600); err != nil {
		t.Fatalf("failed to write test Caddyfile: %v", err)
	}

	stub := &adminStub{fail: failReload}
	server := httptest.NewServer(stub.handler(t))
	t.Cleanup(server.Close)

	t.Setenv("CADDY_UI_MANAGED_DIR", managedDir)
	t.Setenv("CADDY_UI_DATA_DIR", filepath.Join(tmp, "data"))
	t.Setenv("CADDY_UI_BACKUP_DIR", backupDir)
	t.Setenv("CADDY_UI_CADDYFILE", caddyfile)
	t.Setenv("CADDY_ADMIN_URL", server.URL)

	return &chainEnv{managedDir: managedDir, backupDir: backupDir, admin: stub}
}

// seedWAFOverlay creates a waf-{slug}.conf overlay with the given previous
// content.
func seedWAFOverlay(t *testing.T, managedDir, domain, content string) {
	if err := os.WriteFile(
		filepath.Join(managedDir, "waf-"+strings.ReplaceAll(strings.ReplaceAll(domain, ".", "_"), "*", "wildcard")+".conf"),
		[]byte(content), 0640); err != nil {
		t.Fatalf("failed seeding overlay: %v", err)
	}
}

const oldWAFContent = `# Caddy WAF UI managed - do not edit manually
# domain: api.example.com | mode: DetectionOnly | updated: 2026-01-01T00:00:00Z
(waf_api_example_com) {
    coraza_waf {
        directives ` + "`" + `
            SecRuleEngine DetectionOnly
        ` + "`" + `
    }
}
`

// captureLogs redirects slog to a buffer to assert the audit events (NIST
// AU-12) emitted by the chain. It restores the previous handler.
func captureLogs(t *testing.T) *bytes.Buffer {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return &buf
}

// snapshotCount counts the snapshots of a type in the backups dir of the slug.
func snapshotCount(t *testing.T, backupDir, slug, fileType string) int {
	dir := filepath.Join(backupDir, slug)
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return 0
	}
	if err != nil {
		t.Fatalf("failed reading backups dir: %v", err)
	}
	count := 0
	for _, e := range entries {
		if strings.Contains(e.Name(), "."+fileType+".conf") {
			count++
		}
	}
	return count
}

// seedBackupSnapshot seeds a snapshot with the given content in the dir of
// the slug (simulates a previous backup history).
func seedBackupSnapshot(t *testing.T, backupDir, slug, name, content string) {
	t.Helper()
	dir := filepath.Join(backupDir, slug)
	if err := os.MkdirAll(dir, 0750); err != nil {
		t.Fatalf("failed creating backups dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0640); err != nil {
		t.Fatalf("failed seeding snapshot %s: %v", name, err)
	}
}

// newestSnapshot reads the newest snapshot of a type (the one created by the
// last backup) and returns its content.
func newestSnapshot(t *testing.T, backupDir, slug, fileType string) string {
	t.Helper()
	dir := filepath.Join(backupDir, slug)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("failed reading snapshots dir: %v", err)
	}
	newest := ""
	for _, e := range entries {
		if strings.Contains(e.Name(), "."+fileType+".conf") && e.Name() > newest {
			newest = e.Name()
		}
	}
	if newest == "" {
		t.Fatalf("no snapshots of type %s in %s", fileType, dir)
	}
	content, err := os.ReadFile(filepath.Join(dir, newest))
	if err != nil {
		t.Fatalf("failed reading snapshot %s: %v", newest, err)
	}
	return string(content)
}

func TestUpdateWAFModeChainSuccess(t *testing.T) {
	env := setupChainEnv(t, false)
	seedWAFOverlay(t, env.managedDir, "api.example.com", oldWAFContent)
	audit := captureLogs(t)

	if err := service.UpdateWAFMode("api.example.com", domain.ModeOn, "192.0.2.1"); err != nil {
		t.Fatalf("UpdateWAFMode failed: %v", err)
	}

	// Overlay regenerated with the new mode and the real domain in the header.
	conf, err := os.ReadFile(filepath.Join(env.managedDir, "waf-api_example_com.conf"))
	if err != nil {
		t.Fatalf("failed reading overlay: %v", err)
	}
	if !strings.Contains(string(conf), "SecRuleEngine On") {
		t.Errorf("the overlay does not contain the new mode:\n%s", conf)
	}
	if !strings.Contains(string(conf), "# domain: api.example.com") {
		t.Errorf("the overlay does not keep the real domain in the header:\n%s", conf)
	}

	// The snapshot must contain the PREVIOUS state: the backup happened
	// before writing.
	if got := snapshotCount(t, env.backupDir, "api_example_com", "waf"); got != 1 {
		t.Fatalf("expected 1 waf snapshot, found %d", got)
	}
	entries, err := os.ReadDir(filepath.Join(env.backupDir, "api_example_com"))
	if err != nil {
		t.Fatalf("failed reading snapshots dir: %v", err)
	}
	snapBytes, err := os.ReadFile(filepath.Join(env.backupDir, "api_example_com", entries[0].Name()))
	if err != nil {
		t.Fatalf("failed reading snapshot: %v", err)
	}
	if string(snapBytes) != oldWAFContent {
		t.Errorf("the snapshot does not contain the previous state (backup before writing)")
	}

	if env.admin.calls != 1 {
		t.Errorf("expected exactly 1 Caddy reload, %d made", env.admin.calls)
	}

	if !strings.Contains(audit.String(), "waf_mode_changed") {
		t.Errorf("waf_mode_changed was not audited:\n%s", audit.String())
	}
}

func TestUpdateWAFModeReloadFailureRestoresOverlay(t *testing.T) {
	env := setupChainEnv(t, true) // stub responds 500
	seedWAFOverlay(t, env.managedDir, "api.example.com", oldWAFContent)

	err := service.UpdateWAFMode("api.example.com", domain.ModeOn, "192.0.2.1")
	if err == nil {
		t.Fatal("UpdateWAFMode should fail when the reload fails")
	}

	// D6: no partial overlay must remain - the previous content was restored.
	conf, readErr := os.ReadFile(filepath.Join(env.managedDir, "waf-api_example_com.conf"))
	if readErr != nil {
		t.Fatalf("the overlay should still exist after the restore: %v", readErr)
	}
	if string(conf) != oldWAFContent {
		t.Errorf("after the reload failure the overlay must return to the previous state (D6):\n%s", conf)
	}
}

func TestUpdateWAFModeReloadFailureRemovesNewFile(t *testing.T) {
	env := setupChainEnv(t, true) // no previous overlay
	err := service.UpdateWAFMode("api.example.com", domain.ModeOn, "192.0.2.1")
	if err == nil {
		t.Fatal("UpdateWAFMode should fail when the reload fails")
	}

	// D6: if there was no previous file, the new overlay must be removed.
	if _, statErr := os.Stat(filepath.Join(env.managedDir, "waf-api_example_com.conf")); !os.IsNotExist(statErr) {
		t.Errorf("without a previous file, the new overlay must be removed after the reload failure (D6)")
	}
}

func TestUpdateWAFModeInvalidModeFailsBeforeBackup(t *testing.T) {
	env := setupChainEnv(t, false)
	audit := captureLogs(t)

	err := service.UpdateWAFMode("api.example.com", domain.WAFMode("BlockAll"), "192.0.2.1")
	if err == nil {
		t.Fatal("an invalid mode should fail the validation")
	}

	// The validation happens BEFORE the backup: nothing must have been
	// written or reloaded.
	if got := snapshotCount(t, env.backupDir, "api_example_com", "waf"); got != 0 {
		t.Errorf("no snapshots must be created with an invalid input, found %d", got)
	}
	if env.admin.calls != 0 {
		t.Errorf("Caddy must not be reloaded with an invalid input, %d calls made", env.admin.calls)
	}
	if strings.Contains(audit.String(), "waf_mode_changed") {
		t.Errorf("a successful change must not be audited with an invalid input:\n%s", audit.String())
	}
}

func TestUpdateExclusionsSuccess(t *testing.T) {
	env := setupChainEnv(t, false)
	audit := captureLogs(t)

	err := service.UpdateExclusions("api.example.com",
		[]waf.Exclusion{{Type: waf.ExcludeByID, Value: "941100", Param: "q"}}, "192.0.2.1")
	if err != nil {
		t.Fatalf("UpdateExclusions failed: %v", err)
	}

	conf, readErr := os.ReadFile(filepath.Join(env.managedDir, "exclusions-api_example_com.conf"))
	if readErr != nil {
		t.Fatalf("the exclusions overlay was not written: %v", readErr)
	}
	if !strings.Contains(string(conf), `SecRuleUpdateTargetById 941100 "!ARGS:q"`) {
		t.Errorf("the overlay does not contain the parameter-scoped exclusion:\n%s", conf)
	}
	if env.admin.calls != 1 {
		t.Errorf("expected 1 reload, %d made", env.admin.calls)
	}
	if !strings.Contains(audit.String(), "exclusions_updated") {
		t.Errorf("exclusions_updated was not audited:\n%s", audit.String())
	}
}

func TestUpdateExclusionsInvalidParamFailsBeforeBackup(t *testing.T) {
	env := setupChainEnv(t, false)

	err := service.UpdateExclusions("api.example.com",
		[]waf.Exclusion{{Type: waf.ExcludeByID, Value: "941100", Param: "q\nSecRuleEngine Off"}}, "192.0.2.1")
	if err == nil {
		t.Fatal("an invalid parameter should fail the validation")
	}
	if got := snapshotCount(t, env.backupDir, "api_example_com", "exclusions"); got != 0 {
		t.Errorf("no snapshots must be created with an invalid input, found %d", got)
	}
	if env.admin.calls != 0 {
		t.Errorf("Caddy must not be reloaded with an invalid input, %d calls made", env.admin.calls)
	}
}

func TestUpdateIPRulesSuccess(t *testing.T) {
	env := setupChainEnv(t, false)
	audit := captureLogs(t)

	err := service.UpdateIPRules("api.example.com",
		iprules.IPRules{Denylist: []string{"192.0.2.5"}}, "192.0.2.1")
	if err != nil {
		t.Fatalf("UpdateIPRules failed: %v", err)
	}

	conf, readErr := os.ReadFile(filepath.Join(env.managedDir, "ip-rules-api_example_com.conf"))
	if readErr != nil {
		t.Fatalf("the ip-rules overlay was not written: %v", readErr)
	}
	if !strings.Contains(string(conf), "192.0.2.5/32") {
		t.Errorf("the overlay does not contain the normalized IP:\n%s", conf)
	}
	if env.admin.calls != 1 {
		t.Errorf("expected 1 reload, %d made", env.admin.calls)
	}
	if !strings.Contains(audit.String(), "iprules_updated") {
		t.Errorf("iprules_updated was not audited:\n%s", audit.String())
	}
}

func TestUpdateIPRulesInvalidEntryFailsBeforeBackup(t *testing.T) {
	env := setupChainEnv(t, false)

	err := service.UpdateIPRules("api.example.com",
		iprules.IPRules{Denylist: []string{"not-an-ip"}}, "192.0.2.1")
	if err == nil {
		t.Fatal("an invalid IP entry should fail the validation")
	}
	if got := snapshotCount(t, env.backupDir, "api_example_com", "ip-rules"); got != 0 {
		t.Errorf("no snapshots must be created with an invalid input, found %d", got)
	}
	if env.admin.calls != 0 {
		t.Errorf("Caddy must not be reloaded with an invalid input, %d calls made", env.admin.calls)
	}
}

const restoredWAFContent = `# Caddy WAF UI managed - do not edit manually
# domain: api.example.com | mode: Off | updated: 2020-01-01T00:00:00Z
(restored snippet)
`

// TestRollbackRestoresSnapshotAndBacksUpCurrent: Rollback restores the mode
// and policy of the chosen snapshot (the overlay is regenerated with the
// current baseline), backs up FIRST the current state (newest snapshot),
// reloads Caddy and audits the event.
func TestRollbackRestoresSnapshotAndBacksUpCurrent(t *testing.T) {
	env := setupChainEnv(t, false)
	seedWAFOverlay(t, env.managedDir, "api.example.com", oldWAFContent)
	seedBackupSnapshot(t, env.backupDir, "api_example_com", "2020-01-01T00-00-00Z.waf.conf", restoredWAFContent)
	audit := captureLogs(t)

	if err := service.Rollback("api.example.com", "2020-01-01T00-00-00Z.waf.conf", "192.0.2.1"); err != nil {
		t.Fatalf("Rollback failed: %v", err)
	}

	// The overlay carries the snapshot's mode, regenerated as a managed WAF.
	conf, err := os.ReadFile(filepath.Join(env.managedDir, "waf-api_example_com.conf"))
	if err != nil {
		t.Fatalf("failed reading overlay: %v", err)
	}
	if !strings.Contains(string(conf), "# domain: api.example.com | mode: Off") ||
		!strings.Contains(string(conf), "SecRuleEngine Off") || !strings.Contains(string(conf), "load_owasp_crs") {
		t.Errorf("the overlay must restore the snapshot's mode in a regenerated overlay:\n%s", conf)
	}

	// The current state was backed up first: 2 snapshots, the newest =
	// previous state.
	if got := snapshotCount(t, env.backupDir, "api_example_com", "waf"); got != 2 {
		t.Fatalf("expected 2 waf snapshots (previous + restored), found %d", got)
	}
	if got := newestSnapshot(t, env.backupDir, "api_example_com", "waf"); got != oldWAFContent {
		t.Errorf("the newest snapshot must contain the state prior to the rollback:\n%s", got)
	}

	if env.admin.calls != 1 {
		t.Errorf("expected exactly 1 Caddy reload, %d made", env.admin.calls)
	}
	if !strings.Contains(audit.String(), "rollback_restored") {
		t.Errorf("rollback_restored was not audited:\n%s", audit.String())
	}
}

// TestRollbackReloadFailureRestoresPreviousState: if the reload fails, the
// overlay must return to the state prior to the rollback (D6) and the event
// is audited.
func TestRollbackReloadFailureRestoresPreviousState(t *testing.T) {
	env := setupChainEnv(t, true) // stub responds 500
	seedWAFOverlay(t, env.managedDir, "api.example.com", oldWAFContent)
	seedBackupSnapshot(t, env.backupDir, "api_example_com", "2020-01-01T00-00-00Z.waf.conf", restoredWAFContent)
	audit := captureLogs(t)

	err := service.Rollback("api.example.com", "2020-01-01T00-00-00Z.waf.conf", "192.0.2.1")
	if err == nil {
		t.Fatal("Rollback should fail when the reload fails")
	}

	conf, readErr := os.ReadFile(filepath.Join(env.managedDir, "waf-api_example_com.conf"))
	if readErr != nil {
		t.Fatalf("the overlay should still exist after the revert: %v", readErr)
	}
	if string(conf) != oldWAFContent {
		t.Errorf("after the reload failure the overlay must return to the previous state (D6):\n%s", conf)
	}
	if !strings.Contains(audit.String(), "rollback_changed_but_reload_failed") {
		t.Errorf("rollback_changed_but_reload_failed was not audited:\n%s", audit.String())
	}
}

// TestRollbackInvalidNameFailsBeforeMutation: an unsafe snapshot name (path
// traversal) must fail the validation BEFORE backing up, writing or
// reloading (validate-before-mutate pattern of the chain).
func TestRollbackInvalidNameFailsBeforeMutation(t *testing.T) {
	env := setupChainEnv(t, false)
	seedWAFOverlay(t, env.managedDir, "api.example.com", oldWAFContent)
	audit := captureLogs(t)

	err := service.Rollback("api.example.com", "../../etc/passwd", "192.0.2.1")
	if err == nil {
		t.Fatal("an unsafe snapshot name should fail the validation")
	}

	conf, readErr := os.ReadFile(filepath.Join(env.managedDir, "waf-api_example_com.conf"))
	if readErr != nil {
		t.Fatalf("failed reading overlay: %v", readErr)
	}
	if string(conf) != oldWAFContent {
		t.Errorf("the overlay must not mutate with an invalid snapshot:\n%s", conf)
	}
	if got := snapshotCount(t, env.backupDir, "api_example_com", "waf"); got != 0 {
		t.Errorf("no snapshots must be created with an invalid name, found %d", got)
	}
	if env.admin.calls != 0 {
		t.Errorf("Caddy must not be reloaded with an invalid snapshot, %d calls made", env.admin.calls)
	}
	if !strings.Contains(audit.String(), "rollback_failed") {
		t.Errorf("rollback_failed was not audited:\n%s", audit.String())
	}
}

// TestRollbackMissingSnapshotFailsWithoutReload: a nonexistent snapshot
// (race between listing and restoration) fails without mutating the overlay
// or reloading Caddy.
func TestRollbackMissingSnapshotFailsWithoutReload(t *testing.T) {
	env := setupChainEnv(t, false)
	seedWAFOverlay(t, env.managedDir, "api.example.com", oldWAFContent)

	err := service.Rollback("api.example.com", "2099-01-01T00-00-00Z.waf.conf", "192.0.2.1")
	if err == nil {
		t.Fatal("Rollback of a nonexistent snapshot should fail")
	}

	conf, readErr := os.ReadFile(filepath.Join(env.managedDir, "waf-api_example_com.conf"))
	if readErr != nil {
		t.Fatalf("failed reading overlay: %v", readErr)
	}
	if string(conf) != oldWAFContent {
		t.Errorf("the overlay must not mutate if the snapshot does not exist:\n%s", conf)
	}
	if env.admin.calls != 0 {
		t.Errorf("Caddy must not be reloaded if the snapshot does not exist, %d calls made", env.admin.calls)
	}
}

// breakBackupDir points CADDY_UI_BACKUP_DIR at a FILE: every MkdirAll under
// that path fails with ENOTDIR, forcing the backup step of the chain to fail
// without depending on permissions (also works as root).
func breakBackupDir(t *testing.T, tmp string) string {
	t.Helper()
	file := filepath.Join(tmp, "backup-es-un-archivo")
	if err := os.WriteFile(file, []byte("x"), 0640); err != nil {
		t.Fatalf("failed seeding backup file: %v", err)
	}
	t.Setenv("CADDY_UI_BACKUP_DIR", file)
	return file
}

// breakOverlayWrites makes the managedDir read-only so the atomic write step
// fails (EACCES in CreateTemp). It replaces the historical injection of the
// directory in "<path>.tmp", which disappeared with the unique-temp contract
// of F1 (CreateTemp with the random ".tmp-*" suffix). The permissions are
// restored in the cleanup so t.TempDir can clean the tree. As root the
// permissions do not block (EACCES is ignored), so the test is skipped: there
// is no deterministic way to force a write failure as root without changing
// the public surface of the chain.
func breakOverlayWrites(t *testing.T, managedDir string) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("EACCES does not block root: impossible to force a deterministic write failure")
	}
	if err := os.Chmod(managedDir, 0550); err != nil {
		t.Fatalf("failed making managedDir read-only: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(managedDir, 0750) })
}

// breakOverlayRestore replaces the managedDir with a file DURING the reload
// (onFail hook of the stub): the D6 restoration fails in CreateTemp
// (ENOTDIR), exercising the combined error. The freshly written overlay stays
// preserved in managedDir+"-moved" to be able to assert its content.
func breakOverlayRestore(t *testing.T, env *chainEnv) {
	t.Helper()
	env.admin.onFail = func() {
		moved := env.managedDir + "-moved"
		if err := os.Rename(env.managedDir, moved); err != nil {
			t.Errorf("failed moving managedDir to break the restoration: %v", err)
			return
		}
		if err := os.WriteFile(env.managedDir, []byte("x"), 0640); err != nil {
			t.Errorf("failed seeding managedDir file: %v", err)
		}
	}
}

// TestUpdateWAFModeReadErrorFailsBeforeBackup: if the previous state CANNOT
// be read (the path is a directory), the chain aborts before backing up,
// writing or reloading, and audits the failure (W2).
func TestUpdateWAFModeReadErrorFailsBeforeBackup(t *testing.T) {
	env := setupChainEnv(t, false)
	if err := os.MkdirAll(filepath.Join(env.managedDir, "waf-api_example_com.conf"), 0750); err != nil {
		t.Fatalf("failed seeding overlay path: %v", err)
	}
	audit := captureLogs(t)

	err := service.UpdateWAFMode("api.example.com", domain.ModeOn, "192.0.2.1")
	if err == nil || !strings.Contains(err.Error(), "reading previous state") {
		t.Fatalf("expected a previous-state read error, got: %v", err)
	}
	if got := snapshotCount(t, env.backupDir, "api_example_com", "waf"); got != 0 {
		t.Errorf("no snapshots must be created if the read fails, found %d", got)
	}
	if env.admin.calls != 0 {
		t.Errorf("Caddy must not be reloaded if the read fails, %d calls made", env.admin.calls)
	}
	if !strings.Contains(audit.String(), "waf_mode_failed") || !strings.Contains(audit.String(), "read error") {
		t.Errorf("expected waf_mode_failed audit with read error:\n%s", audit.String())
	}
}

// TestUpdateWAFModeBackupFailureDoesNotMutate: if the backup fails, the
// chain aborts BEFORE writing: the overlay stays intact, Caddy is not
// reloaded and the event is audited (W2, backup-error branch of the service).
func TestUpdateWAFModeBackupFailureDoesNotMutate(t *testing.T) {
	env := setupChainEnv(t, false)
	seedWAFOverlay(t, env.managedDir, "api.example.com", oldWAFContent)
	breakBackupDir(t, filepath.Dir(env.managedDir))
	audit := captureLogs(t)

	err := service.UpdateWAFMode("api.example.com", domain.ModeOn, "192.0.2.1")
	if err == nil || !strings.Contains(err.Error(), "error creating backup") {
		t.Fatalf("expected a backup error, got: %v", err)
	}

	conf, readErr := os.ReadFile(filepath.Join(env.managedDir, "waf-api_example_com.conf"))
	if readErr != nil {
		t.Fatalf("failed reading overlay: %v", readErr)
	}
	if string(conf) != oldWAFContent {
		t.Errorf("the overlay must not mutate if the backup fails:\n%s", conf)
	}
	if env.admin.calls != 0 {
		t.Errorf("Caddy must not be reloaded if the backup fails, %d calls made", env.admin.calls)
	}
	if !strings.Contains(audit.String(), "waf_mode_failed") || !strings.Contains(audit.String(), "backup error") {
		t.Errorf("expected waf_mode_failed audit with backup error:\n%s", audit.String())
	}
}

// TestUpdateWAFModeWriteFailureAuditsFailed: if the atomic write fails
// (read-only managedDir → EACCES in CreateTemp), the chain aborts without
// reloading and audits the failure (W2, write-error branch of the service).
func TestUpdateWAFModeWriteFailureAuditsFailed(t *testing.T) {
	env := setupChainEnv(t, false)
	seedWAFOverlay(t, env.managedDir, "api.example.com", oldWAFContent)
	breakOverlayWrites(t, env.managedDir)
	audit := captureLogs(t)

	err := service.UpdateWAFMode("api.example.com", domain.ModeOn, "192.0.2.1")
	if err == nil || !strings.Contains(err.Error(), "error writing configuration") {
		t.Fatalf("expected a write error, got: %v", err)
	}

	conf, readErr := os.ReadFile(filepath.Join(env.managedDir, "waf-api_example_com.conf"))
	if readErr != nil {
		t.Fatalf("failed reading overlay: %v", readErr)
	}
	if string(conf) != oldWAFContent {
		t.Errorf("the overlay must not mutate if the write fails:\n%s", conf)
	}
	if env.admin.calls != 0 {
		t.Errorf("Caddy must not be reloaded if the write fails, %d calls made", env.admin.calls)
	}
	if !strings.Contains(audit.String(), "waf_mode_failed") || !strings.Contains(audit.String(), "write error") {
		t.Errorf("expected waf_mode_failed audit with write error:\n%s", audit.String())
	}
}

// TestUpdateWAFModeReloadFailureRestoreError: if the reload fails AND the D6
// restoration also fails (the managedDir is replaced by a file during the
// reload), the chain reports BOTH errors and the overlay keeps the new
// content (the revert could not complete) (W2, restore-error).
func TestUpdateWAFModeReloadFailureRestoreError(t *testing.T) {
	env := setupChainEnv(t, true)
	seedWAFOverlay(t, env.managedDir, "api.example.com", oldWAFContent)
	breakOverlayRestore(t, env)
	audit := captureLogs(t)

	err := service.UpdateWAFMode("api.example.com", domain.ModeOn, "192.0.2.1")
	if err == nil || !strings.Contains(err.Error(), "error restoring overlay") {
		t.Fatalf("expected a combined error with a failed restore, got: %v", err)
	}

	// The revert could not complete: the overlay with the NEW content stayed
	// in the moved dir (the original managedDir is now a file).
	conf, readErr := os.ReadFile(filepath.Join(env.managedDir+"-moved", "waf-api_example_com.conf"))
	if readErr != nil {
		t.Fatalf("the overlay with the new content must be preserved in the moved dir: %v", readErr)
	}
	if strings.Contains(string(conf), oldWAFContent) {
		t.Errorf("if the restore fails, the overlay must keep the new content:\n%s", conf)
	}
	if !strings.Contains(string(conf), "SecRuleEngine On") {
		t.Errorf("the moved overlay must contain the new mode:\n%s", conf)
	}
	if !strings.Contains(audit.String(), "waf_mode_changed_but_reload_failed") || !strings.Contains(audit.String(), "(restore error:") {
		t.Errorf("expected audit with restore error:\n%s", audit.String())
	}
}

// seedOverlayFile writes a generic overlay (type prefix) with the given
// content, to exercise exclusions and ip-rules.
func seedOverlayFile(t *testing.T, managedDir, prefix, domain, content string) {
	t.Helper()
	if err := os.WriteFile(
		filepath.Join(managedDir, prefix+"-"+strings.ReplaceAll(strings.ReplaceAll(domain, ".", "_"), "*", "wildcard")+".conf"),
		[]byte(content), 0640); err != nil {
		t.Fatalf("failed seeding overlay %s: %v", prefix, err)
	}
}

// TestUpdateExclusionsReadErrorFailsBeforeBackup: same early-abort contract
// for the exclusions chain (W2, read-error).
func TestUpdateExclusionsReadErrorFailsBeforeBackup(t *testing.T) {
	env := setupChainEnv(t, false)
	if err := os.MkdirAll(filepath.Join(env.managedDir, "exclusions-api_example_com.conf"), 0750); err != nil {
		t.Fatalf("failed seeding overlay path: %v", err)
	}
	audit := captureLogs(t)

	err := service.UpdateExclusions("api.example.com",
		[]waf.Exclusion{{Type: waf.ExcludeByID, Value: "941100"}}, "192.0.2.1")
	if err == nil || !strings.Contains(err.Error(), "reading previous state") {
		t.Fatalf("expected a read error, got: %v", err)
	}
	if env.admin.calls != 0 {
		t.Errorf("Caddy must not be reloaded if the read fails, %d calls made", env.admin.calls)
	}
	if !strings.Contains(audit.String(), "exclusions_failed") || !strings.Contains(audit.String(), "read error") {
		t.Errorf("expected exclusions_failed audit with read error:\n%s", audit.String())
	}
}

// TestUpdateExclusionsBackupFailureFailsBeforeWrite: a backup failure leaves
// the exclusions overlay intact and audits (W2, backup-error).
func TestUpdateExclusionsBackupFailureFailsBeforeWrite(t *testing.T) {
	env := setupChainEnv(t, false)
	seedOverlayFile(t, env.managedDir, "exclusions", "api.example.com", "previous")
	breakBackupDir(t, filepath.Dir(env.managedDir))
	audit := captureLogs(t)

	err := service.UpdateExclusions("api.example.com",
		[]waf.Exclusion{{Type: waf.ExcludeByID, Value: "941100"}}, "192.0.2.1")
	if err == nil || !strings.Contains(err.Error(), "error creating backup") {
		t.Fatalf("expected a backup error, got: %v", err)
	}

	conf, readErr := os.ReadFile(filepath.Join(env.managedDir, "exclusions-api_example_com.conf"))
	if readErr != nil {
		t.Fatalf("failed reading overlay: %v", readErr)
	}
	if string(conf) != "previous" {
		t.Errorf("the exclusions overlay must not mutate if the backup fails:\n%s", conf)
	}
	if env.admin.calls != 0 {
		t.Errorf("Caddy must not be reloaded if the backup fails, %d calls made", env.admin.calls)
	}
	if !strings.Contains(audit.String(), "exclusions_failed") || !strings.Contains(audit.String(), "backup error") {
		t.Errorf("expected exclusions_failed audit with backup error:\n%s", audit.String())
	}
}

// TestUpdateExclusionsReloadFailureRestoresOverlay: reload failure in the
// exclusions chain → D6 restores the previous overlay and audits (W2).
func TestUpdateExclusionsReloadFailureRestoresOverlay(t *testing.T) {
	env := setupChainEnv(t, true)
	seedOverlayFile(t, env.managedDir, "exclusions", "api.example.com", "previous")
	audit := captureLogs(t)

	err := service.UpdateExclusions("api.example.com",
		[]waf.Exclusion{{Type: waf.ExcludeByID, Value: "941100"}}, "192.0.2.1")
	if err == nil {
		t.Fatal("UpdateExclusions should fail when the reload fails")
	}

	conf, readErr := os.ReadFile(filepath.Join(env.managedDir, "exclusions-api_example_com.conf"))
	if readErr != nil {
		t.Fatalf("failed reading overlay: %v", readErr)
	}
	if string(conf) != "previous" {
		t.Errorf("after the reload failure the overlay must return to the previous state (D6):\n%s", conf)
	}
	if !strings.Contains(audit.String(), "exclusions_changed_but_reload_failed") {
		t.Errorf("exclusions_changed_but_reload_failed was not audited:\n%s", audit.String())
	}
}

// TestUpdateExclusionsWriteFailureAuditsFailed: atomic write failure in the
// exclusions chain → aborts without reloading and audits (W2, write-error).
func TestUpdateExclusionsWriteFailureAuditsFailed(t *testing.T) {
	env := setupChainEnv(t, false)
	seedOverlayFile(t, env.managedDir, "exclusions", "api.example.com", "previous")
	breakOverlayWrites(t, env.managedDir)
	audit := captureLogs(t)

	err := service.UpdateExclusions("api.example.com",
		[]waf.Exclusion{{Type: waf.ExcludeByID, Value: "941100"}}, "192.0.2.1")
	if err == nil || !strings.Contains(err.Error(), "error writing configuration") {
		t.Fatalf("expected a write error, got: %v", err)
	}

	conf, readErr := os.ReadFile(filepath.Join(env.managedDir, "exclusions-api_example_com.conf"))
	if readErr != nil {
		t.Fatalf("failed reading overlay: %v", readErr)
	}
	if string(conf) != "previous" {
		t.Errorf("the overlay must not mutate if the write fails:\n%s", conf)
	}
	if env.admin.calls != 0 {
		t.Errorf("Caddy must not be reloaded if the write fails, %d calls made", env.admin.calls)
	}
	if !strings.Contains(audit.String(), "exclusions_failed") || !strings.Contains(audit.String(), "write error") {
		t.Errorf("expected exclusions_failed audit with write error:\n%s", audit.String())
	}
}

// TestUpdateIPRulesReadErrorFailsBeforeBackup: same early-abort contract for
// the ip-rules chain (W2, read-error).
func TestUpdateIPRulesReadErrorFailsBeforeBackup(t *testing.T) {
	env := setupChainEnv(t, false)
	if err := os.MkdirAll(filepath.Join(env.managedDir, "ip-rules-api_example_com.conf"), 0750); err != nil {
		t.Fatalf("failed seeding overlay path: %v", err)
	}
	audit := captureLogs(t)

	err := service.UpdateIPRules("api.example.com",
		iprules.IPRules{Denylist: []string{"192.0.2.5"}}, "192.0.2.1")
	if err == nil || !strings.Contains(err.Error(), "reading previous state") {
		t.Fatalf("expected a read error, got: %v", err)
	}
	if env.admin.calls != 0 {
		t.Errorf("Caddy must not be reloaded if the read fails, %d calls made", env.admin.calls)
	}
	if !strings.Contains(audit.String(), "iprules_failed") || !strings.Contains(audit.String(), "read error") {
		t.Errorf("expected iprules_failed audit with read error:\n%s", audit.String())
	}
}

// TestUpdateIPRulesBackupFailureFailsBeforeWrite: a backup failure leaves
// the ip-rules overlay intact and audits (W2, backup-error).
func TestUpdateIPRulesBackupFailureFailsBeforeWrite(t *testing.T) {
	env := setupChainEnv(t, false)
	seedOverlayFile(t, env.managedDir, "ip-rules", "api.example.com", "previous")
	breakBackupDir(t, filepath.Dir(env.managedDir))
	audit := captureLogs(t)

	err := service.UpdateIPRules("api.example.com",
		iprules.IPRules{Denylist: []string{"192.0.2.5"}}, "192.0.2.1")
	if err == nil || !strings.Contains(err.Error(), "error creating backup") {
		t.Fatalf("expected a backup error, got: %v", err)
	}

	conf, readErr := os.ReadFile(filepath.Join(env.managedDir, "ip-rules-api_example_com.conf"))
	if readErr != nil {
		t.Fatalf("failed reading overlay: %v", readErr)
	}
	if string(conf) != "previous" {
		t.Errorf("the ip-rules overlay must not mutate if the backup fails:\n%s", conf)
	}
	if env.admin.calls != 0 {
		t.Errorf("Caddy must not be reloaded if the backup fails, %d calls made", env.admin.calls)
	}
	if !strings.Contains(audit.String(), "iprules_failed") || !strings.Contains(audit.String(), "backup error") {
		t.Errorf("expected iprules_failed audit with backup error:\n%s", audit.String())
	}
}

// TestUpdateIPRulesReloadFailureRestoresOverlay: reload failure in the
// ip-rules chain → D6 restores the previous overlay and audits (W2).
func TestUpdateIPRulesReloadFailureRestoresOverlay(t *testing.T) {
	env := setupChainEnv(t, true)
	seedOverlayFile(t, env.managedDir, "ip-rules", "api.example.com", "previous")
	audit := captureLogs(t)

	err := service.UpdateIPRules("api.example.com",
		iprules.IPRules{Denylist: []string{"192.0.2.5"}}, "192.0.2.1")
	if err == nil {
		t.Fatal("UpdateIPRules should fail when the reload fails")
	}

	conf, readErr := os.ReadFile(filepath.Join(env.managedDir, "ip-rules-api_example_com.conf"))
	if readErr != nil {
		t.Fatalf("failed reading overlay: %v", readErr)
	}
	if string(conf) != "previous" {
		t.Errorf("after the reload failure the overlay must return to the previous state (D6):\n%s", conf)
	}
	if !strings.Contains(audit.String(), "iprules_changed_but_reload_failed") {
		t.Errorf("iprules_changed_but_reload_failed was not audited:\n%s", audit.String())
	}
}

// TestUpdateIPRulesWriteFailureAuditsFailed: atomic write failure in the
// ip-rules chain → aborts without reloading and audits (W2, write-error).
func TestUpdateIPRulesWriteFailureAuditsFailed(t *testing.T) {
	env := setupChainEnv(t, false)
	seedOverlayFile(t, env.managedDir, "ip-rules", "api.example.com", "previous")
	breakOverlayWrites(t, env.managedDir)
	audit := captureLogs(t)

	err := service.UpdateIPRules("api.example.com",
		iprules.IPRules{Denylist: []string{"192.0.2.5"}}, "192.0.2.1")
	if err == nil || !strings.Contains(err.Error(), "error writing configuration") {
		t.Fatalf("expected a write error, got: %v", err)
	}

	conf, readErr := os.ReadFile(filepath.Join(env.managedDir, "ip-rules-api_example_com.conf"))
	if readErr != nil {
		t.Fatalf("failed reading overlay: %v", readErr)
	}
	if string(conf) != "previous" {
		t.Errorf("the overlay must not mutate if the write fails:\n%s", conf)
	}
	if env.admin.calls != 0 {
		t.Errorf("Caddy must not be reloaded if the write fails, %d calls made", env.admin.calls)
	}
	if !strings.Contains(audit.String(), "iprules_failed") || !strings.Contains(audit.String(), "write error") {
		t.Errorf("expected iprules_failed audit with write error:\n%s", audit.String())
	}
}

// TestRollbackBackupFailureFailsBeforeRestore: if the backup of the current
// state fails, the rollback aborts without restoring or reloading (W2,
// backup-error).
func TestRollbackBackupFailureFailsBeforeRestore(t *testing.T) {
	env := setupChainEnv(t, false)
	seedWAFOverlay(t, env.managedDir, "api.example.com", oldWAFContent)
	seedBackupSnapshot(t, env.backupDir, "api_example_com", "2020-01-01T00-00-00Z.waf.conf", restoredWAFContent)
	breakBackupDir(t, filepath.Dir(env.managedDir))
	audit := captureLogs(t)

	err := service.Rollback("api.example.com", "2020-01-01T00-00-00Z.waf.conf", "192.0.2.1")
	if err == nil || !strings.Contains(err.Error(), "error creating backup") {
		t.Fatalf("expected a backup error, got: %v", err)
	}

	conf, readErr := os.ReadFile(filepath.Join(env.managedDir, "waf-api_example_com.conf"))
	if readErr != nil {
		t.Fatalf("failed reading overlay: %v", readErr)
	}
	if string(conf) != oldWAFContent {
		t.Errorf("the overlay must not mutate if the rollback backup fails:\n%s", conf)
	}
	if env.admin.calls != 0 {
		t.Errorf("Caddy must not be reloaded if the backup fails, %d calls made", env.admin.calls)
	}
	if !strings.Contains(audit.String(), "rollback_failed") || !strings.Contains(audit.String(), "backup error") {
		t.Errorf("expected rollback_failed audit with backup error:\n%s", audit.String())
	}
}

// TestRollbackRestoreFailureFailsBeforeReload: if the byte restoration fails
// (corrupt backup dir: the snapshot read returns an error that is NOT
// ErrInvalidBackup), the rollback aborts without reloading (W2,
// restore-error).
func TestRollbackRestoreFailureFailsBeforeReload(t *testing.T) {
	env := setupChainEnv(t, false)
	// Without a previous overlay: Backup() is a no-op (no source), the
	// failure happens in RestoreBackup when reading from a backup dir that
	// is a file (ENOTDIR).
	breakBackupDir(t, filepath.Dir(env.managedDir))
	audit := captureLogs(t)

	err := service.Rollback("api.example.com", "2099-01-01T00-00-00Z.waf.conf", "192.0.2.1")
	if err == nil || !strings.Contains(err.Error(), "error restoring snapshot") {
		t.Fatalf("expected a restoration error, got: %v", err)
	}
	if env.admin.calls != 0 {
		t.Errorf("Caddy must not be reloaded if the restoration fails, %d calls made", env.admin.calls)
	}
	if !strings.Contains(audit.String(), "rollback_failed") || !strings.Contains(audit.String(), "restore error") {
		t.Errorf("expected rollback_failed audit with restore error:\n%s", audit.String())
	}
}

// TestRollbackReloadFailureRestoreError: reload fails + D6 restoration fails
// → combined error and audit with restore error (W2, restore-error).
func TestRollbackReloadFailureRestoreError(t *testing.T) {
	env := setupChainEnv(t, true)
	seedWAFOverlay(t, env.managedDir, "api.example.com", oldWAFContent)
	seedBackupSnapshot(t, env.backupDir, "api_example_com", "2020-01-01T00-00-00Z.waf.conf", restoredWAFContent)
	breakOverlayRestore(t, env)
	audit := captureLogs(t)

	err := service.Rollback("api.example.com", "2020-01-01T00-00-00Z.waf.conf", "192.0.2.1")
	if err == nil || !strings.Contains(err.Error(), "error restoring overlay") {
		t.Fatalf("expected a combined error with a failed restore, got: %v", err)
	}

	// The revert could not complete: the overlay regenerated from the
	// snapshot stayed in the moved dir.
	conf, readErr := os.ReadFile(filepath.Join(env.managedDir+"-moved", "waf-api_example_com.conf"))
	if readErr != nil {
		t.Fatalf("the overlay with the restored content must be preserved in the moved dir: %v", readErr)
	}
	if strings.Contains(string(conf), oldWAFContent) {
		t.Errorf("if the restore fails, the overlay must keep the restored content:\n%s", conf)
	}
	if !strings.Contains(string(conf), "SecRuleEngine Off") {
		t.Errorf("the moved overlay must contain the restored snapshot's mode:\n%s", conf)
	}
	if !strings.Contains(audit.String(), "rollback_changed_but_reload_failed") || !strings.Contains(audit.String(), "(restore error:") {
		t.Errorf("expected audit with restore error:\n%s", audit.String())
	}
}

// TestDeployContractCustomManagedDirs (finding J5-1): the generated overlay
// must NOT carry the exclusions Include hardcoded to /etc/caddy/ui-managed.
// With custom CADDY_UI_MANAGED_DIR and CADDY_UI_INCLUDE_DIR, the overlay must
// reference the configured include directory (the Caddy view of the volume):
// a deployment with custom dirs stops breaking in silence.
func TestDeployContractCustomManagedDirs(t *testing.T) {
	env := setupChainEnv(t, false)
	t.Setenv("CADDY_UI_INCLUDE_DIR", "/etc/caddy/custom-managed")
	if err := service.UpdateWAFMode("api.example.com", domain.ModeOn, ""); err != nil {
		t.Fatal(err)
	}
	conf, err := os.ReadFile(filepath.Join(env.managedDir, "waf-api_example_com.conf"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(conf), "Include /etc/caddy/ui-managed") {
		t.Fatal("embedded exclusions must not reference a hardcoded mount")
	}
	if env.admin.calls != 1 {
		t.Fatalf("expected one reload, got %d", env.admin.calls)
	}
}
