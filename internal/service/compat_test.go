package service_test

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/developmi/caddy-waf-ui/internal/domain"
	"github.com/developmi/caddy-waf-ui/internal/service"
	"github.com/developmi/caddy-waf-ui/internal/waf"
)

func readManaged(t *testing.T, dir, name string) []byte {
	t.Helper()
	content, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		t.Fatal(err)
	}
	return content
}

func TestExclusionUpdateAndRollbackRefreshDerivedWAF(t *testing.T) {
	env := setupChainEnv(t, false)
	if err := service.UpdateWAFMode("api.example.com", domain.ModeOn, ""); err != nil {
		t.Fatal(err)
	}
	oldWAF := readManaged(t, env.managedDir, "waf-api_example_com.conf")
	oldExclusions, err := waf.GenerateExclusions(&domain.Site{Domain: "api.example.com"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	seedBackupSnapshot(t, env.backupDir, "api_example_com", "2020-01-01T00-00-00Z.exclusions.conf", string(oldExclusions))
	if err := service.UpdateExclusions("api.example.com", []waf.Exclusion{{Type: waf.ExcludeByID, Value: "942100"}}, ""); err != nil {
		t.Fatal(err)
	}
	updated := readManaged(t, env.managedDir, "waf-api_example_com.conf")
	if bytes.Equal(updated, oldWAF) || !strings.Contains(string(updated), "SecRuleRemoveById 942100") || !strings.Contains(string(updated), "SecRuleEngine On") {
		t.Fatalf("exclusion update did not reach the WAF directives while preserving On mode:\n%s", updated)
	}
	if err := service.Rollback("api.example.com", "2020-01-01T00-00-00Z.exclusions.conf", ""); err != nil {
		t.Fatal(err)
	}
	restored := readManaged(t, env.managedDir, "waf-api_example_com.conf")
	if bytes.Equal(updated, restored) || strings.Contains(string(restored), "SecRuleRemoveById 942100") {
		t.Fatal("rollback must refresh the WAF directives and revision")
	}
}

func TestRejectedExclusionUpdateRestoresBothFiles(t *testing.T) {
	env := setupChainEnv(t, false)
	if err := service.UpdateWAFMode("api.example.com", domain.ModeOn, ""); err != nil {
		t.Fatal(err)
	}
	if err := service.UpdateExclusions("api.example.com", []waf.Exclusion{{Type: waf.ExcludeByID, Value: "941100"}}, ""); err != nil {
		t.Fatal(err)
	}
	oldWAF := readManaged(t, env.managedDir, "waf-api_example_com.conf")
	oldExclusions := readManaged(t, env.managedDir, "exclusions-api_example_com.conf")
	env.admin.fail = true
	if err := service.UpdateExclusions("api.example.com", []waf.Exclusion{{Type: waf.ExcludeByID, Value: "942100"}}, ""); err == nil {
		t.Fatal("expected rejected reload")
	}
	if !bytes.Equal(oldWAF, readManaged(t, env.managedDir, "waf-api_example_com.conf")) ||
		!bytes.Equal(oldExclusions, readManaged(t, env.managedDir, "exclusions-api_example_com.conf")) {
		t.Fatal("partial WAF/exclusion update survived a failed reload")
	}
}

func TestWAFRollbackKeepsCurrentCanonicalExclusions(t *testing.T) {
	env := setupChainEnv(t, false)
	if err := service.UpdateWAFMode("api.example.com", domain.ModeDetectionOnly, ""); err != nil {
		t.Fatal(err)
	}
	old := readManaged(t, env.managedDir, "waf-api_example_com.conf")
	seedBackupSnapshot(t, env.backupDir, "api_example_com", "2020-01-01T00-00-00Z.waf.conf", string(old))
	if err := service.UpdateWAFMode("api.example.com", domain.ModeOn, ""); err != nil {
		t.Fatal(err)
	}
	if err := service.UpdateExclusions("api.example.com", []waf.Exclusion{{Type: waf.ExcludeByID, Value: "942100"}}, ""); err != nil {
		t.Fatal(err)
	}
	if err := service.Rollback("api.example.com", "2020-01-01T00-00-00Z.waf.conf", ""); err != nil {
		t.Fatal(err)
	}
	restored := string(readManaged(t, env.managedDir, "waf-api_example_com.conf"))
	if !strings.Contains(restored, "SecRuleEngine DetectionOnly") || !strings.Contains(restored, "SecRuleRemoveById 942100") {
		t.Fatal("WAF rollback desynchronized the independent exclusion list")
	}
}

func TestReadbackFailureRestoresLiveConfiguration(t *testing.T) {
	env := setupChainEnv(t, false)
	seedWAFOverlay(t, env.managedDir, "example.com", oldWAFContent)
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			calls++
			if calls == 2 && !bytes.Equal(readManaged(t, env.managedDir, "waf-example_com.conf"), []byte(oldWAFContent)) {
				t.Error("compensating reload happened before restoring the file")
			}
			return
		}
		if calls == 1 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		_, _ = w.Write([]byte(`{"srv0":{"routes":[{"match":[{"host":["example.com"]}]}]}}`))
	}))
	defer server.Close()
	t.Setenv("CADDY_ADMIN_URL", server.URL)
	if err := service.UpdateWAFMode("example.com", domain.ModeOn, ""); err == nil {
		t.Fatal("verification failure must be returned")
	}
	if calls != 2 {
		t.Fatalf("expected a compensating reload, got %d POSTs", calls)
	}
}

func TestInitializeSeedsActiveWAFAndPreservesExistingConfiguration(t *testing.T) {
	env := setupChainEnv(t, false)
	source := "example.com {\n import /etc/caddy/ui-managed/waf-example_com.conf\n import /etc/caddy/ui-managed/ip-rules-example_com.conf\n}\n"
	if err := os.WriteFile(os.Getenv("CADDY_UI_CADDYFILE"), []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	if err := service.Initialize([]string{"example.com"}); err != nil {
		t.Fatal(err)
	}
	first := readManaged(t, env.managedDir, "waf-example_com.conf")
	if !strings.Contains(string(first), "load_owasp_crs") || !strings.Contains(string(first), "SecRuleEngine DetectionOnly") {
		t.Fatal("first boot must create a real WAF configuration")
	}
	if err := service.Initialize([]string{"example.com"}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, readManaged(t, env.managedDir, "waf-example_com.conf")) {
		t.Fatal("initialization overwrote an existing WAF")
	}
	if err := service.Initialize([]string{"../bad"}); err == nil {
		t.Fatal("invalid initialization domain accepted")
	}
	if err := os.WriteFile(os.Getenv("CADDY_UI_CADDYFILE"), []byte(source+"\nother.example.com {\n import /etc/caddy/ui-managed/waf-other_example_com.conf\n}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := service.Initialize([]string{"example.com"}); err == nil {
		t.Fatal("missing domain import must prevent startup")
	}
	if env.admin.calls != 0 {
		t.Fatal("offline initialization must not call the Admin API")
	}
}
