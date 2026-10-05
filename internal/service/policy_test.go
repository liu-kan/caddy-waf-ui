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
	"github.com/developmi/caddy-waf-ui/internal/journal"
	"github.com/developmi/caddy-waf-ui/internal/service"
	"github.com/developmi/caddy-waf-ui/internal/waf"
)

func TestApplyPolicyKeepsModeAndExclusionsAndJournals(t *testing.T) {
	env := setupChainEnv(t, false)
	actor := service.Actor{RemoteIP: "192.0.2.1", User: "alice", Reason: "collect PL2 data"}
	if err := service.ApplyMode(actor, "api.example.com", domain.ModeOn); err != nil {
		t.Fatal(err)
	}
	if err := service.ApplyExclusions(actor, "api.example.com", []waf.Exclusion{{Type: waf.ExcludeByID, Value: "942100", Param: "q"}}); err != nil {
		t.Fatal(err)
	}
	policy := waf.Policy{BlockingPL: 1, DetectionPL: 2, Tuning: true}
	if err := service.ApplyPolicy(actor, "api.example.com", policy); err != nil {
		t.Fatal(err)
	}
	state, err := service.ReadSiteState("api.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if state.Mode != domain.ModeOn || state.Policy.DetectionPL != 2 || !state.Policy.Tuning || len(state.Exclusions) != 1 || state.Revision == "" {
		t.Fatalf("state: %+v", state)
	}
	conf := string(readManaged(t, env.managedDir, "waf-api_example_com.conf"))
	for _, want := range []string{"SecRuleEngine On", `SecRuleUpdateTargetById 942100 "!ARGS:q"`, "ctl:auditEngine=On",
		"setvar:tx.detection_paranoia_level=2", "site=api.example.com;rev=" + state.Revision} {
		if !strings.Contains(conf, want) {
			t.Errorf("overlay misses %q", want)
		}
	}
	entries, err := journal.List(journal.Filter{Site: "api.example.com"})
	if err != nil || len(entries) != 3 {
		t.Fatalf("journal: %+v %v", entries, err)
	}
	last := entries[0]
	if last.Action != "policy" || last.Actor != "alice" || last.Reason != "collect PL2 data" || last.Revision != state.Revision ||
		last.Result != journal.ResultSuccess || !strings.Contains(last.Diff, "detection_paranoia_level=2") {
		t.Fatalf("policy entry: %+v", last)
	}
	if !strings.Contains(entries[2].Summary, "unknown → On") {
		t.Fatalf("mode entry: %+v", entries[2])
	}
}

func TestApplyPolicyRejectsInvalidBeforeMutating(t *testing.T) {
	env := setupChainEnv(t, false)
	err := service.ApplyPolicy(service.Actor{}, "api.example.com", waf.Policy{BlockingPL: 3, DetectionPL: 2})
	if !errors.Is(err, service.ErrInvalidPolicy) {
		t.Fatalf("expected ErrInvalidPolicy, got %v", err)
	}
	if env.admin.calls != 0 || snapshotCount(t, env.backupDir, "api_example_com", "waf") != 0 {
		t.Fatal("invalid policies must not back up or reload")
	}
	if err := service.ApplyPolicy(service.Actor{}, "../x", waf.DefaultPolicy()); !errors.Is(err, service.ErrInvalidDomain) {
		t.Fatalf("expected ErrInvalidDomain, got %v", err)
	}
}

func TestReloadWithoutRevisionInLiveConfigRestores(t *testing.T) {
	env := setupChainEnv(t, false)
	if err := service.ApplyMode(service.Actor{}, "api.example.com", domain.ModeDetectionOnly); err != nil {
		t.Fatal(err)
	}
	before := readManaged(t, env.managedDir, "waf-api_example_com.conf")
	posts := 0
	// Caddy accepted the load but its live config does not contain the new
	// overlay (not imported, or a stale bind-mounted file).
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			posts++
			return
		}
		_, _ = w.Write([]byte(`{"srv0":{"routes":[{"match":[{"host":["example.com"]}]}]}}`))
	}))
	defer server.Close()
	t.Setenv("CADDY_ADMIN_URL", server.URL)
	err := service.ApplyMode(service.Actor{}, "api.example.com", domain.ModeOn)
	if err == nil || !strings.Contains(err.Error(), "WAF revision") {
		t.Fatalf("missing revision must fail verification: %v", err)
	}
	if posts != 2 {
		t.Fatalf("expected the load plus a compensating reload, got %d", posts)
	}
	if string(readManaged(t, env.managedDir, "waf-api_example_com.conf")) != string(before) {
		t.Fatal("the previous overlay must be restored")
	}
	entries, _ := journal.List(journal.Filter{Site: "api.example.com"})
	if len(entries) == 0 || entries[0].Result != journal.ResultFailed || !strings.Contains(entries[0].Error, "WAF revision") {
		t.Fatalf("the failure must be journaled: %+v", entries)
	}
}

func TestPreviewsDoNotWrite(t *testing.T) {
	env := setupChainEnv(t, false)
	if err := service.ApplyMode(service.Actor{}, "api.example.com", domain.ModeOn); err != nil {
		t.Fatal(err)
	}
	before := readManaged(t, env.managedDir, "waf-api_example_com.conf")
	p, err := service.PreviewPolicy("api.example.com", waf.Policy{BlockingPL: 2})
	if err != nil || !strings.Contains(p.Diff, "+ ") || !strings.Contains(p.Diff, "blocking_paranoia_level=2") {
		t.Fatalf("policy preview: %+v %v", p, err)
	}
	x, err := service.PreviewExclusions("api.example.com", []waf.Exclusion{{Type: waf.ExcludeByID, Value: "930130", Path: "/.well-known/"}})
	if err != nil || !strings.Contains(x.Diff, "ruleRemoveById=930130") {
		t.Fatalf("exclusion preview: %+v %v", x, err)
	}
	if _, err := service.PreviewExclusions("api.example.com", []waf.Exclusion{{Type: waf.ExcludeByID, Value: "949110"}}); err == nil {
		t.Fatal("previews validate like changes")
	}
	if string(readManaged(t, env.managedDir, "waf-api_example_com.conf")) != string(before) || env.admin.calls != 1 {
		t.Fatal("previews must not write or reload")
	}
	if _, err := os.Stat(filepath.Join(env.managedDir, "exclusions-api_example_com.conf")); !os.IsNotExist(err) {
		t.Fatal("previews must not create the exclusions file")
	}
}

func TestWAFRollbackRestoresPolicy(t *testing.T) {
	env := setupChainEnv(t, false)
	if err := service.ApplyPolicy(service.Actor{}, "api.example.com", waf.Policy{BlockingPL: 2, InboundThreshold: 8}); err != nil {
		t.Fatal(err)
	}
	snapshot := readManaged(t, env.managedDir, "waf-api_example_com.conf")
	seedBackupSnapshot(t, env.backupDir, "api_example_com", "2020-01-01T00-00-00Z.waf.conf", string(snapshot))
	if err := service.ApplyPolicy(service.Actor{}, "api.example.com", waf.DefaultPolicy()); err != nil {
		t.Fatal(err)
	}
	if err := service.Rollback("api.example.com", "2020-01-01T00-00-00Z.waf.conf", ""); err != nil {
		t.Fatal(err)
	}
	state, _ := service.ReadSiteState("api.example.com")
	if state.Policy.BlockingPL != 2 || state.Policy.InboundThreshold != 8 {
		t.Fatalf("rollback must restore the snapshot's policy: %+v", state.Policy)
	}
	if string(readManaged(t, env.managedDir, "waf-api_example_com.conf")) == string(snapshot) {
		t.Fatal("the restored overlay gets a fresh revision")
	}
}

func TestReadSiteStateDefaultsAndLegacyExclusions(t *testing.T) {
	env := setupChainEnv(t, false)
	state, err := service.ReadSiteState("new.example.com")
	if err != nil || state.HasWAF || state.Mode != domain.ModeDetectionOnly || state.Policy.InboundThreshold != 5 {
		t.Fatalf("defaults: %+v %v", state, err)
	}
	legacy := "SecRule ARGS:q \"@unconditionalMatch\" \"id:9000001,phase:2,pass,nolog,ctl:ruleRemoveById=942100\"\n"
	if err := os.WriteFile(filepath.Join(env.managedDir, "exclusions-new_example_com.conf"), []byte(legacy), 0o640); err != nil {
		t.Fatal(err)
	}
	state, err = service.ReadSiteState("new.example.com")
	if err != nil || len(state.Exclusions) != 1 || state.Exclusions[0].Param != "q" {
		t.Fatalf("legacy exclusions: %+v %v", state.Exclusions, err)
	}
	if err := os.WriteFile(filepath.Join(env.managedDir, "exclusions-new_example_com.conf"), []byte("SecRuleEngine Off\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := service.ReadSiteState("new.example.com"); err == nil {
		t.Fatal("unknown directives in the canonical file must be reported")
	}
	if summary := service.PolicySummary(waf.Policy{BlockingPL: 2, Tuning: true, EarlyBlocking: true, DisabledGroups: []string{"933"}}); summary != "PL 2 (detect 2), thresholds 5/4, tuning, early blocking, disabled 933" {
		t.Fatalf("summary: %q", summary)
	}
}
