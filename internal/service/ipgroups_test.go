package service_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/developmi/caddy-waf-ui/internal/domain"
	"github.com/developmi/caddy-waf-ui/internal/files"
	"github.com/developmi/caddy-waf-ui/internal/ipgroups"
	"github.com/developmi/caddy-waf-ui/internal/journal"
	"github.com/developmi/caddy-waf-ui/internal/service"
	"github.com/developmi/caddy-waf-ui/internal/waf"
)

type groupEnv struct {
	*chainEnv
	sources string
	reg     *ipgroups.Registry
}

func setupGroupEnv(t *testing.T) *groupEnv {
	t.Helper()
	env := &groupEnv{chainEnv: setupChainEnv(t, false), sources: t.TempDir()}
	reg, err := ipgroups.Open(ipgroups.Options{
		StateDir: filepath.Join(t.TempDir(), "state"), ListDir: filepath.Join(env.managedDir, "ipgroups"),
		CaddyDir: "/etc/caddy/ui-managed/ipgroups", SourceDir: env.sources,
	})
	if err != nil {
		t.Fatal(err)
	}
	env.reg = reg
	service.SetIPGroups(reg)
	t.Cleanup(func() { service.SetIPGroups(nil) })
	return env
}

func (env *groupEnv) writeSource(t *testing.T, name, content string, at time.Time) {
	t.Helper()
	path := filepath.Join(env.sources, name)
	if err := os.WriteFile(path, []byte(content), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, at, at); err != nil {
		t.Fatal(err)
	}
}

func overlay(t *testing.T, env *groupEnv) string {
	t.Helper()
	b, err := os.ReadFile(files.WAFConfigPath(env.managedDir, "example.com"))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestIPGroupPolicyLifecycle(t *testing.T) {
	env := setupGroupEnv(t)
	actor := service.Actor{User: "ops", Reason: "test"}
	env.writeSource(t, "office.txt", "192.0.2.0/24\n", time.Now().Add(-time.Hour))
	g, err := service.PutIPGroup(context.Background(), actor, ipgroups.Definition{Name: "office", Source: ipgroups.SourceFile, File: "office.txt"})
	if err != nil || g.Active == nil {
		t.Fatalf("put: %+v %v", g, err)
	}
	if err := service.ApplyMode(actor, "example.com", domain.ModeDetectionOnly); err != nil {
		t.Fatal(err)
	}
	p := waf.DefaultPolicy()
	p.IPGroups = []waf.IPGroupRule{{Groups: []string{"nowhere"}, Action: waf.GroupBlock}}
	if err := service.ApplyPolicy(actor, "example.com", p); err == nil {
		t.Fatal("a rule for an unknown group must be rejected")
	}
	p.IPGroups = []waf.IPGroupRule{{Groups: []string{"office"}, Action: waf.GroupEngine, Engine: "Off"}}
	if err := service.ApplyPolicy(actor, "example.com", p); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(overlay(t, env), "@ipMatchFromFile /etc/caddy/ui-managed/ipgroups/"+g.Active.File) {
		t.Fatal("the overlay must reference the active list")
	}
	if sites, err := service.IPGroupUsage("office"); err != nil || len(sites) != 1 || sites[0] != "example.com" {
		t.Fatalf("usage: %v %v", sites, err)
	}

	// A changed list is published to every site that uses the group.
	calls := env.admin.calls
	env.writeSource(t, "office.txt", "192.0.2.0/24\n198.51.100.0/24\n", time.Now())
	changed, err := service.RefreshIPGroup(context.Background(), actor, "office", false)
	if err != nil || !changed {
		t.Fatalf("refresh: %v %v", changed, err)
	}
	g2, _ := env.reg.Get("office")
	if g2.Active.File == g.Active.File || !strings.Contains(overlay(t, env), g2.Active.File) || env.admin.calls == calls {
		t.Fatal("the new list must be published to the sites using the group")
	}
	entries, err := journal.List(journal.Filter{Site: "example.com", Limit: 5})
	if err != nil || len(entries) == 0 || entries[0].Action != "ipgroup" || !strings.Contains(entries[0].Summary, "office") {
		t.Fatalf("journal: %+v %v", entries, err)
	}

	if err := service.DeleteIPGroup(actor, "office"); !errors.Is(err, service.ErrIPGroupInUse) {
		t.Fatalf("a group used by a policy cannot be deleted: %v", err)
	}
	p.IPGroups = nil
	if err := service.ApplyPolicy(actor, "example.com", p); err != nil {
		t.Fatal(err)
	}
	if err := service.DeleteIPGroup(actor, "office"); err != nil {
		t.Fatal(err)
	}
}

func TestMergedListFollowsItsMemberGroups(t *testing.T) {
	env := setupGroupEnv(t)
	actor := service.Actor{User: "ops", Reason: "test"}
	env.writeSource(t, "cn.txt", "203.0.113.0/25\n", time.Now().Add(-time.Hour))
	env.writeSource(t, "jp.txt", "203.0.113.128/25\n", time.Now().Add(-time.Hour))
	for _, name := range []string{"cn", "jp"} {
		if _, err := service.PutIPGroup(context.Background(), actor, ipgroups.Definition{Name: name, Source: ipgroups.SourceFile, File: name + ".txt"}); err != nil {
			t.Fatal(err)
		}
	}
	if err := service.ApplyMode(actor, "example.com", domain.ModeOn); err != nil {
		t.Fatal(err)
	}
	p := waf.DefaultPolicy()
	p.IPGroups = []waf.IPGroupRule{{Groups: []string{"jp", "cn"}, Negate: true, Action: waf.GroupBan}}
	if err := service.ApplyPolicy(actor, "example.com", p); err != nil {
		t.Fatal(err)
	}
	first, err := env.reg.ListPath([]string{"cn", "jp"})
	if err != nil || !strings.Contains(overlay(t, env), `"!@ipMatchFromFile `+first+`"`) || !strings.Contains(overlay(t, env), "ctl:auditEngine=Off") {
		t.Fatalf("the ban must match the merged list without recording: %q %v", first, err)
	}
	if _, err := os.Stat(filepath.Join(env.managedDir, "ipgroups", filepath.Base(first))); err != nil {
		t.Fatalf("the merged list must be written for Caddy: %v", err)
	}
	for _, name := range []string{"cn", "jp"} {
		if sites, err := service.IPGroupUsage(name); err != nil || len(sites) != 1 {
			t.Fatalf("%s usage: %v %v", name, sites, err)
		}
	}
	if err := service.DeleteIPGroup(actor, "jp"); !errors.Is(err, service.ErrIPGroupInUse) {
		t.Fatalf("a member of a rule cannot be deleted: %v", err)
	}

	// A new list of one member republishes the site with a new merged list.
	env.writeSource(t, "jp.txt", "203.0.113.128/25\n198.51.100.0/24\n", time.Now())
	if changed, err := service.RefreshIPGroup(context.Background(), actor, "jp", false); err != nil || !changed {
		t.Fatalf("refresh: %v %v", changed, err)
	}
	second, err := env.reg.ListPath([]string{"cn", "jp"})
	if err != nil || second == first || !strings.Contains(overlay(t, env), second) {
		t.Fatalf("the site must load the new merged list: %q %v", second, err)
	}
	if _, stale, err := service.IPGroupPublication(); err != nil || len(stale) != 0 {
		t.Fatalf("nothing is stale after publishing: %v %v", stale, err)
	}
}

func TestDraftIsStaleAfterAGroupListChanges(t *testing.T) {
	env := setupGroupEnv(t)
	env.writeSource(t, "a.txt", "192.0.2.0/24\n", time.Now().Add(-time.Hour))
	if _, err := service.PutIPGroup(context.Background(), service.Actor{}, ipgroups.Definition{Name: "a", Source: ipgroups.SourceFile, File: "a.txt"}); err != nil {
		t.Fatal(err)
	}
	if err := service.ApplyMode(service.Actor{}, "example.com", domain.ModeDetectionOnly); err != nil {
		t.Fatal(err)
	}
	p := waf.DefaultPolicy()
	p.IPGroups = []waf.IPGroupRule{{Groups: []string{"a"}, Action: waf.GroupTrial}}
	draft, err := service.CreatePolicyDraft("example.com", p)
	if err != nil {
		t.Fatal(err)
	}
	env.writeSource(t, "a.txt", "192.0.2.0/24\n203.0.113.0/24\n", time.Now())
	if _, err := service.RefreshIPGroup(context.Background(), service.Actor{}, "a", false); err != nil {
		t.Fatal(err)
	}
	if err := service.ApplyPolicyDraft(service.Actor{}, "example.com", p, draft.DraftID); !errors.Is(err, service.ErrStaleDraft) {
		t.Fatalf("a draft rendered with an older list must be reviewed again: %v", err)
	}
}

func TestGCIPGroupListsKeepsReferencedFiles(t *testing.T) {
	env := setupGroupEnv(t)
	env.writeSource(t, "a.txt", "192.0.2.0/24\n", time.Now().Add(-time.Hour))
	g, err := service.PutIPGroup(context.Background(), service.Actor{}, ipgroups.Definition{Name: "a", Source: ipgroups.SourceFile, File: "a.txt"})
	if err != nil {
		t.Fatal(err)
	}
	if err := service.ApplyMode(service.Actor{}, "example.com", domain.ModeDetectionOnly); err != nil {
		t.Fatal(err)
	}
	p := waf.DefaultPolicy()
	p.IPGroups = []waf.IPGroupRule{{Groups: []string{"a"}, Action: waf.GroupTrial}}
	if err := service.ApplyPolicy(service.Actor{}, "example.com", p); err != nil {
		t.Fatal(err)
	}
	// The overlay keeps referencing the first list after the group moves on,
	// for instance when publishing the new list failed.
	env.writeSource(t, "a.txt", "192.0.2.0/24\n198.51.100.0/24\n", time.Now())
	if _, err := env.reg.Refresh(context.Background(), "a", false); err != nil {
		t.Fatal(err)
	}
	stale := filepath.Join(env.managedDir, "ipgroups", "a.000000000000.txt")
	if err := os.WriteFile(stale, []byte("10.0.0.0/8\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-48 * time.Hour)
	for _, name := range []string{stale, filepath.Join(env.managedDir, "ipgroups", g.Active.File)} {
		if err := os.Chtimes(name, old, old); err != nil {
			t.Fatal(err)
		}
	}
	if err := service.GCIPGroupLists(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Fatal("unreferenced old lists must be removed")
	}
	if _, err := os.Stat(filepath.Join(env.managedDir, "ipgroups", g.Active.File)); err != nil {
		t.Fatal("a list referenced by an overlay must be kept")
	}
}
