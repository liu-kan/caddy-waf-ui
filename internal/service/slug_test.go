package service_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/developmi/caddy-waf-ui/internal/domain"
	"github.com/developmi/caddy-waf-ui/internal/files"
	"github.com/developmi/caddy-waf-ui/internal/iprules"
	"github.com/developmi/caddy-waf-ui/internal/service"
	"github.com/developmi/caddy-waf-ui/internal/waf"
)

// TestSlugConflictIsRejected: DomainSlug maps "." and "-" to "_", so
// a-b.example.com and a.b.example.com share overlay and snapshot names. A
// change to the second domain must be refused instead of overwriting the
// first one's configuration.
func TestSlugConflictIsRejected(t *testing.T) {
	env := setupChainEnv(t, false)
	if err := service.ApplyMode(service.Actor{}, "a.b.example.com", domain.ModeOn); err != nil {
		t.Fatal(err)
	}
	if err := service.ApplyIPRules(service.Actor{}, "a.b.example.com", iprules.IPRules{Denylist: []string{"192.0.2.1"}}); err != nil {
		t.Fatal(err)
	}
	wafPath := files.WAFConfigPath(env.managedDir, "a.b.example.com")
	before, _ := os.ReadFile(wafPath)
	calls := env.admin.calls

	attempts := map[string]func() error{
		"mode":       func() error { return service.ApplyMode(service.Actor{}, "a-b.example.com", domain.ModeOff) },
		"policy":     func() error { return service.ApplyPolicy(service.Actor{}, "a-b.example.com", waf.DefaultPolicy()) },
		"exclusions": func() error { return service.ApplyExclusions(service.Actor{}, "a-b.example.com", nil) },
		"iprules":    func() error { return service.ApplyIPRules(service.Actor{}, "a-b.example.com", iprules.IPRules{}) },
		"draft": func() error {
			_, err := service.CreatePolicyDraft("a-b.example.com", waf.DefaultPolicy())
			return err
		},
	}
	for name, attempt := range attempts {
		if err := attempt(); !errors.Is(err, service.ErrSlugConflict) {
			t.Errorf("%s: expected ErrSlugConflict, got %v", name, err)
		}
	}
	if after, _ := os.ReadFile(wafPath); string(after) != string(before) {
		t.Fatal("the conflicting domain overwrote the other site's overlay")
	}
	if env.admin.calls != calls {
		t.Fatal("a refused change must not reload Caddy")
	}
	if err := service.ApplyMode(service.Actor{}, "A.B.example.com", domain.ModeOn); err != nil {
		t.Fatalf("the same domain in another letter case is not a conflict: %v", err)
	}
}

// TestInitializeRejectsCollidingSites: two configured sites that share file
// names cannot both be initialized.
func TestInitializeRejectsCollidingSites(t *testing.T) {
	env := setupChainEnv(t, false)
	t.Setenv("CADDY_UI_INCLUDE_DIR", "/etc/caddy/ui-managed")
	err := service.Initialize([]string{"a.b.example.com", "a-b.example.com"})
	if !errors.Is(err, service.ErrSlugConflict) {
		t.Fatalf("expected ErrSlugConflict, got %v", err)
	}
	if _, err := os.Stat(filepath.Join(env.managedDir, "waf-a_b_example_com.conf")); err != nil {
		t.Fatalf("the first site keeps its overlay: %v", err)
	}
}
