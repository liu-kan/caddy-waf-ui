package service_test

import (
	"errors"
	"testing"

	"github.com/developmi/caddy-waf-ui/internal/iprules"
	"github.com/developmi/caddy-waf-ui/internal/service"
	"github.com/developmi/caddy-waf-ui/internal/waf"
)

// TestReadModifyWriteDetectsConcurrentChanges: the forms read the current
// list, add or remove one entry and send the whole list back. A change that
// lands between the read and the apply must be reported as a conflict, not
// silently overwritten (lost update).
func TestReadModifyWriteDetectsConcurrentChanges(t *testing.T) {
	env := setupChainEnv(t, false)
	if err := service.ApplyIPRules(service.Actor{}, "example.com", iprules.IPRules{Denylist: []string{"192.0.2.1"}}); err != nil {
		t.Fatal(err)
	}
	base, err := service.Baseline("example.com")
	if err != nil {
		t.Fatal(err)
	}
	// Another administrator adds an entry after our read.
	if err := service.ApplyIPRules(service.Actor{}, "example.com", iprules.IPRules{Denylist: []string{"192.0.2.1", "192.0.2.2"}}); err != nil {
		t.Fatal(err)
	}
	calls := env.admin.calls
	stale := iprules.IPRules{Denylist: []string{"192.0.2.1", "198.51.100.7"}}
	if err := service.ApplyIPRulesAt(service.Actor{}, "example.com", stale, base); !errors.Is(err, service.ErrConflict) {
		t.Fatalf("IP rules: expected ErrConflict, got %v", err)
	}
	if err := service.ApplyExclusionsAt(service.Actor{}, "example.com", []waf.Exclusion{{Type: waf.ExcludeByID, Value: "941100"}}, base); !errors.Is(err, service.ErrConflict) {
		t.Fatalf("exclusions: expected ErrConflict, got %v", err)
	}
	if env.admin.calls != calls {
		t.Fatal("a conflicting change must not reload Caddy")
	}

	fresh, err := service.Baseline("example.com")
	if err != nil {
		t.Fatal(err)
	}
	if err := service.ApplyIPRulesAt(service.Actor{}, "example.com", iprules.IPRules{Denylist: []string{"192.0.2.1", "192.0.2.2", "198.51.100.7"}}, fresh); err != nil {
		t.Fatalf("an up-to-date change must apply: %v", err)
	}
}
