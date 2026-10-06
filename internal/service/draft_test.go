package service_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/developmi/caddy-waf-ui/internal/domain"
	"github.com/developmi/caddy-waf-ui/internal/files"
	"github.com/developmi/caddy-waf-ui/internal/service"
	"github.com/developmi/caddy-waf-ui/internal/waf"
)

func TestReviewedDraftRejectsEditedIntentAndChangedBaseline(t *testing.T) {
	env := setupChainEnv(t, false)
	if err := service.ApplyMode(service.Actor{}, "example.com", domain.ModeDetectionOnly); err != nil {
		t.Fatal(err)
	}
	p := waf.DefaultPolicy()
	p.DetectionPL = 2
	draft, err := service.CreatePolicyDraft("example.com", p)
	if err != nil {
		t.Fatal(err)
	}
	edited := p
	edited.InboundThreshold = 10
	if err := service.ApplyPolicyDraft(service.Actor{}, "example.com", edited, draft.DraftID); !errors.Is(err, service.ErrStaleDraft) {
		t.Fatalf("edited intent accepted: %v", err)
	}
	path := files.WAFConfigPath(env.managedDir, "example.com")
	b, _ := os.ReadFile(path)
	if err := os.WriteFile(path, append(b, []byte("\n# external edit\n")...), 0600); err != nil {
		t.Fatal(err)
	}
	calls := env.admin.calls
	if err := service.ApplyPolicyDraft(service.Actor{}, "example.com", p, draft.DraftID); !errors.Is(err, service.ErrStaleDraft) {
		t.Fatalf("stale baseline accepted: %v", err)
	}
	if env.admin.calls != calls {
		t.Fatal("stale draft must not reload")
	}
	draft, err = service.CreatePolicyDraft("example.com", p)
	if err != nil {
		t.Fatal(err)
	}
	if err := service.ApplyPolicyDraft(service.Actor{Reason: "reviewed change"}, "example.com", p, draft.DraftID); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(path)
	if string(got) != draft.Content {
		t.Fatal("applied configuration differs from reviewed artifact")
	}
}

func TestFailedOriginProbeRestoresFilesAndLiveConfiguration(t *testing.T) {
	env := setupChainEnv(t, false)
	if err := service.ApplyMode(service.Actor{}, "example.com", domain.ModeDetectionOnly); err != nil {
		t.Fatal(err)
	}
	path := files.WAFConfigPath(env.managedDir, "example.com")
	before, _ := os.ReadFile(path)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(503) }))
	defer origin.Close()
	t.Setenv("CADDY_UI_PROBE_URLS", `{"example.com":"`+origin.URL+`"}`)
	calls := env.admin.calls
	if err := service.ApplyMode(service.Actor{}, "example.com", domain.ModeOn); err == nil {
		t.Fatal("failed request accepted")
	}
	after, _ := os.ReadFile(path)
	if string(before) != string(after) {
		t.Fatal("failed candidate left on disk")
	}
	if env.admin.calls != calls+2 {
		t.Fatalf("expected candidate and compensating reload, got %d", env.admin.calls-calls)
	}
}
