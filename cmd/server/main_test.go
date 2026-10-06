package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/developmi/caddy-waf-ui/internal/events"
	"github.com/developmi/caddy-waf-ui/internal/ipgroups"
	"github.com/developmi/caddy-waf-ui/internal/metrics"
	"github.com/developmi/caddy-waf-ui/internal/service"
)

// TestNewServerBounds (SH-1): the newServer constructor must set the four
// HTTP server limits: ReadHeaderTimeout 5s (slowloris, G114; kept),
// WriteTimeout 30s (covers the 2x10s Caddy admin chain), IdleTimeout 60s
// (margin over the 30s healthcheck) and MaxHeaderBytes 1 MiB. It must also
// propagate as-is the listening address and the assembled handler (it does
// not assemble muxes: that stays in main()).
func TestNewServerBounds(t *testing.T) {
	addr := "127.0.0.1:18099"
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	srv := newServer(addr, handler)

	if srv.Addr != addr {
		t.Errorf("Addr: expected %q, got %q", addr, srv.Addr)
	}
	if srv.Handler == nil {
		t.Error("Handler: it cannot be nil, it must propagate the received handler")
	}
	if srv.ReadHeaderTimeout != 5*time.Second {
		t.Errorf("ReadHeaderTimeout: expected 5s, got %v", srv.ReadHeaderTimeout)
	}
	if srv.WriteTimeout != 30*time.Second {
		t.Errorf("WriteTimeout: expected 30s, got %v", srv.WriteTimeout)
	}
	if srv.IdleTimeout != 60*time.Second {
		t.Errorf("IdleTimeout: expected 60s, got %v", srv.IdleTimeout)
	}
	if srv.MaxHeaderBytes != 1<<20 {
		t.Errorf("MaxHeaderBytes: expected 1 MiB (%d), got %d", 1<<20, srv.MaxHeaderBytes)
	}
}

func TestBuildHandler(t *testing.T) {
	h := buildHandler()
	if h == nil {
		t.Fatal("buildHandler() returned nil")
	}

	tests := []struct {
		name       string
		method     string
		target     string
		wantStatus int
	}{
		{
			name:       "health endpoint",
			method:     http.MethodGet,
			target:     "/health",
			wantStatus: http.StatusOK,
		},
		{
			name:       "login page",
			method:     http.MethodGet,
			target:     "/login",
			wantStatus: http.StatusOK,
		},
		{
			name:       "static css asset",
			method:     http.MethodGet,
			target:     "/static/app.css",
			wantStatus: http.StatusOK,
		},
		{
			name:       "unauthenticated api access",
			method:     http.MethodGet,
			target:     "/api/overview",
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "unauthenticated root redirect to login",
			method:     http.MethodGet,
			target:     "/",
			wantStatus: http.StatusFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.target, nil)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)

			if rec.Code != tt.wantStatus {
				t.Errorf("%s %s: expected status %d, got %d", tt.method, tt.target, tt.wantStatus, rec.Code)
			}
			// Verify security headers wrapped by ui.SecurityHeaders
			if rec.Header().Get("X-Content-Type-Options") != "nosniff" {
				t.Errorf("expected X-Content-Type-Options: nosniff, got %q", rec.Header().Get("X-Content-Type-Options"))
			}
		})
	}
}

func TestRun(t *testing.T) {
	called := false
	err := run(func(srv *http.Server) error {
		called = true
		if srv == nil {
			t.Fatal("expected non-nil server")
		}
		if srv.Handler == nil {
			t.Fatal("expected non-nil server handler")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("run failed: %v", err)
	}
	if !called {
		t.Error("expected serve callback to be invoked")
	}
}

func TestInvalidPrivacySettingsPreventStartup(t *testing.T) {
	t.Setenv("CADDY_UI_REDACTION_LOCAL", "typo")
	called := false
	if err := run(func(*http.Server) error { called = true; return nil }); err == nil || called {
		t.Fatal("invalid privacy configuration silently started")
	}
}

func TestExportQueueCanBeDisabled(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("CADDY_UI_DATA_DIR", dir)
	store, err := events.OpenStore(filepath.Join(dir, "events"), time.Hour, 10)
	if err != nil {
		t.Fatal(err)
	}
	settings := events.RedactionSettings{Local: events.Redaction{Level: events.LevelStandard}}
	t.Setenv("CADDY_UI_CLOUD_EXPORT", "true")
	cloud, err := openExportQueue(store, settings, time.Hour)
	if err != nil || cloud == nil {
		t.Fatalf("export queue: %v", err)
	}
	marker := filepath.Join(dir, "cloud", "bootstrap.done")
	if _, err := os.Stat(marker); err != nil {
		t.Fatal("the first export start must record the migration")
	}
	t.Setenv("CADDY_UI_CLOUD_EXPORT", "false")
	if cloud, err := openExportQueue(store, settings, time.Hour); err != nil || cloud != nil {
		t.Fatalf("disabled export must not open a queue: %v %v", cloud, err)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("disabling export must reset the migration so re-enabling queues retained events again")
	}
}

func TestIPGroupGauges(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "office.txt"), []byte("192.0.2.0/24\n198.51.100.0/24\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	reg, err := ipgroups.Open(ipgroups.Options{StateDir: filepath.Join(dir, "state"), ListDir: filepath.Join(dir, "lists"), CaddyDir: "/lists", SourceDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reg.Put(t.Context(), ipgroups.Definition{Name: "office", Source: ipgroups.SourceFile, File: "office.txt"}); err != nil {
		t.Fatal(err)
	}
	service.SetIPGroups(reg)
	t.Cleanup(func() { service.SetIPGroups(nil) })
	ipGroupGauges.Do(registerIPGroupGauges)
	var out strings.Builder
	if err := metrics.Default.Render(&out); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`waf_ipgroup_prefixes{group="office"} 2`, `waf_ipgroup_error{group="office"} 0`, `waf_ipgroup_pending{group="office"} 0`} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("metrics miss %q:\n%s", want, out.String())
		}
	}
}
