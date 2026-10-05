package caddy_test

import (
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/developmi/caddy-waf-ui/internal/caddy"
)

func TestReloadOverUnixSocket(t *testing.T) {
	dir, err := os.MkdirTemp("", "waf-sock-")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(dir) }()
	socket := filepath.Join(dir, "admin.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{ReadHeaderTimeout: time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != "localhost" {
			t.Errorf("Unix request must use a permitted Caddy origin, got %s", r.Host)
		}
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(`{"srv0":{"routes":[{"match":[{"host":["example.com"]}]}]}}`))
		}
	})}
	go func() { _ = server.Serve(listener) }()
	defer func() { _ = server.Close() }()
	source := filepath.Join(dir, "Caddyfile")
	if err := os.WriteFile(source, []byte("example.com {\n}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CADDY_ADMIN_URL", "unix://"+socket)
	t.Setenv("CADDY_UI_CADDYFILE", source)
	if err := caddy.Reload(); err != nil {
		t.Fatal(err)
	}
}
