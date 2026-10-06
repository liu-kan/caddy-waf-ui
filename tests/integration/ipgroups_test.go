package integration_test

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/developmi/caddy-waf-ui/internal/domain"
	"github.com/developmi/caddy-waf-ui/internal/ipgroups"
	"github.com/developmi/caddy-waf-ui/internal/service"
	"github.com/developmi/caddy-waf-ui/internal/waf"
)

// Opt-in: IP group rules rendered by the UI, evaluated by real Coraza with
// @ipMatchFromFile, including a sing-box .srs list and a list refresh.
func TestRealCaddyIPGroupRules(t *testing.T) {
	binary := os.Getenv("CADDY_TEST_BINARY")
	if binary == "" {
		t.Skip("set CADDY_TEST_BINARY to test a real Caddy/Coraza runtime")
	}
	tmp := t.TempDir()
	managed := filepath.Join(tmp, "managed")
	sources := filepath.Join(tmp, "sources")
	auditPath := filepath.Join(tmp, "coraza-audit.json")
	for _, dir := range []string{managed, sources} {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	write := func(path, content string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	srs, err := os.ReadFile(filepath.Join("..", "..", "internal", "ipgroups", "testdata", "ip.srs"))
	if err != nil {
		t.Fatal(err)
	}
	write(filepath.Join(sources, "scanners.srs"), string(srs)) // 203.0.113.0/24, 198.51.100.7, ...
	write(filepath.Join(sources, "office.txt"), "100.64.0.0/24\n")
	write(filepath.Join(sources, "partners.txt"), "10.10.0.0/16\n")
	write(filepath.Join(sources, "trial.txt"), "172.20.0.0/16\n")

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok") }))
	defer upstream.Close()
	appAddress, adminAddress := reserveAddress(t), reserveAddress(t)
	caddyfile := filepath.Join(tmp, "Caddyfile")
	write(caddyfile, fmt.Sprintf(`{
    auto_https off
    admin %s
    order coraza_waf first
    servers {
        trusted_proxies static 127.0.0.1/32
        trusted_proxies_strict
        client_ip_headers CF-Connecting-IP
    }
}
http://example.com:%s {
    route {
        import %s/ip-rules-example_com.conf
        import %s/waf-example_com.conf
        reverse_proxy %s
    }
}
`, adminAddress, strings.Split(appAddress, ":")[1], managed, managed, upstream.URL))
	for key, value := range map[string]string{
		"CADDY_UI_MANAGED_DIR": managed, "CADDY_UI_INCLUDE_DIR": managed,
		"CADDY_UI_BACKUP_DIR": filepath.Join(tmp, "backups"), "CADDY_UI_CADDYFILE": caddyfile,
		"CADDY_UI_DATA_DIR": filepath.Join(tmp, "ui-data"), "CADDY_UI_PROBE_URLS": "",
		"CADDY_ADMIN_URL": "http://" + adminAddress, "CADDY_UI_AUDIT_LOG": auditPath,
		"CADDY_UI_WAF_BEFORE_FILE": "", "CADDY_UI_WAF_AFTER_FILE": "",
		"CADDY_UI_CRS_MODE": "embedded", "CADDY_UI_RESPONSE_BODY_ACCESS": "Off", "CADDY_UI_AUDIT_LOG_PARTS": "AHKZ",
		"CADDY_UI_CORAZA_CONFIG": "", "CADDY_UI_CRS_SETUP": "", "CADDY_UI_CRS_RULES": "",
	} {
		t.Setenv(key, value)
	}
	reg, err := ipgroups.Open(ipgroups.Options{StateDir: filepath.Join(tmp, "ui-data", "ipgroups"),
		ListDir: filepath.Join(managed, "ipgroups"), CaddyDir: filepath.Join(managed, "ipgroups"), SourceDir: sources})
	if err != nil {
		t.Fatal(err)
	}
	service.SetIPGroups(reg)
	t.Cleanup(func() { service.SetIPGroups(nil) })
	if err := service.Initialize([]string{"example.com"}); err != nil {
		t.Fatal(err)
	}

	output, err := os.Create(filepath.Join(tmp, "caddy.log"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	// The binary is explicitly selected by the test operator, not an HTTP input.
	cmd := exec.CommandContext(ctx, binary, "run", "--config", caddyfile, "--adapter", "caddyfile") //nolint:gosec
	cmd.Env = append(os.Environ(), "XDG_DATA_HOME="+filepath.Join(tmp, "data"), "XDG_CONFIG_HOME="+filepath.Join(tmp, "config"))
	cmd.Stdout, cmd.Stderr = output, output
	if err := cmd.Start(); err != nil {
		cancel()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cancel()
		_ = cmd.Wait()
		_ = output.Close()
		if t.Failed() {
			data, _ := os.ReadFile(filepath.Join(tmp, "caddy.log"))
			t.Logf("Caddy output:\n%s", data)
		}
	})
	client := &http.Client{Timeout: 5 * time.Second}
	status := func(path, visitor string) int {
		t.Helper()
		req, err := http.NewRequest(http.MethodGet, "http://"+appAddress+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Host = "example.com"
		req.Header.Set("Accept", "text/html")
		req.Header.Set("User-Agent", "Mozilla/5.0")
		if visitor != "" {
			req.Header.Set("CF-Connecting-IP", visitor)
		}
		resp, err := client.Do(req)
		if err != nil {
			return 0
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		return resp.StatusCode
	}
	for deadline := time.Now().Add(10 * time.Second); status("/health", "") == 0; time.Sleep(25 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("Caddy did not start")
		}
	}
	actor := service.Actor{User: "integration"}
	for _, def := range []ipgroups.Definition{
		{Name: "scanners", Source: ipgroups.SourceFile, File: "scanners.srs"},
		{Name: "office", Source: ipgroups.SourceFile, File: "office.txt"},
		{Name: "partners", Source: ipgroups.SourceFile, File: "partners.txt"},
		{Name: "trialnet", Source: ipgroups.SourceFile, File: "trial.txt"},
	} {
		if g, err := service.PutIPGroup(context.Background(), actor, def); err != nil || g.Active == nil {
			t.Fatalf("%s: %+v %v", def.Name, g, err)
		}
	}
	if err := service.ApplyMode(actor, "example.com", domain.ModeOn); err != nil {
		t.Fatal(err)
	}
	p := waf.DefaultPolicy()
	p.IPGroups = []waf.IPGroupRule{
		{Group: "scanners", Action: waf.GroupBlock},
		{Group: "office", Action: waf.GroupEngine, Engine: "DetectionOnly"},
		{Group: "partners", Action: waf.GroupTune, InboundThreshold: 100},
		{Group: "trialnet", Action: waf.GroupTrial},
	}
	if err := service.ApplyPolicy(actor, "example.com", p); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		path, visitor string
		want          int
	}{
		{"/normal", "203.0.113.5", 403},  // block: from the sing-box .srs list
		{"/normal", "198.51.100.7", 403}, // block: single address of the .srs list
		{"/normal", "198.51.100.8", 200}, // not listed
		{"/.env", "100.64.0.5", 200},     // office: DetectionOnly, CRS 930130 does not block
		{"/.env", "100.64.1.5", 403},     // outside office: CRS blocks
		{"/.env", "10.10.3.4", 200},      // partners: inbound threshold 100
		{"/normal", "172.20.0.9", 200},   // trial records only
	} {
		if got := status(c.path, c.visitor); got != c.want {
			t.Fatalf("%s from %s: got %d, want %d", c.path, c.visitor, got, c.want)
		}
	}
	audit, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"IP group policy: inside scanners blocked", "IP group policy (trial): inside trialnet would be blocked"} {
		if !strings.Contains(string(audit), want) {
			t.Fatalf("audit log misses %q", want)
		}
	}

	// A refreshed list reaches Caddy without a manual reload.
	write(filepath.Join(sources, "office.txt"), "100.64.0.0/24\n100.64.1.0/24\n")
	if err := os.Chtimes(filepath.Join(sources, "office.txt"), time.Now().Add(time.Minute), time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if changed, err := service.RefreshIPGroup(context.Background(), actor, "office", false); err != nil || !changed {
		t.Fatalf("refresh: %v %v", changed, err)
	}
	if got := status("/.env", "100.64.1.5"); got != 200 {
		t.Fatalf("the refreshed office list must apply: got %d", got)
	}
}
