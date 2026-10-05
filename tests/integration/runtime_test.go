package integration_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/developmi/caddy-waf-ui/internal/domain"
	"github.com/developmi/caddy-waf-ui/internal/files"
	"github.com/developmi/caddy-waf-ui/internal/iprules"
	"github.com/developmi/caddy-waf-ui/internal/logs"
	"github.com/developmi/caddy-waf-ui/internal/service"
	"github.com/developmi/caddy-waf-ui/internal/waf"
)

// Opt-in real-Caddy contract test. Supply an existing native Caddy binary
// containing coraza-caddy/v2; this application remains stdlib-only.
func TestRealCaddyWAFUpdatesAndStreaming(t *testing.T) {
	binary := os.Getenv("CADDY_TEST_BINARY")
	if binary == "" {
		t.Skip("set CADDY_TEST_BINARY to test a real Caddy/Coraza runtime")
	}
	tmp := t.TempDir()
	managed := filepath.Join(tmp, "managed")
	backups := filepath.Join(tmp, "backups")
	auditPath := filepath.Join(tmp, "coraza-audit.json")
	before := filepath.Join(tmp, "before.conf")
	after := filepath.Join(tmp, "after.conf")
	probeRule := func(path string) string {
		return "SecRule REQUEST_URI \"@beginsWith " + path + "\" \"id:1000001,phase:1,deny,log,msg:'Runtime probe',status:403\"\n"
	}
	write := func(path, content string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	write(before, probeRule("/probe"))
	write(after, "SecRule ARGS:q \"@contains blocked-value\" \"id:1000002,phase:2,deny,log,msg:'Parameter probe',status:403\"\n")
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/sse":
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = io.WriteString(w, "data: first\n\n")
			w.(http.Flusher).Flush()
			time.Sleep(600 * time.Millisecond)
			_, _ = io.WriteString(w, "data: second\n\n")
		case "/ws":
			conn, _, err := w.(http.Hijacker).Hijack()
			if err != nil {
				return
			}
			defer conn.Close()
			_, _ = io.WriteString(conn, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n")
			_, _ = conn.Write([]byte{0x81, 2, 'o', 'k'})
		case "/upload":
			r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
			reader, err := r.MultipartReader()
			if err != nil {
				http.Error(w, err.Error(), 400)
				return
			}
			file, err := reader.NextPart()
			if err != nil {
				http.Error(w, err.Error(), 400)
				return
			}
			defer file.Close()
			_, _ = io.Copy(w, file)
		default:
			_, _ = io.WriteString(w, "ok")
		}
	}))
	defer upstream.Close()
	appAddress := reserveAddress(t)
	adminAddress := reserveAddress(t)
	sourcePath := filepath.Join(tmp, "Caddyfile")
	source := fmt.Sprintf(`{
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
`, adminAddress, strings.Split(appAddress, ":")[1], managed, managed, upstream.URL)
	write(sourcePath, source)
	for key, value := range map[string]string{
		"CADDY_UI_MANAGED_DIR": managed, "CADDY_UI_INCLUDE_DIR": managed,
		"CADDY_UI_BACKUP_DIR": backups, "CADDY_UI_CADDYFILE": sourcePath,
		"CADDY_ADMIN_URL": "http://" + adminAddress, "CADDY_UI_AUDIT_LOG": auditPath,
		"CADDY_UI_WAF_BEFORE_FILE": before, "CADDY_UI_WAF_AFTER_FILE": after,
		"CADDY_UI_CRS_MODE": "embedded", "CADDY_UI_RESPONSE_BODY_ACCESS": "Off",
		"CADDY_UI_AUDIT_LOG_PARTS": "AHKZ",
		"CADDY_UI_CORAZA_CONFIG":   "", "CADDY_UI_CRS_SETUP": "", "CADDY_UI_CRS_RULES": "",
	} {
		t.Setenv(key, value)
	}
	if err := service.Initialize([]string{"example.com"}); err != nil {
		t.Fatal(err)
	}
	originalExclusions, err := os.ReadFile(files.ExclusionsConfigPath(managed, "example.com"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(backups, "example_com"), 0750); err != nil {
		t.Fatal(err)
	}
	write(filepath.Join(backups, "example_com", "2020-01-01T00-00-00Z.exclusions.conf"), string(originalExclusions))

	output, err := os.Create(filepath.Join(tmp, "caddy.log"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	// The binary is explicitly selected by the test operator, not an HTTP input.
	cmd := exec.CommandContext(ctx, binary, "run", "--config", sourcePath, "--adapter", "caddyfile") //nolint:gosec
	cmd.Env = append(os.Environ(), "XDG_DATA_HOME="+filepath.Join(tmp, "data"), "XDG_CONFIG_HOME="+filepath.Join(tmp, "config"))
	cmd.Stdout, cmd.Stderr = output, output
	if err := cmd.Start(); err != nil {
		cancel()
		output.Close()
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
	request := func(path, visitor string) (*http.Response, error) {
		req, err := http.NewRequest(http.MethodGet, "http://"+appAddress+path, nil)
		if err != nil {
			return nil, err
		}
		req.Host = "example.com"
		if visitor != "" {
			req.Header.Set("CF-Connecting-IP", visitor)
		}
		return client.Do(req)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		resp, err := request("/health", "")
		if err == nil {
			resp.Body.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("Caddy did not start: %v", err)
		}
		time.Sleep(25 * time.Millisecond)
	}
	status := func(path string, want int) {
		t.Helper()
		resp, err := request(path, "")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != want {
			t.Fatalf("%s: got %d, want %d, body %s", path, resp.StatusCode, want, body)
		}
	}
	status("/probe", 200)
	page, err := logs.Read(auditPath, logs.Options{})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, entry := range page.Entries {
		if entry.RuleID == "1000001" {
			found = true
			if entry.Action != "DETECTED" {
				t.Fatalf("DetectionOnly probe classified %s", entry.Action)
			}
		}
	}
	if !found {
		t.Fatal("missing actual DetectionOnly audit entry")
	}
	if err := service.UpdateWAFMode("example.com", domain.ModeOn, ""); err != nil {
		t.Fatal(err)
	}
	status("/probe", 403)
	if err := service.UpdateExclusions("example.com", []waf.Exclusion{{Type: waf.ExcludeByID, Value: "1000001"}}, ""); err != nil {
		t.Fatal(err)
	}
	status("/probe", 200)
	if err := service.Rollback("example.com", "2020-01-01T00-00-00Z.exclusions.conf", ""); err != nil {
		t.Fatal(err)
	}
	status("/probe", 403)

	status("/param?q=blocked-value", 403)
	if err := service.UpdateExclusions("example.com", []waf.Exclusion{{Type: waf.ExcludeByID, Value: "1000002", Param: "q"}}, ""); err != nil {
		t.Fatal(err)
	}
	status("/param?q=blocked-value", 200)
	if err := service.UpdateExclusions("example.com", nil, ""); err != nil {
		t.Fatal(err)
	}
	write(before, probeRule("/other-probe"))
	if err := service.UpdateWAFMode("example.com", domain.ModeOn, ""); err != nil {
		t.Fatal(err)
	}
	status("/probe", 200)
	status("/other-probe", 403)
	if err := service.UpdateWAFMode("example.com", domain.ModeOff, ""); err != nil {
		t.Fatal(err)
	}
	status("/other-probe", 200)
	if err := service.UpdateWAFMode("example.com", domain.ModeOn, ""); err != nil {
		t.Fatal(err)
	}

	if err := service.UpdateIPRules("example.com", iprules.IPRules{Denylist: []string{"192.0.2.45"}}, ""); err != nil {
		t.Fatal(err)
	}
	if resp, err := request("/normal", "192.0.2.45"); err == nil {
		resp.Body.Close()
		t.Fatal("client_ip denylist did not reject the trusted proxy visitor")
	}
	resp, err := request("/normal", "192.0.2.46")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatal("unlisted visitor was rejected")
	}
	if err := service.UpdateIPRules("example.com", iprules.IPRules{}, ""); err != nil {
		t.Fatal(err)
	}

	started := time.Now()
	resp, err = request("/sse", "")
	if err != nil {
		t.Fatal(err)
	}
	first := make([]byte, len("data: first\n\n"))
	if _, err := io.ReadFull(resp.Body, first); err != nil {
		t.Fatal(err)
	}
	if time.Since(started) >= 450*time.Millisecond {
		t.Fatal("first SSE event was buffered until the second event")
	}
	remaining, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil || string(first) != "data: first\n\n" || string(remaining) != "data: second\n\n" {
		t.Fatalf("SSE stream corrupted: %q / %q, %v", first, remaining, err)
	}

	var upload bytes.Buffer
	writer := multipart.NewWriter(&upload)
	part, err := writer.CreateFormFile("file", "test.txt")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.WriteString(part, "upload-through-waf")
	_ = writer.Close()
	req, err := http.NewRequest(http.MethodPost, "http://"+appAddress+"/upload", &upload)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "example.com"
	req.Header.Set("Content-Type", writer.FormDataContentType())
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	uploaded, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || string(uploaded) != "upload-through-waf" {
		t.Fatalf("upload corrupted: %d %q", resp.StatusCode, uploaded)
	}
	status("/oauth/callback?code=test", 200)
	status("/mcp/callback?state=test", 200)

	req, err = http.NewRequest(http.MethodGet, "http://"+appAddress+"/ws", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "example.com"
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	req.Header.Set("Sec-WebSocket-Version", "13")
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 101 {
		t.Fatalf("WebSocket upgrade failed: %d", resp.StatusCode)
	}
	frame := make([]byte, 4)
	if _, err := io.ReadFull(resp.Body, frame); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(frame, []byte{0x81, 2, 'o', 'k'}) {
		t.Fatalf("WebSocket frame corrupted: %v", frame)
	}
}

func reserveAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return addr
}
