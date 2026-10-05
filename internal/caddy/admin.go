package caddy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/developmi/caddy-waf-ui/internal/config"
)

// ReadbackState describes the latest post-reload verification result (D3):
// after each POST /load, the UI queries Caddy's live config
// (GET /config/apps/http/servers) to confirm that the submitted Caddyfile
// was actually adopted - closing the "blind 200" gap that only trusted the
// load response.
type ReadbackState struct {
	OK        bool      `json:"ok"`
	CheckedAt time.Time `json:"checked_at"`
	Servers   int       `json:"servers"`
	Missing   []string  `json:"missing,omitempty"`
	Err       string    `json:"err,omitempty"`
	// Revisions is the number of WAF revisions verified in the live config.
	Revisions int `json:"revisions,omitempty"`
}

var (
	readbackMu   sync.Mutex
	lastReadback ReadbackState
)

// AppliedError identifies reload failures after Caddy accepted the config.
// The service must compensate by reloading its restored files in this case.
type AppliedError struct{ Err error }

func (e *AppliedError) Error() string { return e.Err.Error() }
func (e *AppliedError) Unwrap() error { return e.Err }
func WasApplied(err error) bool {
	var applied *AppliedError
	return errors.As(err, &applied)
}

// LastReadback returns the latest recorded verification state. The UI exposes
// it as a badge/flag (same pattern as the scanner's Degraded flag).
func LastReadback() ReadbackState {
	readbackMu.Lock()
	defer readbackMu.Unlock()
	return lastReadback
}

func setReadback(s ReadbackState) {
	readbackMu.Lock()
	lastReadback = s
	readbackMu.Unlock()
}

// siteHostRE captures the literal hosts of the Caddyfile's site blocks.
// By design it does NOT capture: the global block ("{"), snippets ("(waf) {"),
// comments, or environment-variable addresses ("{$SITE_ADDRESS}").
var siteHostRE = regexp.MustCompile(`(?m)^\s*([a-zA-Z0-9*.-]+(?::\d+)?(?:\s*,\s*[a-zA-Z0-9*.-]+(?::\d+)?)*)\s*\{`)

// looksLikeHost filters out tokens that are not hosts: Caddy directives such
// as "email {...}", "log {", "header {" or "format json {" match the capture
// regex because they end in "{", but they are not hostnames. A real host is
// an FQDN (contains "."), a port address (contains ":") or "localhost".
func looksLikeHost(h string) bool {
	return strings.Contains(h, ".") || strings.Contains(h, ":") || h == "localhost"
}

// expectedHosts extracts the literal host names of a Caddyfile. Port-only
// addresses (":80") are discarded: they live in listen addresses, not host
// matchers, and cannot be verified against /config/apps/http/servers.
func expectedHosts(caddyfile []byte) []string {
	var hosts []string
	seen := make(map[string]bool)
	for _, m := range siteHostRE.FindAllSubmatch(caddyfile, -1) {
		for _, part := range strings.Split(string(m[1]), ",") {
			h := strings.TrimSpace(part)
			if h == "" || strings.HasPrefix(h, ":") || seen[h] || !looksLikeHost(h) {
				continue
			}
			seen[h] = true
			hosts = append(hosts, h)
		}
	}
	return hosts
}

// validateAdminURL accepts HTTP/HTTPS endpoints or absolute Unix sockets,
// with no userinfo. The Admin API does not accept
// embedded credentials, and a failure must be loud BEFORE issuing any
// request, so configuration errors are not hidden behind network failures.
func validateAdminURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid CADDY_ADMIN_URL: %w", err)
	}
	if u.User != nil {
		return fmt.Errorf("CADDY_ADMIN_URL: userinfo is not allowed")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		if u.Scheme == "unix" && u.Host == "" && filepath.IsAbs(u.Path) && u.Path != "/" &&
			u.RawQuery == "" && u.Fragment == "" && !strings.ContainsRune(u.Path, 0) {
			return nil
		}
		return fmt.Errorf("CADDY_ADMIN_URL: scheme must be http or https, or unix:///absolute/socket/path; got %q", u.Scheme)
	}
	if u.Host == "" {
		return fmt.Errorf("CADDY_ADMIN_URL: host must not be empty")
	}
	return nil
}

// newAdminClient returns an HTTP client for the Admin API with a fixed
// timeout and no redirect following: a 30x is never a valid admin result,
// and following it could dispatch the load/read to a destination other than
// the configured one (fail-loud on the raw response).
func newAdminClient(adminURL string) (*http.Client, string) {
	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	parsed, _ := url.Parse(adminURL) // All callers validate the URL first.
	if parsed.Scheme == "unix" {
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.Proxy = nil
		transport.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
			var dialer net.Dialer
			return dialer.DialContext(ctx, "unix", parsed.Path)
		}
		client.Transport = transport
		return client, "http://localhost"
	}
	return client, strings.TrimSuffix(adminURL, "/")
}

// fetchLiveHosts queries the live config and collects the hosts of the
// server blocks ("host" matchers of the HTTP routes). It also returns the
// number of loaded servers. raw is the response body, used to verify the
// WAF revisions embedded in coraza_waf directives.
func fetchLiveHosts(adminURL string) (hosts []string, servers int, raw []byte, err error) {
	if err := validateAdminURL(adminURL); err != nil {
		return nil, 0, nil, err
	}
	client, baseURL := newAdminClient(adminURL)
	defer client.CloseIdleConnections()
	resp, err := client.Get(baseURL + "/config/apps/http/servers")
	if err != nil {
		return nil, 0, nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, 0, nil, fmt.Errorf("GET /config/apps/http/servers returned %s", resp.Status)
	}

	raw, err = io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return nil, 0, nil, err
	}
	var cfg any
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return nil, 0, nil, fmt.Errorf("unparseable /config response: %w", err)
	}

	if m, ok := cfg.(map[string]any); ok {
		servers = len(m)
	}
	collectHosts(cfg, &hosts)
	return hosts, servers, raw, nil
}

// missingRevisions returns the expected WAF revisions that the live config
// does not contain. Each generated overlay carries "# waf-config-revision:
// <hex>" inside its directives, which Caddy keeps verbatim in the handler's
// JSON; its absence means Caddy did not load the new overlay (not imported
// by the Caddyfile, or Caddy reads a stale file).
func missingRevisions(raw []byte, revisions []string) []string {
	var missing []string
	for _, rev := range revisions {
		if rev == "" {
			continue
		}
		if !bytes.Contains(raw, []byte("waf-config-revision: "+rev)) {
			missing = append(missing, rev)
		}
	}
	return missing
}

// collectHosts walks the config JSON recursively and accumulates the values
// of Caddy's "host" matchers (HTTP routes).
func collectHosts(v any, hosts *[]string) {
	switch t := v.(type) {
	case map[string]any:
		if h, ok := t["host"]; ok {
			if arr, ok := h.([]any); ok {
				for _, e := range arr {
					if s, ok := e.(string); ok {
						*hosts = append(*hosts, s)
					}
				}
			}
		}
		for _, val := range t {
			collectHosts(val, hosts)
		}
	case []any:
		for _, val := range t {
			collectHosts(val, hosts)
		}
	}
}

func containsHost(live []string, h string) bool {
	for _, l := range live {
		if l == h {
			return true
		}
	}
	return false
}

// Reload reads the Caddyfile (configured via CADDY_UI_CADDYFILE) and sends
// it to POST /load on Caddy's Admin API with Content-Type text/caddyfile.
// This lets Caddy re-adapt the imports and take the updated ui-managed/
// snippets into effect. On any failure (unreadable file or rejected reload)
// it returns an explicit error (fail-loud).
//
// D3 (read-back): after a 200 from the load, it queries the live config and
// verifies that the literal hosts of the submitted Caddyfile are present in
// the host matchers. If the verification fails, Reload returns an error so
// that the D6 chain in the service layer can restore the previous overlay.
// Note: on a read-back failure the config was already applied by Caddy; the
// overlay restoration is flagged in the ReadbackState and in the audit log.
func Reload() error {
	return ReloadExpect(nil)
}

// ReloadExpect reloads like Reload and additionally requires every given
// WAF revision to be present in the live configuration.
func ReloadExpect(revisions []string) error {
	// Centralized in config (finding J5-3): environment reads no longer live
	// in this package.
	adminURL := config.AdminURL()
	if err := validateAdminURL(adminURL); err != nil {
		setReadback(ReadbackState{OK: false, CheckedAt: time.Now().UTC(), Err: err.Error()})
		return err
	}

	caddyfilePath := config.CaddyfilePath()

	caddyfile, err := os.ReadFile(caddyfilePath)
	if err != nil {
		setReadback(ReadbackState{OK: false, CheckedAt: time.Now().UTC(), Err: err.Error()})
		return fmt.Errorf("could not read Caddyfile %q: %w", caddyfilePath, err)
	}

	client, baseURL := newAdminClient(adminURL)
	defer client.CloseIdleConnections()
	req, err := http.NewRequest(http.MethodPost, baseURL+"/load", bytes.NewReader(caddyfile))
	if err != nil {
		setReadback(ReadbackState{OK: false, CheckedAt: time.Now().UTC(), Err: err.Error()})
		return fmt.Errorf("error creating reload request: %w", err)
	}
	req.Header.Set("Content-Type", "text/caddyfile")
	req.Header.Set("Cache-Control", "must-revalidate")

	loadResp, err := client.Do(req)
	if err != nil {
		setReadback(ReadbackState{OK: false, CheckedAt: time.Now().UTC(), Err: err.Error()})
		return fmt.Errorf("error performing reload in Caddy: %w", err)
	}
	defer func() { _ = loadResp.Body.Close() }()

	if loadResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(loadResp.Body)
		msg := fmt.Sprintf("caddy POST /load failed with HTTP %d: %s", loadResp.StatusCode, string(body))
		setReadback(ReadbackState{OK: false, CheckedAt: time.Now().UTC(), Err: msg})
		return errors.New(msg)
	}

	// Read-back (D3): the live config must reflect the submitted hosts.
	live, servers, raw, err := fetchLiveHosts(adminURL)
	if err != nil {
		setReadback(ReadbackState{OK: false, CheckedAt: time.Now().UTC(), Err: err.Error()})
		return &AppliedError{Err: fmt.Errorf("post-reload verification failed: %w", err)}
	}

	var missing []string
	for _, h := range expectedHosts(caddyfile) {
		if !containsHost(live, h) {
			missing = append(missing, h)
		}
	}

	if len(missing) > 0 {
		msg := fmt.Sprintf("read-back: hosts not found in the live config: %s", strings.Join(missing, ", "))
		setReadback(ReadbackState{OK: false, CheckedAt: time.Now().UTC(), Servers: servers, Missing: missing, Err: msg})
		return &AppliedError{Err: errors.New(msg)}
	}
	if gone := missingRevisions(raw, revisions); len(gone) > 0 {
		msg := fmt.Sprintf("read-back: WAF revision(s) %s not found in the live config: is the overlay imported by the Caddyfile and visible to Caddy?", strings.Join(gone, ", "))
		setReadback(ReadbackState{OK: false, CheckedAt: time.Now().UTC(), Servers: servers, Err: msg})
		return &AppliedError{Err: errors.New(msg)}
	}

	setReadback(ReadbackState{OK: true, CheckedAt: time.Now().UTC(), Servers: servers, Revisions: len(revisions)})
	return nil
}
