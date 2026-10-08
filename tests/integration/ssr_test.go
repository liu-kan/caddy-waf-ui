package integration_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/developmi/caddy-waf-ui/internal/auth"
	"github.com/developmi/caddy-waf-ui/internal/ui"
)

// setupSSR prepares the complete environment (token, directories, stub of
// the Admin API) and assembles the mux with the three route groups EXACTLY
// as cmd/server/main.go does (task 2.7): public (login), SSR pages (cookie
// or Bearer session + CSRF) and RESTful API (Bearer-only).
func setupSSR(t *testing.T, admin *adminStub) http.Handler {
	t.Setenv("CADDY_UI_TOKEN", "super-secret-token")

	tmp := t.TempDir()
	managedDir := filepath.Join(tmp, "ui-managed")
	backupDir := filepath.Join(tmp, "backups")
	if err := os.MkdirAll(managedDir, 0750); err != nil {
		t.Fatalf("failed creating managedDir: %v", err)
	}
	t.Setenv("CADDY_UI_MANAGED_DIR", managedDir)
	t.Setenv("CADDY_UI_DATA_DIR", t.TempDir())
	t.Setenv("CADDY_UI_BACKUP_DIR", backupDir)

	caddyfile := filepath.Join(tmp, "Caddyfile")
	if err := os.WriteFile(caddyfile, []byte("example.com {\n}\n"), 0600); err != nil {
		t.Fatalf("failed to write test Caddyfile: %v", err)
	}
	t.Setenv("CADDY_UI_CADDYFILE", caddyfile)

	server := httptest.NewServer(admin.handler(t))
	t.Cleanup(server.Close)
	t.Setenv("CADDY_ADMIN_URL", server.URL)

	mux := http.NewServeMux()
	mux.Handle("/login", ui.NewLoginMux())
	api := auth.Middleware(ui.NewRouter())
	mux.Handle("/api/", api)
	mux.Handle("/health", api)
	mux.Handle("/", auth.Session(auth.CSRF(ui.NewPagesMux())))
	return mux
}

// sessionCookie returns a valid signed cookie like the one POST /login sets.
func sessionCookie() *http.Cookie {
	value, err := auth.NewSessionValue(time.Now())
	if err != nil {
		panic(err)
	}
	return &http.Cookie{Name: "CADDY_UI_TOKEN", Value: value, Path: "/"}
}

// formRequest builds a urlencoded POST with an optional cookie.
func formRequest(t *testing.T, method, path string, form url.Values, cookie *http.Cookie) *http.Request {
	req, err := http.NewRequest(method, path, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("failed creating request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if cookie != nil {
		req.AddCookie(cookie)
	}
	return req
}

// csrfValue derives the CSRF token of the test environment (D1).
func csrfValue(t *testing.T) string {
	token, err := auth.CSRFValue()
	if err != nil {
		t.Fatalf("failed deriving the CSRF token: %v", err)
	}
	return token
}

func TestSSRLoginSetsSessionCookie(t *testing.T) {
	handler := setupSSR(t, &adminStub{})

	form := url.Values{"token": {"super-secret-token"}}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, formRequest(t, http.MethodPost, "/login", form, nil))

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("expected 303 after a valid login, got %d", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/" {
		t.Errorf("expected a redirect to /, got %q", loc)
	}
	setCookie := rec.Header().Get("Set-Cookie")
	if !strings.Contains(setCookie, "CADDY_UI_TOKEN=v1.") || strings.Contains(setCookie, "super-secret-token") {
		t.Errorf("the cookie must be a signed session, never the token: %q", setCookie)
	}
	for _, flag := range []string{"HttpOnly", "Secure", "SameSite=Strict"} {
		if !strings.Contains(setCookie, flag) {
			t.Errorf("the session cookie does not carry the flag %s: %q", flag, setCookie)
		}
	}
}

func TestSSRLoginRejectsWrongToken(t *testing.T) {
	handler := setupSSR(t, &adminStub{})

	form := url.Values{"token": {"token-incorrecto"}}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, formRequest(t, http.MethodPost, "/login", form, nil))

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("expected 303 after an invalid login, got %d", rec.Code)
	}
	if loc := rec.Header().Get("Location"); !strings.Contains(loc, "flash=invalid_login") {
		t.Errorf("expected a redirect with flash=invalid_login, got %q", loc)
	}
	if setCookie := rec.Header().Get("Set-Cookie"); strings.Contains(setCookie, "CADDY_UI_TOKEN=") {
		t.Errorf("no cookie must be set with an invalid credential: %q", setCookie)
	}
}

func TestSSRPageWithoutSessionRedirectsToLogin(t *testing.T) {
	handler := setupSSR(t, &adminStub{})

	for _, path := range []string{"/", "/?tab=logs", "/?tab=sites"} {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusFound {
			t.Errorf("%s: expected 302 without a session, got %d", path, rec.Code)
		}
		if loc := rec.Header().Get("Location"); loc != "/login" {
			t.Errorf("%s: expected Location /login, got %q", path, loc)
		}
	}
}

func TestSSRIndexRendersWithCookie(t *testing.T) {
	handler := setupSSR(t, &adminStub{})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(sessionCookie())
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 with a session cookie, got %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "Caddy WAF UI") {
		t.Errorf("the HTML does not contain the UI brand")
	}
	if !strings.Contains(body, "?tab=sites") {
		t.Errorf("the HTML does not contain the tab navigation")
	}
}

func TestSSRIndexAcceptsBearer(t *testing.T) {
	handler := setupSSR(t, &adminStub{})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer super-secret-token")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 with a valid Bearer, got %d", rec.Code)
	}
}

func TestSSRIndexEscapesDomainValue(t *testing.T) {
	handler := setupSSR(t, &adminStub{})

	// A domain with <script> registered from the header of an overlay:
	// html/template must escape it in text context (web-ui spec).
	overlay := filepath.Join(os.Getenv("CADDY_UI_MANAGED_DIR"), "waf-<script>_com.conf")
	if err := os.WriteFile(overlay, []byte("# domain: <script>.com | mode: On | updated: 2026-08-07T00:00:00Z\n"), 0640); err != nil {
		t.Fatalf("failed seeding overlay: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(sessionCookie())
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "&lt;script&gt;.com") {
		t.Errorf("the domain must be rendered escaped (&lt;script&gt;.com)")
	}
	if strings.Contains(body, "<script>.com") {
		t.Errorf("the domain must not appear raw in the HTML")
	}
}

func TestSSRPRGModeChangeSuccess(t *testing.T) {
	admin := &adminStub{}
	handler := setupSSR(t, admin)

	form := url.Values{
		"mode":   {"On"},
		"tab":    {"sites"},
		"domain": {"example.com"},
		"csrf":   {csrfValue(t)},
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, formRequest(t, http.MethodPost, "/sites/example.com/mode", form, sessionCookie()))

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("expected 303 (PRG), got %d", rec.Code)
	}
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("invalid Location: %v", err)
	}
	q := loc.Query()
	if q.Get("flash") != "success" {
		t.Errorf("expected flash=success, got %q", q.Get("flash"))
	}
	if q.Get("tab") != "sites" || q.Get("domain") != "example.com" {
		t.Errorf("the redirect must preserve tab and domain: %s", rec.Header().Get("Location"))
	}

	overlay, err := os.ReadFile(filepath.Join(os.Getenv("CADDY_UI_MANAGED_DIR"), "waf-example_com.conf"))
	if err != nil {
		t.Fatalf("the overlay was not written after the POST: %v", err)
	}
	if !strings.Contains(string(overlay), "SecRuleEngine On") {
		t.Errorf("the overlay does not reflect the sent mode:\n%s", overlay)
	}
	if admin.reloads != 1 {
		t.Errorf("expected 1 Caddy reload, %d made", admin.reloads)
	}
}

func TestSSRPRGModeChangeInvalidNoMutation(t *testing.T) {
	admin := &adminStub{}
	handler := setupSSR(t, admin)

	form := url.Values{
		"mode":   {"NonexistentMode"},
		"tab":    {"sites"},
		"domain": {"example.com"},
		"csrf":   {csrfValue(t)},
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, formRequest(t, http.MethodPost, "/sites/example.com/mode", form, sessionCookie()))

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("expected 303 (PRG), got %d", rec.Code)
	}
	if loc := rec.Header().Get("Location"); !strings.Contains(loc, "flash=invalid") {
		t.Errorf("expected flash=invalid, got %q", loc)
	}
	if _, err := os.Stat(filepath.Join(os.Getenv("CADDY_UI_MANAGED_DIR"), "waf-example_com.conf")); !os.IsNotExist(err) {
		t.Errorf("an invalid POST must not mutate state: the overlay must not exist")
	}
	if admin.reloads != 0 {
		t.Errorf("an invalid POST must not reload Caddy, %d reloads made", admin.reloads)
	}
}

func TestSSRCSRFMissingTokenRejected(t *testing.T) {
	handler := setupSSR(t, &adminStub{})

	form := url.Values{"mode": {"On"}, "tab": {"sites"}, "domain": {"example.com"}}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, formRequest(t, http.MethodPost, "/sites/example.com/mode", form, sessionCookie()))

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 without a CSRF token, got %d", rec.Code)
	}
}

func TestSSRCSRFWrongTokenRejected(t *testing.T) {
	handler := setupSSR(t, &adminStub{})

	form := url.Values{
		"mode":   {"On"},
		"tab":    {"sites"},
		"domain": {"example.com"},
		"csrf":   {"token-incorrecto"},
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, formRequest(t, http.MethodPost, "/sites/example.com/mode", form, sessionCookie()))

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 with an invalid CSRF token, got %d", rec.Code)
	}
}

func TestSSRCSRFBearerExempt(t *testing.T) {
	admin := &adminStub{}
	handler := setupSSR(t, admin)

	// Requests authenticated by Bearer cannot be emitted cross-site by a
	// browser (D1): they are exempt from the CSRF check.
	form := url.Values{"mode": {"On"}, "tab": {"sites"}, "domain": {"example.com"}}
	req := formRequest(t, http.MethodPost, "/sites/example.com/mode", form, nil)
	req.Header.Set("Authorization", "Bearer super-secret-token")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("expected 303 with Bearer (CSRF exempt), got %d", rec.Code)
	}
	if !strings.Contains(rec.Header().Get("Location"), "flash=success") {
		t.Errorf("expected flash=success, got %q", rec.Header().Get("Location"))
	}
	if admin.reloads != 1 {
		t.Errorf("expected 1 reload, %d made", admin.reloads)
	}
}

// auditFixture returns the path of the JSONL fixture of the reader (same
// source as the unit tests of internal/logs).
func auditFixture() string {
	return filepath.Join("..", "..", "internal", "logs", "testdata", "audit-valid.jsonl")
}

// TestSSRLogsTabRendersFilteredEntries: the Logs tab must be fed by the REAL
// audit log (audit-logs spec) and apply actionFilter + search server-side.
func TestSSRLogsTabRendersFilteredEntries(t *testing.T) {
	t.Setenv("CADDY_UI_AUDIT_LOG", auditFixture())
	handler := setupSSR(t, &adminStub{})

	req := httptest.NewRequest(http.MethodGet, "/?tab=logs&actionFilter=BLOCKED&search=1.2.3.4", nil)
	req.AddCookie(sessionCookie())
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "942100") {
		t.Errorf("the blocked entry (942100) must be rendered")
	}
	if !strings.Contains(body, "/wp-admin/login.php") {
		t.Errorf("the URI of the blocked entry must be rendered")
	}
	if strings.Contains(body, "920420") {
		t.Errorf("actionFilter=BLOCKED must exclude the detected entry (920420)")
	}
	if strings.Contains(body, "203.0.113.9") {
		t.Errorf("search=1.2.3.4 must exclude the entry of the client 203.0.113.9")
	}
	if strings.Contains(body, "No Coraza audit logs found") {
		t.Errorf("with results the empty state must not be rendered")
	}
}

// TestSSRLogsTabSearchMatchesAnyField: the search is case-insensitive and
// covers client/uri/ruleID/message (placeholder of the template).
func TestSSRLogsTabSearchMatchesAnyField(t *testing.T) {
	t.Setenv("CADDY_UI_AUDIT_LOG", auditFixture())
	handler := setupSSR(t, &adminStub{})

	// Uppercase URI: it must match /wp-admin/login.php.
	req := httptest.NewRequest(http.MethodGet, "/?tab=logs&search=WP-ADMIN", nil)
	req.AddCookie(sessionCookie())
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "942100") {
		t.Errorf("search=WP-ADMIN must match the entry 942100 (case-insensitive)")
	}
	if strings.Contains(body, "920420") {
		t.Errorf("search=WP-ADMIN must not bring the entry 920420")
	}
}

// TestSSRLogsTabEmptyState: a search without results and a missing file
// render the honest empty state (200, never 500).
func TestSSRLogsTabEmptyState(t *testing.T) {
	t.Setenv("CADDY_UI_AUDIT_LOG", auditFixture())
	handler := setupSSR(t, &adminStub{})

	for _, path := range []string{"/?tab=logs&search=zzz-no-existe", "/?tab=logs&search=zzz-no-existe&actionFilter=BLOCKED"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.AddCookie(sessionCookie())
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: expected 200, got %d", path, rec.Code)
		}
		if !strings.Contains(rec.Body.String(), "No Coraza audit logs found") {
			t.Errorf("%s: without results it must render the empty state", path)
		}
	}

	// Missing file (first start of the sidecar): warn + empty state.
	t.Setenv("CADDY_UI_AUDIT_LOG", filepath.Join(t.TempDir(), "no-existe.log"))
	req := httptest.NewRequest(http.MethodGet, "/?tab=logs", nil)
	req.AddCookie(sessionCookie())
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("without an audit log file expected 200 with the empty state, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "No Coraza audit logs found") {
		t.Errorf("without an audit log file it must render the empty state")
	}
}

func TestSSRLogoutClearsSessionCookie(t *testing.T) {
	handler := setupSSR(t, &adminStub{})

	form := url.Values{"csrf": {csrfValue(t)}}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, formRequest(t, http.MethodPost, "/logout", form, sessionCookie()))

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("expected 303 after logout, got %d", rec.Code)
	}
	setCookie := rec.Header().Get("Set-Cookie")
	if !strings.Contains(setCookie, "CADDY_UI_TOKEN=") {
		t.Fatalf("logout must emit an expiration cookie: %q", setCookie)
	}

	// After the logout the session is no longer valid: the page redirects
	// again.
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec2.Code != http.StatusFound || rec2.Header().Get("Location") != "/login" {
		t.Errorf("after logout, GET / must redirect to /login (302), got %d %q", rec2.Code, rec2.Header().Get("Location"))
	}
}

// TestSSRPRGRollbackSuccess: POST /sites/{domain}/rollback restores the
// snapshot (PRG 303 + flash) and the overlay returns to the bytes of the
// snapshot.
func TestSSRPRGRollbackSuccess(t *testing.T) {
	admin := &adminStub{}
	handler := setupSSR(t, admin)

	overlayPath := filepath.Join(os.Getenv("CADDY_UI_MANAGED_DIR"), "waf-example_com.conf")
	if err := os.WriteFile(overlayPath, []byte("current state"), 0640); err != nil {
		t.Fatalf("failed seeding overlay: %v", err)
	}
	slugDir := filepath.Join(os.Getenv("CADDY_UI_BACKUP_DIR"), "example_com")
	if err := os.MkdirAll(slugDir, 0750); err != nil {
		t.Fatalf("failed creating backups dir: %v", err)
	}
	snapshot := "# Caddy WAF UI managed - do not edit manually\n# domain: example.com | mode: Off | updated: 2020-01-01T00:00:00Z\n"
	if err := os.WriteFile(filepath.Join(slugDir, "2020-01-01T00-00-00Z.waf.conf"), []byte(snapshot), 0640); err != nil {
		t.Fatalf("failed seeding snapshot: %v", err)
	}

	form := url.Values{
		"snapId": {"2020-01-01T00-00-00Z.waf.conf"},
		"tab":    {"rollback"},
		"domain": {"example.com"},
		"csrf":   {csrfValue(t)},
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, formRequest(t, http.MethodPost, "/sites/example.com/rollback", form, sessionCookie()))

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("expected 303 (PRG), got %d", rec.Code)
	}
	loc := rec.Header().Get("Location")
	if !strings.Contains(loc, "flash=success") {
		t.Errorf("expected flash=success, got %q", loc)
	}
	if !strings.Contains(loc, "tab=rollback") {
		t.Errorf("the redirect must preserve the rollback tab: %q", loc)
	}

	overlay, err := os.ReadFile(overlayPath)
	if err != nil {
		t.Fatalf("the overlay was not restored: %v", err)
	}
	if !strings.Contains(string(overlay), "SecRuleEngine Off") || !strings.Contains(string(overlay), "coraza_waf {") {
		t.Errorf("the overlay must restore the snapshot's mode in a regenerated overlay: %q", overlay)
	}
	if admin.reloads != 1 {
		t.Errorf("expected 1 Caddy reload, %d made", admin.reloads)
	}
}

// TestSSRPRGRollbackInvalidNoMutation: an invalid snapshot returns 303
// ?flash=invalid without mutating the overlay nor reloading Caddy (fail-fast).
func TestSSRPRGRollbackInvalidNoMutation(t *testing.T) {
	admin := &adminStub{}
	handler := setupSSR(t, admin)

	overlayPath := filepath.Join(os.Getenv("CADDY_UI_MANAGED_DIR"), "waf-example_com.conf")
	if err := os.WriteFile(overlayPath, []byte("current state"), 0640); err != nil {
		t.Fatalf("failed seeding overlay: %v", err)
	}

	form := url.Values{
		"snapId": {"../../etc/passwd"},
		"tab":    {"rollback"},
		"domain": {"example.com"},
		"csrf":   {csrfValue(t)},
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, formRequest(t, http.MethodPost, "/sites/example.com/rollback", form, sessionCookie()))

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("expected 303 (PRG), got %d", rec.Code)
	}
	if !strings.Contains(rec.Header().Get("Location"), "flash=invalid") {
		t.Errorf("expected flash=invalid, got %q", rec.Header().Get("Location"))
	}

	overlay, err := os.ReadFile(overlayPath)
	if err != nil {
		t.Fatalf("failed reading overlay: %v", err)
	}
	if string(overlay) != "current state" {
		t.Errorf("an invalid snapshot must not mutate the overlay: %q", overlay)
	}
	if admin.reloads != 0 {
		t.Errorf("an invalid snapshot must not reload Caddy, %d reloads made", admin.reloads)
	}
}

// TestSSRFormRollbackMissingDomainFlashError: a POST towards a domain
// WITHOUT overlay or snapshots (domain not in the registry) responds 303
// ?flash=invalid through the full stack (session + CSRF), without mutating
// anything nor reloading Caddy (W2, error branch of the form with an absent
// domain).
func TestSSRFormRollbackMissingDomainFlashError(t *testing.T) {
	admin := &adminStub{}
	handler := setupSSR(t, admin)

	form := url.Values{
		"snapId": {"2099-01-01T00-00-00Z.waf.conf"}, // canonical name, nonexistent snapshot
		"tab":    {"rollback"},
		"domain": {"no-such-domain.com"},
		"csrf":   {csrfValue(t)},
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, formRequest(t, http.MethodPost, "/sites/no-such-domain.com/rollback", form, sessionCookie()))

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("expected 303 (PRG), got %d", rec.Code)
	}
	if !strings.Contains(rec.Header().Get("Location"), "flash=invalid") {
		t.Errorf("a domain without snapshots must redirect with flash=invalid, got %q", rec.Header().Get("Location"))
	}
	if _, err := os.Stat(filepath.Join(os.Getenv("CADDY_UI_MANAGED_DIR"), "waf-no_such_domain_com.conf")); !os.IsNotExist(err) {
		t.Errorf("a failed rollback must not create overlays for the domain")
	}
	if admin.reloads != 0 {
		t.Errorf("a failed rollback must not reload Caddy, %d reloads made", admin.reloads)
	}
}
