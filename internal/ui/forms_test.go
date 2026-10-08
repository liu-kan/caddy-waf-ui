package ui

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/developmi/caddy-waf-ui/internal/files"
	"github.com/developmi/caddy-waf-ui/internal/service"
	"github.com/developmi/caddy-waf-ui/internal/waf"
)

// formPost builds a urlencoded POST towards the given mux.
func formPost(t *testing.T, mux *http.ServeMux, path string, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

// TestRedirectAfterFormPreservesQuery: the PRG pattern preserves
// tab/domain/search/actionFilter and adds flash (web-ui spec).
func TestRedirectAfterFormPreservesQuery(t *testing.T) {
	form := url.Values{
		"tab":          {"sites"},
		"domain":       {"example.com"},
		"search":       {"1.2.3.4"},
		"actionFilter": {"BLOCKED"},
	}
	req := httptest.NewRequest(http.MethodPost, "/sites/example.com/mode", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()

	redirectAfterForm(rec, req, "success")

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("expected 303, got %d", rec.Code)
	}
	loc := rec.Header().Get("Location")
	q, err := url.ParseQuery(strings.TrimPrefix(loc, "/?"))
	if err != nil {
		t.Fatalf("invalid Location: %q", loc)
	}
	for key, want := range map[string]string{
		"tab": "sites", "domain": "example.com", "search": "1.2.3.4", "actionFilter": "BLOCKED", "flash": "success",
	} {
		if q.Get(key) != want {
			t.Errorf("the redirect must preserve %s=%q, got %q (Location=%q)", key, want, q.Get(key), loc)
		}
	}
}

// TestHandleLoginSuccess: a valid token sets the cookie and redirects to /.
func TestHandleLoginSuccess(t *testing.T) {
	t.Setenv("CADDY_UI_TOKEN", "super-secret-token")
	mux := NewLoginMux()

	rec := formPost(t, mux, "/login", url.Values{"token": {"super-secret-token"}})

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("expected 303, got %d", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/" {
		t.Errorf("expected a redirect to /, got %q", loc)
	}
	if !strings.Contains(rec.Header().Get("Set-Cookie"), "CADDY_UI_TOKEN=") {
		t.Errorf("a valid login must set the session cookie: %q", rec.Header().Get("Set-Cookie"))
	}
}

// TestHandleLoginInvalidToken: wrong token → flash=invalid_login without
// cookie.
func TestHandleLoginInvalidToken(t *testing.T) {
	t.Setenv("CADDY_UI_TOKEN", "super-secret-token")
	mux := NewLoginMux()

	rec := formPost(t, mux, "/login", url.Values{"token": {"token-incorrecto"}})

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("expected 303, got %d", rec.Code)
	}
	if loc := rec.Header().Get("Location"); !strings.Contains(loc, "flash=invalid_login") {
		t.Errorf("expected flash=invalid_login, got %q", loc)
	}
	if strings.Contains(rec.Header().Get("Set-Cookie"), "CADDY_UI_TOKEN=") {
		t.Errorf("an invalid credential must not set a cookie: %q", rec.Header().Get("Set-Cookie"))
	}
}

// TestHandleLogout: invalidates the cookie and redirects to the login with
// flash.
func TestHandleLogout(t *testing.T) {
	mux := NewPagesMux()

	rec := formPost(t, mux, "/logout", url.Values{})

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("expected 303, got %d", rec.Code)
	}
	if loc := rec.Header().Get("Location"); !strings.Contains(loc, "flash=logged_out") {
		t.Errorf("expected flash=logged_out, got %q", loc)
	}
	if !strings.Contains(rec.Header().Get("Set-Cookie"), "CADDY_UI_TOKEN=") {
		t.Errorf("logout must emit an expiration cookie: %q", rec.Header().Get("Set-Cookie"))
	}
}

// TestHandleLoginInvalidTokenEmitsSecurityWarn (LE-1/D10): a POST /login
// with an invalid token emits a security slog.Warn that includes the
// RemoteAddr of the client, and keeps the PRG 303 ?flash=invalid_login. The
// event uses direct slog (msg "login rejected", key remote_ip): it is NEVER
// logged as ui_request (D2) nor records credential material.
func TestHandleLoginInvalidTokenEmitsSecurityWarn(t *testing.T) {
	t.Setenv("CADDY_UI_TOKEN", "super-secret-token")

	var buf bytes.Buffer
	handler := slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})
	prev := slog.Default()
	slog.SetDefault(slog.New(handler))
	defer slog.SetDefault(prev)

	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader("token=token-incorrecto"))
	req.RemoteAddr = "203.0.113.77:5555"
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()

	NewLoginMux().ServeHTTP(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("expected 303 (PRG), got %d", rec.Code)
	}
	if loc := rec.Header().Get("Location"); !strings.Contains(loc, "flash=invalid_login") {
		t.Errorf("expected flash=invalid_login, got %q", loc)
	}

	out := buf.String()
	if !strings.Contains(out, "level=WARN") || !strings.Contains(out, "login rejected") {
		t.Errorf("the failed login must emit slog.Warn \"login rejected\", buffer:\n%s", out)
	}
	if !strings.Contains(out, "remote_ip=203.0.113.77:5555") {
		t.Errorf("the Warn must include remote_ip with the RemoteAddr of the client, buffer:\n%s", out)
	}
	if strings.Contains(out, "token-incorrecto") {
		t.Errorf("the provided credential must not appear in the log, buffer:\n%s", out)
	}
}

// TestHandleLoginSuccessSilentNoWarn (LE-1): the valid login does NOT emit
// the security event (silent success) nor any credential in the log.
func TestHandleLoginSuccessSilentNoWarn(t *testing.T) {
	t.Setenv("CADDY_UI_TOKEN", "super-secret-token")

	var buf bytes.Buffer
	handler := slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})
	prev := slog.Default()
	slog.SetDefault(slog.New(handler))
	defer slog.SetDefault(prev)

	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader("token=super-secret-token"))
	req.RemoteAddr = "203.0.113.77:5555"
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()

	NewLoginMux().ServeHTTP(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("expected 303, got %d", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/" {
		t.Errorf("expected a redirect to /, got %q", loc)
	}

	out := buf.String()
	if out != "" {
		t.Errorf("the valid login must be silent (no Warn nor credentials), buffer:\n%s", out)
	}
}

// TestHandleFormSetModeSuccess: a valid POST → 303 flash=success and
// regenerated overlay (PRG, web-ui spec).
func TestHandleFormSetModeSuccess(t *testing.T) {
	setupUIEnv(t)
	mux := NewPagesMux()

	rec := formPost(t, mux, "/sites/example.com/mode", url.Values{
		"mode": {"On"}, "tab": {"sites"}, "domain": {"example.com"},
	})

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("expected 303, got %d", rec.Code)
	}
	if !strings.Contains(rec.Header().Get("Location"), "flash=success") {
		t.Errorf("expected flash=success, got %q", rec.Header().Get("Location"))
	}
	overlay, err := os.ReadFile(filepath.Join(os.Getenv("CADDY_UI_MANAGED_DIR"), "waf-example_com.conf"))
	if err != nil {
		t.Fatalf("the overlay was not written: %v", err)
	}
	if !strings.Contains(string(overlay), "SecRuleEngine On") {
		t.Errorf("the overlay does not reflect the sent mode:\n%s", overlay)
	}
}

// TestHandleFormSetModeInvalidModeFlashError: invalid mode → flash=invalid
// without mutating anything (the service validates before the backup).
func TestHandleFormSetModeInvalidModeFlashError(t *testing.T) {
	setupUIEnv(t)
	mux := NewPagesMux()

	rec := formPost(t, mux, "/sites/example.com/mode", url.Values{"mode": {"BlockAll"}})

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("expected 303, got %d", rec.Code)
	}
	if !strings.Contains(rec.Header().Get("Location"), "flash=invalid") {
		t.Errorf("expected flash=invalid, got %q", rec.Header().Get("Location"))
	}
	if _, err := os.Stat(filepath.Join(os.Getenv("CADDY_UI_MANAGED_DIR"), "waf-example_com.conf")); !os.IsNotExist(err) {
		t.Errorf("an invalid mode must not create the overlay")
	}
}

// TestHandleFormAddExclusionReadErrorFlashError: if the active state cannot
// be read (corrupt managed dir - domain without a readable overlay), the
// exclusion POST fails with flash=error instead of blindly replacing the
// list (W2, readExclusions-error branch of forms.go).
func TestHandleFormAddExclusionReadErrorFlashError(t *testing.T) {
	setupUIEnv(t)
	file := filepath.Join(t.TempDir(), "managed-es-un-archivo")
	if err := os.WriteFile(file, []byte("x"), 0640); err != nil {
		t.Fatalf("failed seeding file: %v", err)
	}
	t.Setenv("CADDY_UI_MANAGED_DIR", file)
	mux := NewPagesMux()

	rec := formPost(t, mux, "/sites/example.com/exclusions", url.Values{"ruleId": {"941100"}})

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("expected 303, got %d", rec.Code)
	}
	if !strings.Contains(rec.Header().Get("Location"), "flash=error") {
		t.Errorf("a read failure must redirect with flash=error, got %q", rec.Header().Get("Location"))
	}
}

// TestHandleFormAddExclusionSuccess: new exclusion merged with the current
// state → 303 flash=success (PRG).
func TestHandleFormAddExclusionSuccess(t *testing.T) {
	setupUIEnv(t)
	mux := NewPagesMux()

	draft, err := service.CreateExclusionsDraft("example.com", []waf.Exclusion{{Type: waf.ExcludeByID, Value: "941100", Param: "q"}})
	if err != nil {
		t.Fatal(err)
	}
	rec := formPost(t, mux, "/sites/example.com/exclusions", url.Values{"ruleId": {"941100"}, "param": {"q"}, "draft_id": {draft.DraftID}})

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("expected 303, got %d", rec.Code)
	}
	if !strings.Contains(rec.Header().Get("Location"), "flash=success") {
		t.Errorf("expected flash=success, got %q", rec.Header().Get("Location"))
	}
	overlay, err := os.ReadFile(filepath.Join(os.Getenv("CADDY_UI_MANAGED_DIR"), "exclusions-example_com.conf"))
	if err != nil {
		t.Fatalf("the overlay was not written: %v", err)
	}
	if !strings.Contains(string(overlay), `SecRuleUpdateTargetById 941100 "!ARGS:q"`) {
		t.Errorf("the overlay does not contain the parameter-scoped exclusion:\n%s", overlay)
	}
}

// TestHandleFormAddIPRuleInvalidActionFlashError: unknown action → error
// flash without mutating (default branch of forms.go).
func TestHandleFormAddIPRuleInvalidActionFlashError(t *testing.T) {
	setupUIEnv(t)
	mux := NewPagesMux()

	rec := formPost(t, mux, "/sites/example.com/iprules", url.Values{"cidr": {"192.0.2.5"}, "action": {"BAN"}})

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("expected 303, got %d", rec.Code)
	}
	if !strings.Contains(rec.Header().Get("Location"), "flash=invalid") {
		t.Errorf("an invalid action must redirect with flash=invalid, got %q", rec.Header().Get("Location"))
	}
}

// TestHandleFormAddIPRuleReadErrorFlashError: if the current state cannot be
// read, the IP rule POST fails with flash=error (W2, readIPRules-error
// branch).
func TestHandleFormAddIPRuleReadErrorFlashError(t *testing.T) {
	setupUIEnv(t)
	file := filepath.Join(t.TempDir(), "managed-es-un-archivo")
	if err := os.WriteFile(file, []byte("x"), 0640); err != nil {
		t.Fatalf("failed seeding file: %v", err)
	}
	t.Setenv("CADDY_UI_MANAGED_DIR", file)
	mux := NewPagesMux()

	rec := formPost(t, mux, "/sites/example.com/iprules", url.Values{"cidr": {"192.0.2.5"}, "action": {"DENY"}})

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("expected 303, got %d", rec.Code)
	}
	if !strings.Contains(rec.Header().Get("Location"), "flash=error") {
		t.Errorf("a read failure must redirect with flash=error, got %q", rec.Header().Get("Location"))
	}
}

// TestHandleFormAddIPRuleSuccess: merged DENY rule → 303 flash=success.
func TestHandleFormAddIPRuleSuccess(t *testing.T) {
	setupUIEnv(t)
	mux := NewPagesMux()

	rec := formPost(t, mux, "/sites/example.com/iprules", url.Values{"cidr": {"192.0.2.5"}, "action": {"DENY"}})

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("expected 303, got %d", rec.Code)
	}
	if !strings.Contains(rec.Header().Get("Location"), "flash=success") {
		t.Errorf("expected flash=success, got %q", rec.Header().Get("Location"))
	}
	overlay, err := os.ReadFile(filepath.Join(os.Getenv("CADDY_UI_MANAGED_DIR"), "ip-rules-example_com.conf"))
	if err != nil {
		t.Fatalf("the overlay was not written: %v", err)
	}
	if !strings.Contains(string(overlay), "192.0.2.5/32") {
		t.Errorf("the overlay does not contain the normalized IP:\n%s", overlay)
	}
}

// TestHandleFormRollbackSuccess: successful PRG rollback → 303 flash=success.
func TestHandleFormRollbackSuccess(t *testing.T) {
	setupUIEnv(t)
	mux := NewPagesMux()

	overlayPath := filepath.Join(os.Getenv("CADDY_UI_MANAGED_DIR"), "waf-example_com.conf")
	if err := os.WriteFile(overlayPath, []byte("current state"), 0640); err != nil {
		t.Fatalf("failed seeding overlay: %v", err)
	}
	seedUISnapshot(t, "example_com", "2020-01-01T00-00-00Z.waf.conf", "# Caddy WAF UI managed - do not edit manually\n# domain: example.com | mode: Off | updated: 2020-01-01T00:00:00Z\n")

	rec := formPost(t, mux, "/sites/example.com/rollback", url.Values{"snapId": {"2020-01-01T00-00-00Z.waf.conf"}, "tab": {"rollback"}})

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("expected 303, got %d", rec.Code)
	}
	loc := rec.Header().Get("Location")
	if !strings.Contains(loc, "flash=success") || !strings.Contains(loc, "tab=rollback") {
		t.Errorf("expected flash=success preserving the tab, got %q", loc)
	}
	overlay, err := os.ReadFile(overlayPath)
	if err != nil {
		t.Fatalf("the overlay was not restored: %v", err)
	}
	if !strings.Contains(string(overlay), "SecRuleEngine Off") || !strings.Contains(string(overlay), "coraza_waf {") {
		t.Errorf("the overlay must restore the snapshot's mode in a regenerated overlay: %q", overlay)
	}
}

// TestHandleFormRollbackInvalidSnapshotFlashError: unsafe snapshot →
// flash=error without mutating (fail-fast of the service).
func TestHandleFormRollbackInvalidSnapshotFlashError(t *testing.T) {
	setupUIEnv(t)
	mux := NewPagesMux()

	overlayPath := filepath.Join(os.Getenv("CADDY_UI_MANAGED_DIR"), "waf-example_com.conf")
	if err := os.WriteFile(overlayPath, []byte("current state"), 0640); err != nil {
		t.Fatalf("failed seeding overlay: %v", err)
	}

	rec := formPost(t, mux, "/sites/example.com/rollback", url.Values{"snapId": {"../../etc/passwd"}})

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("expected 303, got %d", rec.Code)
	}
	if !strings.Contains(rec.Header().Get("Location"), "flash=invalid") {
		t.Errorf("an invalid snapshot must redirect with flash=invalid, got %q", rec.Header().Get("Location"))
	}
	overlay, err := os.ReadFile(overlayPath)
	if err != nil {
		t.Fatalf("failed reading overlay: %v", err)
	}
	if string(overlay) != "current state" {
		t.Errorf("an invalid snapshot must not mutate the overlay: %q", overlay)
	}
}

// TestFlashMessagesAreAllowListed: ?flash= only selects one of the UI's
// messages; arbitrary text is never displayed (content spoofing through a
// crafted link).
func TestFlashMessagesAreAllowListed(t *testing.T) {
	for _, key := range []string{"Your session expired: sign in at evil.example", "backfill:", "backfill:12 then visit evil.example", "<b>x</b>"} {
		if got := flashMessage(key); got != "" {
			t.Errorf("flash %q displayed %q", key, got)
		}
	}
	for _, key := range []string{"success", "error", "invalid", "stale", "conflict", "slug_conflict", "invalid_login", "logged_out", "backfill:12"} {
		if flashMessage(key) == "" {
			t.Errorf("known flash %q has no message", key)
		}
	}
	for key, want := range map[string]string{"error": "error", "invalid": "error", "stale": "error", "conflict": "error", "slug_conflict": "error", "success": "success"} {
		if got := flashType(key); got != want {
			t.Errorf("flashType(%q) = %q, want %q", key, got, want)
		}
	}
	setupUIEnv(t)
	rec := httptest.NewRecorder()
	HandleIndex(rec, httptest.NewRequest(http.MethodGet, "/?tab=sites&flash=visit+evil.example", nil))
	for _, c := range rec.Result().Cookies() {
		if c.Name == flashCookieName {
			t.Fatal("an unknown flash key must not be carried to the next page")
		}
	}
}

// TestFormFailureKeys: a failed form explains what to do next instead of a
// generic error.
func TestFormFailureKeys(t *testing.T) {
	cases := map[string]error{
		"invalid":       service.ErrInvalidMode,
		"stale":         service.ErrStaleDraft,
		"conflict":      service.ErrConflict,
		"slug_conflict": fmt.Errorf("wrapped: %w", service.ErrSlugConflict),
		"error":         errors.New("caddy rejected the configuration"),
	}
	for want, err := range cases {
		if got := flashKeyFor(err); got != want {
			t.Errorf("flashKeyFor(%v) = %q, want %q", err, got, want)
		}
	}
	if got := flashKeyFor(fmt.Errorf("x: %w", files.ErrInvalidBackup)); got != "invalid" {
		t.Errorf("invalid snapshot: got %q", got)
	}
	if got := flashKeyFor(fmt.Errorf("%w: bad cidr", service.ErrInvalidInput)); got != "invalid" {
		t.Errorf("invalid input: got %q", got)
	}
}
