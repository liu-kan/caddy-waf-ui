package ui

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/developmi/caddy-waf-ui/internal/domain"
	"github.com/developmi/caddy-waf-ui/internal/logs"
)

// TestLogPageURLPreservesFilters verifies that the pager links preserve the
// active explorer filters (tab/search/actionFilter) and do not emit
// out-of-range links.
func TestLogPageURLPreservesFilters(t *testing.T) {
	q := url.Values{"search": {"1.2.3.4"}, "actionFilter": {"BLOCKED"}}

	got := logPageURL(q, 2)
	// url.Values.Encode sorts alphabetically: actionFilter, page, search, tab.
	want := "/?actionFilter=BLOCKED&page=2&search=1.2.3.4&tab=logs"
	if got != want {
		t.Errorf("expected %q, got %q", want, got)
	}

	if got := logPageURL(q, 0); got != "" {
		t.Errorf("page=0 must not produce a link (out of range), got %q", got)
	}
	if got := logPageURL(url.Values{}, 1); got != "/?page=1&tab=logs" {
		t.Errorf("without filters it must only carry tab and page, got %q", got)
	}
}

// TestLogsPageRendersPager verifies that the pager renders with the current
// page and the prev/next links, and that the table entries are shown.
func TestLogsPageRendersPager(t *testing.T) {
	data := pageData{
		ActiveTab:    "logs",
		Logs:         []logs.AuditEntry{{RuleID: "942100", Client: "1.2.3.4", Action: "BLOCKED"}},
		LogPage:      2,
		LogPages:     3,
		LogPrevURL:   "/?tab=logs&page=1",
		LogNextURL:   "/?tab=logs&page=3",
		LogSearch:    "1.2.3.4",
		ActionFilter: "BLOCKED",
	}

	rec := httptest.NewRecorder()
	if err := executePage(rec, "logs", data); err != nil {
		t.Fatalf("render failed: %v", err)
	}
	body := rec.Body.String()
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if !strings.Contains(body, "Page 2 of 3") {
		t.Errorf("the pager must show the current page and the total: %s", body)
	}
	// html/template escapes & as &amp; in attribute context.
	if !strings.Contains(body, `href="/?tab=logs&amp;page=1"`) || !strings.Contains(body, `href="/?tab=logs&amp;page=3"`) {
		t.Errorf("the pager must link prev and next: %s", body)
	}
	if !strings.Contains(body, "942100") || !strings.Contains(body, "1.2.3.4") {
		t.Errorf("the table must render the entries of the page: %s", body)
	}
}

// TestLogsPageWithoutPagerRendersNoPager verifies that with a single page the
// pager is not rendered (negative branch of the template).
func TestLogsPageWithoutPagerRendersNoPager(t *testing.T) {
	data := pageData{
		ActiveTab: "logs",
		Logs:      []logs.AuditEntry{{RuleID: "942100"}},
		LogPage:   1,
		LogPages:  1,
	}

	rec := httptest.NewRecorder()
	if err := executePage(rec, "logs", data); err != nil {
		t.Fatalf("render failed: %v", err)
	}
	body := rec.Body.String()
	if strings.Contains(body, "Page 1 of 1") {
		t.Errorf("with a single page the pager must not be rendered: %s", body)
	}
	if !strings.Contains(body, "942100") {
		t.Errorf("the table must keep rendering the entry: %s", body)
	}
}

// seedRollbackEnv prepares managedDir + backupDir with a registered overlay
// and optional snapshots for the rollback tab.
func seedRollbackEnv(t *testing.T, snapshots map[string]string) {
	t.Helper()
	managedDir := t.TempDir()
	backupDir := t.TempDir()
	t.Setenv("CADDY_UI_MANAGED_DIR", managedDir)
	t.Setenv("CADDY_UI_DATA_DIR", t.TempDir())
	t.Setenv("CADDY_UI_BACKUP_DIR", backupDir)

	overlay := filepath.Join(managedDir, "waf-api_example_com.conf")
	if err := os.WriteFile(overlay, []byte("# domain: api.example.com | mode: On | updated: 2026-08-07T00:00:00Z\n"), 0640); err != nil {
		t.Fatalf("failed seeding overlay: %v", err)
	}
	for name, content := range snapshots {
		slugDir := filepath.Join(backupDir, "api_example_com")
		if err := os.MkdirAll(slugDir, 0750); err != nil {
			t.Fatalf("failed creating backups dir: %v", err)
		}
		if err := os.WriteFile(filepath.Join(slugDir, name), []byte(content), 0640); err != nil {
			t.Fatalf("failed seeding snapshot %s: %v", name, err)
		}
	}
}

// TestRollbackTabRendersSnapshots: the rollback tab must load the real
// snapshots of the domain (files.ListBackups) and render the restore row with
// the PRG form (action + snapId) (backup-recovery spec).
func TestRollbackTabRendersSnapshots(t *testing.T) {
	seedRollbackEnv(t, map[string]string{
		"2020-01-01T00-00-00Z.waf.conf": "v1",
	})

	req := httptest.NewRequest(http.MethodGet, "/?tab=rollback&domain=api.example.com", nil)
	data := buildPageData(req, "rollback", scanSites())
	if len(data.Snapshots) != 1 {
		t.Fatalf("expected 1 snapshot loaded from the real listing, got %d", len(data.Snapshots))
	}
	if data.Snapshots[0].FileType != "waf" {
		t.Errorf("the loaded snapshot must keep its type: %+v", data.Snapshots[0])
	}

	rec := httptest.NewRecorder()
	if err := executePage(rec, "rollback", data); err != nil {
		t.Fatalf("render failed: %v", err)
	}
	body := rec.Body.String()
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if !strings.Contains(body, "2020-01-01T00-00-00Z") {
		t.Errorf("the timeline must show the timestamp of the snapshot: %s", body)
	}
	if !strings.Contains(body, `action="/sites/api.example.com/rollback"`) {
		t.Errorf("each snapshot must have its PRG restore form: %s", body)
	}
	if !strings.Contains(body, `name="snapId" value="2020-01-01T00-00-00Z.waf.conf"`) {
		t.Errorf("the form must send the full snapshot name: %s", body)
	}
	if !strings.Contains(body, "Restore This Snapshot") {
		t.Errorf("the restore button must exist: %s", body)
	}
}

// TestRollbackTabEmptyState: without backups the rollback tab renders the
// honest empty state (backup-recovery spec: "empty state"), never 500.
func TestRollbackTabEmptyState(t *testing.T) {
	seedRollbackEnv(t, nil)

	req := httptest.NewRequest(http.MethodGet, "/?tab=rollback&domain=api.example.com", nil)
	data := buildPageData(req, "rollback", scanSites())
	if len(data.Snapshots) != 0 {
		t.Fatalf("without backups an empty list was expected, got %d", len(data.Snapshots))
	}

	rec := httptest.NewRecorder()
	if err := executePage(rec, "rollback", data); err != nil {
		t.Fatalf("render failed: %v", err)
	}
	body := rec.Body.String()
	if rec.Code != http.StatusOK {
		t.Fatalf("without backups expected 200, got %d", rec.Code)
	}
	if !strings.Contains(body, "No configuration snapshots created yet for this domain.") {
		t.Errorf("without backups it must render the honest empty state: %s", body)
	}
	if strings.Contains(body, "Restore This Snapshot") {
		t.Errorf("without snapshots there must be no restore buttons: %s", body)
	}
}

// TestOverviewRendersDegradedBadge: a site with Degraded=true (unknown header
// mode) must show the "degraded" badge in the overview table row (W1) - the
// UI must never present an invented mode.
func TestOverviewRendersDegradedBadge(t *testing.T) {
	data := pageData{
		ActiveTab: "overview",
		Sites: []*domain.Site{
			{Domain: "api.example.com", Mode: domain.ModeDetectionOnly, Degraded: true},
			{Domain: "web.example.com", Mode: domain.ModeOn},
		},
		SitesOn:        1,
		SitesDetection: 1,
	}

	rec := httptest.NewRecorder()
	if err := executePage(rec, "overview", data); err != nil {
		t.Fatalf("render failed: %v", err)
	}
	body := rec.Body.String()
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	// The visible badge is the span with the text "degraded" (the CSS class
	// .badge-degraded is always in the <style> - it is not render evidence).
	if !strings.Contains(body, ">degraded<") {
		t.Errorf("the degraded site must show the 'degraded' badge: %s", body)
	}
}

// TestOverviewHidesDegradedBadgeForHealthySites (triangulation): the sites
// with a valid mode do NOT carry a degraded badge.
func TestOverviewHidesDegradedBadgeForHealthySites(t *testing.T) {
	data := pageData{
		ActiveTab: "overview",
		Sites:     []*domain.Site{{Domain: "web.example.com", Mode: domain.ModeOn}},
		SitesOn:   1,
	}

	rec := httptest.NewRecorder()
	if err := executePage(rec, "overview", data); err != nil {
		t.Fatalf("render failed: %v", err)
	}
	if body := rec.Body.String(); strings.Contains(body, ">degraded<") {
		t.Errorf("a healthy site must not show the degraded badge: %s", body)
	}
}

// TestSitesRendersDegradedBadge: the sites view (current domain) must also
// expose the badge when the site is degraded (W1).
func TestSitesRendersDegradedBadge(t *testing.T) {
	data := pageData{
		ActiveTab:   "sites",
		Sites:       []*domain.Site{{Domain: "api.example.com", Mode: domain.ModeDetectionOnly, Degraded: true}},
		CurrentSite: &domain.Site{Domain: "api.example.com", Mode: domain.ModeDetectionOnly, Degraded: true},
	}

	rec := httptest.NewRecorder()
	if err := executePage(rec, "sites", data); err != nil {
		t.Fatalf("render failed: %v", err)
	}
	body := rec.Body.String()
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if !strings.Contains(body, ">degraded<") {
		t.Errorf("the sites view must show the 'degraded' badge: %s", body)
	}
}

// findCookie locates a cookie by name in the response (helpers of the
// one-shot flash tests).
func findCookie(cookies []*http.Cookie, name string) *http.Cookie {
	for _, c := range cookies {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// TestOverviewScanFailureRendersEmptyState: if the overlay scan fails
// (corrupt managed dir), the overview view responds 200 with the honest
// empty state and the translated flash - never 500 (W2, scanSites-error
// branch of pages). The flash is consumed one-shot: the ?flash= redirects to
// a clean URL with the ephemeral cookie, and the render consumes and deletes
// the cookie (a refresh does not re-show it).
func TestOverviewScanFailureRendersEmptyState(t *testing.T) {
	file := filepath.Join(t.TempDir(), "managed-es-un-archivo")
	if err := os.WriteFile(file, []byte("x"), 0640); err != nil {
		t.Fatalf("failed seeding file: %v", err)
	}
	t.Setenv("CADDY_UI_MANAGED_DIR", file)
	t.Setenv("CADDY_UI_BACKUP_DIR", t.TempDir())

	for flash, want := range map[string]string{
		"success":     "Configuration updated successfully.",
		"error":       "The configuration could not be applied.",
		"logged_out":  "You have been signed out.",
		"unknown-key": "unknown-key", // flashMessage default: the key passes through as-is
	} {
		// First GET with ?flash= (PRG): consumed with a clean redirect + cookie.
		req := httptest.NewRequest(http.MethodGet, "/?flash="+flash, nil)
		rec := httptest.NewRecorder()
		HandleIndex(rec, req)

		if rec.Code != http.StatusFound {
			t.Fatalf("flash=%s: the one-shot consumption must redirect, got %d", flash, rec.Code)
		}
		if loc := rec.Header().Get("Location"); strings.Contains(loc, "flash=") {
			t.Errorf("flash=%s: the consuming redirect must remove ?flash=, got %q", flash, loc)
		}
		cookie := findCookie(rec.Result().Cookies(), flashCookieName)
		if cookie == nil {
			t.Fatalf("flash=%s: the redirect must set the ephemeral flash cookie", flash)
		}

		// Second GET: render with a typed toast and the cookie consumed
		// (deleted).
		req2 := httptest.NewRequest(http.MethodGet, "/", nil)
		req2.AddCookie(cookie)
		rec2 := httptest.NewRecorder()
		HandleIndex(rec2, req2)

		if rec2.Code != http.StatusOK {
			t.Fatalf("flash=%s: expected 200 with the empty state, got %d", flash, rec2.Code)
		}
		body := rec2.Body.String()
		if !strings.Contains(body, "No managed domains registered yet.") {
			t.Errorf("flash=%s: the overview must render the honest empty state", flash)
		}
		if !strings.Contains(body, want) {
			t.Errorf("flash=%s: the toast must show %q, got: %s", flash, want, body)
		}
		if del := findCookie(rec2.Result().Cookies(), flashCookieName); del == nil || del.MaxAge >= 0 {
			t.Errorf("flash=%s: the render must delete the flash cookie (one-shot)", flash)
		}
		// Typing (fix J3-1): error → red with role=alert; the rest → green
		// role=status.
		if flash == "error" {
			if !strings.Contains(body, `class="toast-notice toast-notice--error"`) || !strings.Contains(body, `role="alert"`) {
				t.Errorf("flash=error must render as an alert (red + role=alert): %s", body)
			}
		} else if !strings.Contains(body, `role="status"`) {
			t.Errorf("flash=%s must render as a success (green + role=status): %s", flash, body)
		}
	}
}

// TestHandleIndexRendersOverview: with a healthy environment, GET / renders
// the overview (200) through the pages mux (W2, main branch of HandleIndex).
func TestHandleIndexRendersOverview(t *testing.T) {
	seedRollbackEnv(t, nil)
	mux := NewPagesMux()

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "Managed Per-Site WAF Domains") || !strings.Contains(body, "Caddy WAF UI") {
		t.Errorf("the overview did not render completely: %s", body)
	}
}

// TestHandleLoginPageWithoutSessionRendersForm: GET /login without a session
// renders the form (200). The one-shot flash first redirects to a clean URL
// and is consumed in the next render.
func TestHandleLoginPageWithoutSessionRendersForm(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/login?flash=invalid_login", nil)
	rec := httptest.NewRecorder()
	HandleLoginPage(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("the one-shot flash consumption must redirect, got %d", rec.Code)
	}
	cookie := findCookie(rec.Result().Cookies(), flashCookieName)
	if cookie == nil {
		t.Fatal("the consuming redirect must set the ephemeral flash cookie")
	}

	req2 := httptest.NewRequest(http.MethodGet, "/login", nil)
	req2.AddCookie(cookie)
	rec2 := httptest.NewRecorder()
	HandleLoginPage(rec2, req2)

	if rec2.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec2.Code)
	}
	body := rec2.Body.String()
	if !strings.Contains(body, "Invalid access token.") {
		t.Errorf("the invalid_login flash must be translated in the login: %s", body)
	}
}

// TestHandleLoginPageWithSessionRedirects: with a valid session, /login
// redirects to / (302).
func TestHandleLoginPageWithSessionRedirects(t *testing.T) {
	t.Setenv("CADDY_UI_TOKEN", "super-secret-token")
	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	req.AddCookie(&http.Cookie{Name: "CADDY_UI_TOKEN", Value: "super-secret-token", Path: "/", HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode})
	rec := httptest.NewRecorder()
	HandleLoginPage(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("expected 302 with a valid session, got %d", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/" {
		t.Errorf("expected Location /, got %q", loc)
	}
}

// TestExecutePageUnknownTemplateError: an unknown template produces an error
// (executePage branch) and the handler responds 500.
func TestExecutePageUnknownTemplateError(t *testing.T) {
	rec := httptest.NewRecorder()
	err := executePage(rec, "no-existe", pageData{})
	if err == nil {
		t.Fatal("an unknown template must return an error")
	}

	rec2 := httptest.NewRecorder()
	HandleIndex(rec2, httptest.NewRequest(http.MethodGet, "/?tab=no-existe", nil))
	if rec2.Code != http.StatusInternalServerError {
		t.Errorf("an unknown tab must respond 500, got %d", rec2.Code)
	}
}

// TestLoadLogsErrorBranchReturnsEmpty: without an audit log file, loadLogs
// returns an empty page (honest empty state of the logs tab).
func TestLoadLogsErrorBranchReturnsEmpty(t *testing.T) {
	t.Setenv("CADDY_UI_AUDIT_LOG", filepath.Join(t.TempDir(), "no-existe.log"))
	t.Setenv("CADDY_UI_MANAGED_DIR", t.TempDir())
	t.Setenv("CADDY_UI_BACKUP_DIR", t.TempDir())

	req := httptest.NewRequest(http.MethodGet, "/?tab=logs", nil)
	data := buildPageData(req, "logs", nil)

	if len(data.Logs) != 0 || data.LogPages != 0 {
		t.Errorf("without an audit log it must stay in the empty state, got %d entries / %d pages", len(data.Logs), data.LogPages)
	}
}

// TestLoadLogsSuccessPopulatesEntries (triangulation): with a real audit log
// the logs tab is fed by the entries.
func TestLoadLogsSuccessPopulatesEntries(t *testing.T) {
	t.Setenv("CADDY_UI_AUDIT_LOG", filepath.Join("..", "logs", "testdata", "audit-valid.jsonl"))
	t.Setenv("CADDY_UI_MANAGED_DIR", t.TempDir())
	t.Setenv("CADDY_UI_BACKUP_DIR", t.TempDir())

	req := httptest.NewRequest(http.MethodGet, "/?tab=logs", nil)
	data := buildPageData(req, "logs", nil)

	if len(data.Logs) == 0 {
		t.Fatal("with a real audit log the logs tab must load entries")
	}
	if data.LogPages < 1 {
		t.Errorf("with entries there must be at least 1 page, got %d", data.LogPages)
	}
}
