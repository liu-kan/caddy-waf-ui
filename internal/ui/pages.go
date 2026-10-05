package ui

import (
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/developmi/caddy-waf-ui/internal/auth"
	"github.com/developmi/caddy-waf-ui/internal/caddy"
	"github.com/developmi/caddy-waf-ui/internal/config"
	"github.com/developmi/caddy-waf-ui/internal/domain"
	"github.com/developmi/caddy-waf-ui/internal/files"
	"github.com/developmi/caddy-waf-ui/internal/iprules"
	"github.com/developmi/caddy-waf-ui/internal/logs"
	"github.com/developmi/caddy-waf-ui/internal/waf"
)

// managedDir returns the managed overlays directory. Centralized in config
// (finding J5-3): the environment read used to live triplicated in
// internal/service, internal/files and this package.
func managedDir() string {
	return config.ManagedDir()
}

// pageData is the data model common to all SSR pages. Each template consumes
// only the fields it needs; the views whose data comes from later phases
// (logs, snapshots) arrive as an honest empty state with the shape already
// defined in the design (AuditEntry, BackupInfo).
type pageData struct {
	ActiveTab        string
	Flash            string
	FlashType        string
	CSRF             string
	Sites            []*domain.Site
	CurrentSite      *domain.Site
	SitesOn          int
	SitesDetection   int
	TotalExclusions  int
	TotalIPRules     int
	TotalDenyIPs     int
	TotalAllowIPs    int
	Logs             []logs.AuditEntry
	LogSearch        string
	ActionFilter     string
	LogPage          int
	LogPages         int
	LogPrevURL       string
	LogNextURL       string
	ActiveExclusions []waf.Exclusion
	ExclusionsConf   string
	ActiveIPRules    iprules.IPRules
	IPRulesConf      string
	Snapshots        []files.BackupInfo
	WafConf          string
	Readback         caddy.ReadbackState

	wafData
}

// flashMessage translates the ?flash= key to a visible message (English UI
// copy; the keys success/error/invalid_login/logged_out are machine keys).
func flashMessage(key string) string {
	switch key {
	case "success":
		return "Configuration updated successfully."
	case "error":
		return "The configuration could not be applied. Check the service logs for details."
	case "invalid_login":
		return "Invalid access token."
	case "logged_out":
		return "You have been signed out."
	default:
		if n, ok := strings.CutPrefix(key, "backfill:"); ok {
			return "Loki backfill finished: " + n + " event(s) imported."
		}
		return key
	}
}

// flashType maps the flash key to the visual type of the toast (fix J3-1):
// error → red variant with role="alert" and aria-live="assertive"; the rest
// is presented as a green success/info with role="status" and
// aria-live="polite".
func flashType(key string) string {
	if key == "error" {
		return "error"
	}
	return "success"
}

// flashCookie carries the flash between the consuming redirect (one-shot) and
// the page render: the URL stays clean and a refresh does not re-show the old
// toast. The cookie is ephemeral (60s), HttpOnly + SameSite=Lax.
const flashCookieName = "ui_flash"

// setFlashCookie sets the ephemeral flash cookie for the consuming hop (same
// flag convention as the session cookie: HttpOnly + Secure).
func setFlashCookie(w http.ResponseWriter, key string) {
	http.SetCookie(w, &http.Cookie{
		Name:     flashCookieName,
		Value:    key,
		Path:     "/",
		MaxAge:   60,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
}

// takeFlashCookie reads the flash cookie and deletes it (one-shot: it is
// consumed on the first render; a later refresh does not re-show it).
func takeFlashCookie(w http.ResponseWriter, r *http.Request) (string, bool) {
	cookie, err := r.Cookie(flashCookieName)
	if err != nil {
		return "", false
	}
	http.SetCookie(w, &http.Cookie{
		Name:     flashCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
	return cookie.Value, true
}

// cleanURL returns the same path without the ?flash= parameter (one-shot:
// the toast is consumed with a clean redirect; the cookie carries the
// message). It preserves tab/domain/search/actionFilter/page so the context
// of the view survives the hop.
func cleanURL(q url.Values) string {
	clean := url.Values{}
	for _, key := range []string{"tab", "domain", "search", "actionFilter", "page"} {
		if value := q.Get(key); value != "" {
			clean.Set(key, value)
		}
	}
	if len(clean) == 0 {
		return "/"
	}
	return "/?" + clean.Encode()
}

// scanSites scans the sites discovered in ui-managed (scanner, D2: read per
// request) and returns them sorted by domain. The in-memory Registry was
// removed (finding J5-6): the abstraction was created and discarded per
// request without providing shared state.
func scanSites() []*domain.Site {
	scanner := domain.NewScanner(managedDir())
	sites, err := scanner.Scan()
	if err != nil {
		slog.Warn("error scanning overlays", "error", err)
	}
	sort.Slice(sites, func(i, j int) bool { return sites[i].Domain < sites[j].Domain })
	return sites
}

// findSite locates the site selected by ?domain=; without a match (or without
// sites) it uses the first one of the list so the views with a selector do
// not stay empty.
func findSite(sites []*domain.Site, domainName string) *domain.Site {
	for _, site := range sites {
		if site.Domain == domainName {
			return site
		}
	}
	if len(sites) > 0 {
		return sites[0]
	}
	return nil
}

// readOverlay returns the current content of an overlay ("" if it does not
// exist). It is the real deployed state, the source of truth for the previews.
func readOverlay(path string) string {
	content, err := os.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			slog.Warn("error reading overlay", "path", path, "error", err)
		}
		return ""
	}
	return string(content)
}

// countOverlays walks the exclusions and IP rules overlays of ALL the domains
// for the overview metrics (the per-domain views use the parsers of
// overlay.go).
func countOverlays() (exclusions, ipRules, deny, allow int) {
	entries, err := os.ReadDir(managedDir())
	if err != nil {
		return 0, 0, 0, 0
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		path := filepath.Join(managedDir(), name)
		switch {
		case strings.HasPrefix(name, files.FileTypeExclusions+"-") && strings.HasSuffix(name, ".conf"):
			if ex, err := readExclusionsFile(path); err == nil {
				exclusions += len(ex)
			}
		case strings.HasPrefix(name, files.FileTypeIPRules+"-") && strings.HasSuffix(name, ".conf"):
			if rules, err := readIPRulesFile(path); err == nil {
				ipRules += len(rules.Denylist) + len(rules.Allowlist)
				deny += len(rules.Denylist)
				allow += len(rules.Allowlist)
			}
		}
	}
	return exclusions, ipRules, deny, allow
}

// csrfOrEmpty derives the CSRF token for the forms; if the token is not
// configured it returns "" (the session middleware already blocks all
// access).
func csrfOrEmpty() string {
	token, err := auth.CSRFValue()
	if err != nil {
		return ""
	}
	return token
}

// logPageURL builds the URL of a log explorer page preserving the active
// filters (tab/search/actionFilter). page < 1 returns "" so the template does
// not render the link (out of range).
func logPageURL(q url.Values, page int) string {
	if page < 1 {
		return ""
	}
	query := url.Values{}
	query.Set("tab", "logs")
	if search := q.Get("search"); search != "" {
		query.Set("search", search)
	}
	if action := q.Get("actionFilter"); action != "" {
		query.Set("actionFilter", action)
	}
	query.Set("page", strconv.Itoa(page))
	return "/?" + query.Encode()
}

// loadLogs reads the requested page of the Coraza audit log (D7) with the
// query string filters. If the file does not exist yet (first start) a warn
// is logged and the table stays in an honest empty state.
func loadLogs(q url.Values) (logs.Page, bool) {
	page, _ := strconv.Atoi(q.Get("page"))
	result, err := logs.Read(logs.AuditLogPath(), logs.Options{
		Search: q.Get("search"),
		Action: q.Get("actionFilter"),
		Page:   page,
	})
	if err != nil {
		slog.Warn("failed to read the audit log", "path", logs.AuditLogPath(), "error", err)
		return logs.Page{}, false
	}
	return result, true
}

// buildPageData builds the data model of the active page. The logs view is
// fed by the real audit log (Phase 3); rollback stays in an honest empty
// state (read in Phase 4).
func buildPageData(r *http.Request, tab string, sites []*domain.Site) pageData {
	q := r.URL.Query()
	data := pageData{
		ActiveTab:    tab,
		Flash:        flashMessage(q.Get("flash")),
		FlashType:    flashType(q.Get("flash")),
		CSRF:         csrfOrEmpty(),
		Sites:        sites,
		LogSearch:    q.Get("search"),
		ActionFilter: q.Get("actionFilter"),
		Logs:         []logs.AuditEntry{},
		Snapshots:    []files.BackupInfo{},
	}

	if tab == "logs" {
		if result, ok := loadLogs(q); ok {
			data.Logs = result.Entries
			data.LogPage = result.Page
			data.LogPages = result.Pages
			data.LogPrevURL = logPageURL(q, result.Page-1)
			data.LogNextURL = logPageURL(q, result.Page+1)
		}
	}

	data.CurrentSite = findSite(sites, q.Get("domain"))
	if data.CurrentSite != nil {
		domainName := data.CurrentSite.Domain
		data.WafConf = readOverlay(files.WAFConfigPath(managedDir(), domainName))
		data.ExclusionsConf = readOverlay(files.ExclusionsConfigPath(managedDir(), domainName))
		data.IPRulesConf = readOverlay(files.IPRulesConfigPath(managedDir(), domainName))
		if ex, err := readExclusions(domainName); err == nil {
			data.ActiveExclusions = ex
		}
		if rules, err := readIPRules(domainName); err == nil {
			data.ActiveIPRules = rules
		}
	}

	// The rollback tab is fed by the REAL snapshots of the domain (Phase 4);
	// without backups (or with a nonexistent directory) the honest empty
	// state remains.
	if tab == "rollback" && data.CurrentSite != nil {
		snapshots, err := files.ListBackups(data.CurrentSite.Domain)
		if err != nil {
			slog.Warn("failed to list snapshots", "domain", data.CurrentSite.Domain, "error", err)
		} else {
			data.Snapshots = snapshots
		}
	}

	for _, site := range sites {
		switch site.Mode {
		case domain.ModeOn:
			data.SitesOn++
		case domain.ModeDetectionOnly:
			data.SitesDetection++
		}
	}
	data.TotalExclusions, data.TotalIPRules, data.TotalDenyIPs, data.TotalAllowIPs = countOverlays()
	data.Readback = caddy.LastReadback()
	buildWAFData(r, tab, &data)
	return data
}

// executePage executes the base template of the given page (all the
// templates define the "base" block; the content pages additionally define
// "content").
func executePage(w http.ResponseWriter, page string, data pageData) error {
	tmpl, ok := templates[page]
	if !ok {
		return fmt.Errorf("unknown template: %s", page)
	}
	return tmpl.ExecuteTemplate(w, "base", data)
}

// HandleIndex renders the active page by ?tab (SSR; web-ui spec: the page
// renders 200, without template errors, with automatic escaping).
func HandleIndex(w http.ResponseWriter, r *http.Request) {
	tab := r.URL.Query().Get("tab")
	if tab == "" {
		tab = "overview"
	}

	// One-shot flash (fix J3-12): the ?flash= of the PRG is consumed with a
	// clean redirect that carries the message in an ephemeral cookie; a
	// refresh of the clean URL does not re-show the toast.
	if key := r.URL.Query().Get("flash"); key != "" {
		setFlashCookie(w, key)
		http.Redirect(w, r, cleanURL(r.URL.Query()), http.StatusFound)
		return
	}

	data := buildPageData(r, tab, scanSites())
	if key, ok := takeFlashCookie(w, r); ok {
		data.Flash = flashMessage(key)
		data.FlashType = flashType(key)
	}
	if err := executePage(w, tab, data); err != nil {
		slog.Error("error rendering page", "tab", tab, "error", err)
		http.Error(w, "Internal error rendering the page", http.StatusInternalServerError)
	}
}

// HandleLoginPage renders the login form (public route). If there is already
// a valid session it redirects to the index. The flash (?flash= or cookie)
// receives the same one-shot treatment as the index.
func HandleLoginPage(w http.ResponseWriter, r *http.Request) {
	if auth.HasValidSession(r) {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	if key := r.URL.Query().Get("flash"); key != "" {
		setFlashCookie(w, key)
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	data := pageData{}
	if key, ok := takeFlashCookie(w, r); ok {
		data.Flash = flashMessage(key)
		data.FlashType = flashType(key)
	}
	if err := executePage(w, "login", data); err != nil {
		slog.Error("error rendering login", "error", err)
		http.Error(w, "Internal error rendering the page", http.StatusInternalServerError)
	}
}

// NewPagesMux assembles the SSR routes protected by session (cookie or
// Bearer). The mutations are mounted under /sites/{domain}/... and go through
// the CSRF middleware in cmd/server/main.go (task 2.7).
func NewPagesMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /", HandleIndex)
	mux.HandleFunc("POST /sites/{domain}/mode", HandleFormSetMode)
	mux.HandleFunc("POST /sites/{domain}/exclusions", HandleFormAddExclusion)
	mux.HandleFunc("POST /sites/{domain}/exclusions/remove", HandleFormRemoveExclusion)
	mux.HandleFunc("POST /sites/{domain}/policy", HandleFormPolicy)
	mux.HandleFunc("POST /events/backfill", HandleFormBackfill)
	mux.HandleFunc("POST /sites/{domain}/iprules", HandleFormAddIPRule)
	mux.HandleFunc("POST /sites/{domain}/rollback", HandleFormRollback)
	mux.HandleFunc("POST /logout", HandleLogout)
	return mux
}

// NewLoginMux exposes the public authentication routes (without session).
func NewLoginMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /login", HandleLoginPage)
	mux.HandleFunc("POST /login", HandleLogin)
	return mux
}
