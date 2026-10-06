package ui

import (
	"log/slog"
	"net/http"
	"net/url"

	"github.com/developmi/caddy-waf-ui/internal/auth"
	"github.com/developmi/caddy-waf-ui/internal/domain"
	"github.com/developmi/caddy-waf-ui/internal/service"
	"github.com/developmi/caddy-waf-ui/internal/waf"
)

// redirectAfterForm applies the PRG pattern (web-ui spec): POST + 303 with
// ?flash=, preserving ?tab, ?domain, ?search and ?actionFilter so the source
// view (and its context) survives the redirect. A 303 never re-sends the
// POST on refresh.
func redirectAfterForm(w http.ResponseWriter, r *http.Request, flash string) {
	q := url.Values{}
	for _, key := range []string{"tab", "domain", "search", "actionFilter", "tx", "node", "source", "ts"} {
		if value := r.FormValue(key); value != "" {
			q.Set(key, value)
		}
	}
	q.Set("flash", flash)
	http.Redirect(w, r, "/?"+q.Encode(), http.StatusSeeOther)
}

// HandleLogin processes POST /login (public route): it validates the token
// and sets the session cookie (D3). The failure emits a security event
// (LE-1/D10: slog.Warn with the RemoteAddr, NEVER as ui_request - D2 - and
// without credential material; the success is silent) and redirects to the
// login with flash=invalid_login (PRG, without mutated state).
func HandleLogin(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	if auth.Login(w, r.FormValue("token")) {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	slog.Warn("login rejected", "remote_ip", r.RemoteAddr)
	http.Redirect(w, r, "/login?flash=invalid_login", http.StatusSeeOther)
}

// HandleLogout processes POST /logout: it invalidates the cookie and returns
// to the login.
func HandleLogout(w http.ResponseWriter, r *http.Request) {
	auth.Logout(w)
	http.Redirect(w, r, "/login?flash=logged_out", http.StatusSeeOther)
}

// HandleFormSetMode processes POST /sites/{domain}/mode (PRG): it delegates
// to the shared chain (validate → backup → generate → write → reload →
// audit). An invalid mode returns 303 ?flash=error without mutating anything
// (the service validates BEFORE the backup).
func HandleFormSetMode(w http.ResponseWriter, r *http.Request) {
	domainName := r.PathValue("domain")
	mode := domain.WAFMode(r.FormValue("mode"))
	if err := service.ApplyMode(actor(r, r.FormValue("reason")), domainName, mode); err != nil {
		redirectAfterForm(w, r, "error")
		return
	}
	redirectAfterForm(w, r, "success")
}

// HandleFormAddExclusion processes POST /sites/{domain}/exclusions: it
// merges the new exclusion with the active ones (overlay.go) and sends the
// COMPLETE list to the shared chain - which replaces the overlay. Without the
// merge, adding a rule would silently delete the existing ones. With
// action=preview nothing is changed: the page shows the generated diff and
// the estimated impact over the stored events.
func HandleFormAddExclusion(w http.ResponseWriter, r *http.Request) {
	domainName := r.PathValue("domain")
	_ = r.ParseForm()
	exclusion, form := exclusionFromRequest(r)
	if form.Expires != "" && exclusion.Expires.IsZero() {
		renderTab(w, r, "exclusions", domainName, func(d *pageData) { d.FormError = "Invalid expiry: use a UTC date and time"; d.ExclusionForm = form })
		return
	}

	current, err := readExclusions(domainName)
	if err != nil {
		redirectAfterForm(w, r, "error")
		return
	}
	merged := append(current, exclusion)

	if r.FormValue("action") == "preview" {
		if err := waf.ValidateExclusions([]waf.Exclusion{exclusion}); err != nil {
			renderTab(w, r, "exclusions", domainName, func(d *pageData) {
				d.ExclusionForm, d.FormError = form, err.Error()
			})
			return
		}
		previewExclusions(w, r, domainName, form, exclusion, merged)
		return
	}
	if err := service.ApplyExclusionsDraft(actor(r, form.Reason), domainName, merged, r.FormValue("draft_id")); err != nil {
		redirectAfterForm(w, r, "error")
		return
	}
	redirectAfterForm(w, r, "success")
}

// HandleFormAddIPRule processes POST /sites/{domain}/iprules: it adds the
// entry to the DENY or ALLOW list of the current state and sends the complete
// list to the shared chain (same merge reason as exclusions).
func HandleFormAddIPRule(w http.ResponseWriter, r *http.Request) {
	domainName := r.PathValue("domain")
	cidr := r.FormValue("cidr")
	action := r.FormValue("action")

	current, err := readIPRules(domainName)
	if err != nil {
		redirectAfterForm(w, r, "error")
		return
	}
	switch action {
	case "DENY":
		current.Denylist = append(current.Denylist, cidr)
	case "ALLOW":
		current.Allowlist = append(current.Allowlist, cidr)
	default:
		redirectAfterForm(w, r, "error")
		return
	}

	if err := service.ApplyIPRules(actor(r, r.FormValue("reason")), domainName, current); err != nil {
		redirectAfterForm(w, r, "error")
		return
	}
	redirectAfterForm(w, r, "success")
}

// HandleFormRollback processes POST /sites/{domain}/rollback (PRG, contract
// of the .jinja DOM: domain + snapId): it restores the given snapshot (full
// name {ISO8601}.{type}.conf) through the shared chain. The failure redirects
// with flash=error without mutating anything (validation fail-fast in the
// service).
func HandleFormRollback(w http.ResponseWriter, r *http.Request) {
	domainName := r.PathValue("domain")
	backupID := r.FormValue("snapId")

	if err := service.ApplyRollback(actor(r, r.FormValue("reason")), domainName, backupID); err != nil {
		redirectAfterForm(w, r, "error")
		return
	}
	redirectAfterForm(w, r, "success")
}
