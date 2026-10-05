package ui

import (
	"net/http"
)

// NewRouter assembles the RESTful routes of the management API.
// The path params (Go 1.22+ ServeMux) replace the flat endpoints: the old
// contract (/api/mode, /api/exclusions, /api/iprules) no longer exists and
// naturally returns 404. /health does NOT live here: main.go mounts it apart
// (outside the authenticated mux) for the container healthchecks.
func NewRouter() *http.ServeMux {
	mux := http.NewServeMux()

	// RESTful WAF and security configuration endpoints
	mux.HandleFunc("PUT /api/sites/{domain}/mode", HandleSetMode)
	mux.HandleFunc("PUT /api/sites/{domain}/exclusions", HandleSetExclusions)
	mux.HandleFunc("PUT /api/sites/{domain}/iprules", HandleSetIPRules)

	// RESTful snapshot and rollback endpoints (backup-recovery spec)
	mux.HandleFunc("GET /api/sites/{domain}/backups", HandleListBackups)
	mux.HandleFunc("POST /api/sites/{domain}/rollback", HandleRollback)

	// Policy, impact estimates and the change journal
	mux.HandleFunc("GET /api/sites/{domain}/policy", HandleAPIGetPolicy)
	mux.HandleFunc("PUT /api/sites/{domain}/policy", HandleAPISetPolicy)
	mux.HandleFunc("POST /api/sites/{domain}/impact", HandleAPIImpact)
	mux.HandleFunc("GET /api/changes", HandleAPIChanges)

	// WAF events, explanations, rule dictionary and retrospective analysis
	mux.HandleFunc("GET /api/events", HandleAPIEvents)
	mux.HandleFunc("GET /api/events/{tx}", HandleAPIEvent)
	mux.HandleFunc("GET /api/events/{tx}/explain", HandleAPIExplain)
	mux.HandleFunc("GET /api/rules", HandleAPIRules)
	mux.HandleFunc("GET /api/rules/{id}", HandleAPIRule)
	mux.HandleFunc("GET /api/analysis", HandleAPIAnalysis)
	mux.HandleFunc("POST /api/loki/backfill", HandleAPIBackfill)

	return mux
}

// HealthHandler returns the public status endpoint. It is mounted separately
// in main.go, OUTSIDE the auth middleware, so the container healthchecks do
// not need credentials.
func HealthHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}
}
