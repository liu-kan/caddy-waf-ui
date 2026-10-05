package ui

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/developmi/caddy-waf-ui/internal/analysis"
	"github.com/developmi/caddy-waf-ui/internal/crs"
	"github.com/developmi/caddy-waf-ui/internal/events"
	"github.com/developmi/caddy-waf-ui/internal/journal"
	"github.com/developmi/caddy-waf-ui/internal/service"
	"github.com/developmi/caddy-waf-ui/internal/waf"
)

func writeJSONValue(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(true)
	_ = enc.Encode(v)
}

func requireStore(w http.ResponseWriter) *events.Store {
	store := eventStore()
	if store == nil {
		http.Error(w, "Event store unavailable", http.StatusServiceUnavailable)
	}
	return store
}

// queryFromRequest maps the event filters of an API request.
func queryFromRequest(r *http.Request) events.Query {
	q := r.URL.Query()
	_, dur := parseRange(q.Get("range"), "24h")
	query := events.Query{From: time.Now().UTC().Add(-dur), Site: q.Get("site"), Action: q.Get("action"), IP: q.Get("ip"),
		RuleID: atoiDefault(q.Get("rule"), 0), PathPrefix: q.Get("path"), Text: q.Get("q"),
		Limit: atoiDefault(q.Get("limit"), 100), Offset: atoiDefault(q.Get("offset"), 0)}
	if from, err := time.Parse(time.RFC3339, q.Get("from")); err == nil {
		query.From = from
	}
	if to, err := time.Parse(time.RFC3339, q.Get("to")); err == nil {
		query.To = to
	}
	if query.Limit < 1 || query.Limit > 1000 {
		query.Limit = 100
	}
	if query.Offset < 0 {
		query.Offset = 0
	}
	return query
}

// HandleAPIEvents lists events, newest first.
func HandleAPIEvents(w http.ResponseWriter, r *http.Request) {
	store := requireStore(w)
	if store == nil {
		return
	}
	list, total := store.Query(queryFromRequest(r))
	if list == nil {
		list = []*events.Event{}
	}
	writeJSONValue(w, http.StatusOK, map[string]any{"total": total, "events": list})
}

// HandleAPIEvent returns one event.
func HandleAPIEvent(w http.ResponseWriter, r *http.Request) {
	store := requireStore(w)
	if store == nil {
		return
	}
	e, ok := store.Get(r.PathValue("tx"))
	if !ok {
		http.Error(w, "Event not found", http.StatusNotFound)
		return
	}
	writeJSONValue(w, http.StatusOK, e)
}

type apiHit struct {
	events.Hit
	Rule         *crs.Rule `json:"rule,omitempty"`
	NoteZH       string    `json:"note_zh,omitempty"`
	CategoryZH   string    `json:"category_zh,omitempty"`
	Counted      bool      `json:"counted"`
	Contribution string    `json:"contribution"`
	Excludable   bool      `json:"excludable"`
}

type apiImpact struct {
	Events        int      `json:"events"`
	Changed       int      `json:"changed"`
	Unblocked     int      `json:"unblocked"`
	NewlyBlocked  int      `json:"newly_blocked"`
	Sources       int      `json:"sources"`
	AttackSources int      `json:"attack_sources"`
	AttackEvents  int      `json:"attack_events"`
	Samples       []string `json:"sample_transactions"`
	Caveats       []string `json:"caveats"`
}

func toAPIImpact(im analysis.Impact) apiImpact {
	out := apiImpact{Events: im.Events, Changed: im.Changed, Unblocked: im.Unblocked, NewlyBlocked: im.NewlyBlocked,
		Sources: im.Sources, AttackSources: im.AttackSources, AttackEvents: im.AttackEvents, Samples: []string{}, Caveats: im.Caveats}
	for _, e := range im.Samples {
		out.Samples = append(out.Samples, e.TxID)
	}
	if out.Caveats == nil {
		out.Caveats = []string{}
	}
	return out
}

type apiSuggestion struct {
	Rule        int           `json:"rule"`
	Var         string        `json:"var,omitempty"`
	Scope       string        `json:"scope"`
	Description string        `json:"description"`
	Exclusion   waf.Exclusion `json:"exclusion"`
	Impact      apiImpact     `json:"impact"`
	ClearsEvent bool          `json:"clears_event"`
}

// HandleAPIExplain explains why an event was (or would have been) blocked
// and proposes the narrowest exclusions with their impact.
func HandleAPIExplain(w http.ResponseWriter, r *http.Request) {
	store := requireStore(w)
	if store == nil {
		return
	}
	e, ok := store.Get(r.PathValue("tx"))
	if !ok {
		http.Error(w, "Event not found", http.StatusNotFound)
		return
	}
	dict := dictionary()
	var hits []apiHit
	for _, v := range buildHitViews(e, dict) {
		h := apiHit{Hit: v.Hit, NoteZH: v.NoteZH, CategoryZH: v.CategoryZH, Counted: v.Counted, Contribution: v.Contribution, Excludable: v.Excludable}
		if v.Known {
			rule := v.Rule
			h.Rule = &rule
		}
		hits = append(hits, h)
	}
	window := windowFor(e.Site, 14*24*time.Hour)
	var suggestions []apiSuggestion
	for _, s := range analysis.Suggest(e, window, analysis.Profiles(window), dict) {
		suggestions = append(suggestions, apiSuggestion{Rule: s.Rule, Var: s.Var, Scope: s.Scope, Description: s.Exclusion.Describe(),
			Exclusion: s.Exclusion, Impact: toAPIImpact(s.Impact), ClearsEvent: s.ClearsEvent})
	}
	if suggestions == nil {
		suggestions = []apiSuggestion{}
	}
	writeJSONValue(w, http.StatusOK, map[string]any{"event": e, "hits": hits, "suggested_exclusions": suggestions,
		"dictionary_crs": dict.CRSVersion})
}

// HandleAPIRules searches the rule dictionary.
func HandleAPIRules(w http.ResponseWriter, r *http.Request) {
	dict := dictionary()
	var kinds []string
	if k := r.URL.Query().Get("kind"); k != "" {
		kinds = append(kinds, k)
	}
	rules := dict.Search(r.URL.Query().Get("q"), kinds...)
	if rules == nil {
		rules = []crs.Rule{}
	}
	writeJSONValue(w, http.StatusOK, map[string]any{"crs_version": dict.CRSVersion, "rules": rules})
}

// HandleAPIRule returns one rule with its notes.
func HandleAPIRule(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(r.PathValue("id"))
	if err != nil {
		http.Error(w, "Invalid rule id", http.StatusBadRequest)
		return
	}
	rule, ok := dictionary().Lookup(id)
	if !ok {
		http.Error(w, "Rule not found", http.StatusNotFound)
		return
	}
	note, category := crs.Note(rule)
	writeJSONValue(w, http.StatusOK, map[string]any{"rule": rule, "note_zh": note, "category_zh": category, "excludable": rule.IsExcludable()})
}

// HandleAPIAnalysis returns the retrospective report of a window.
func HandleAPIAnalysis(w http.ResponseWriter, r *http.Request) {
	if requireStore(w) == nil {
		return
	}
	_, dur := parseRange(r.URL.Query().Get("range"), "7d")
	site := r.URL.Query().Get("site")
	now := time.Now().UTC()
	report := analysis.Analyze(windowFor(site, dur), dictionary(), now.Add(-dur), now, site, now.Add(-24*time.Hour))
	writeJSONValue(w, http.StatusOK, report)
}

// PolicyRequest is the body of policy changes.
type PolicyRequest struct {
	Policy waf.Policy `json:"policy"`
	Reason string     `json:"reason"`
}

// HandleAPIGetPolicy returns the stored mode and policy of a site.
func HandleAPIGetPolicy(w http.ResponseWriter, r *http.Request) {
	state, err := service.ReadSiteState(r.PathValue("domain"))
	if err != nil {
		if errors.Is(err, service.ErrInvalidDomain) {
			http.Error(w, "Invalid domain", http.StatusBadRequest)
			return
		}
		http.Error(w, "Error reading the policy", http.StatusInternalServerError)
		return
	}
	writeJSONValue(w, http.StatusOK, map[string]any{"mode": state.Mode, "policy": state.Policy, "revision": state.Revision,
		"exclusions": state.Exclusions, "managed": state.HasWAF})
}

// HandleAPISetPolicy applies a site policy.
func HandleAPISetPolicy(w http.ResponseWriter, r *http.Request) {
	var req PolicyRequest
	if err := decodeJSONBody(w, r, &req); err != nil {
		return
	}
	if err := service.ApplyPolicy(actor(r, req.Reason), r.PathValue("domain"), req.Policy); err != nil {
		switch {
		case errors.Is(err, service.ErrInvalidDomain):
			http.Error(w, "Invalid domain", http.StatusBadRequest)
		case errors.Is(err, service.ErrInvalidPolicy):
			http.Error(w, err.Error(), http.StatusBadRequest)
		default:
			http.Error(w, "Error applying the configuration", http.StatusInternalServerError)
		}
		return
	}
	writeJSON(w, http.StatusOK, `{"status":"success"}`)
}

// ImpactRequest is the body of impact estimates and previews.
type ImpactRequest struct {
	Exclusions []waf.Exclusion `json:"exclusions,omitempty"`
	Policy     *waf.Policy     `json:"policy,omitempty"`
	Mode       string          `json:"mode,omitempty"`
	Range      string          `json:"range,omitempty"`
}

// HandleAPIImpact estimates a change (exclusions, policy and/or mode) over
// the site's stored events and returns the generated-overlay diff.
func HandleAPIImpact(w http.ResponseWriter, r *http.Request) {
	domainName := r.PathValue("domain")
	if err := service.ValidateDomain(domainName); err != nil {
		http.Error(w, "Invalid domain", http.StatusBadRequest)
		return
	}
	var req ImpactRequest
	if err := decodeJSONBody(w, r, &req); err != nil {
		return
	}
	if err := waf.ValidateExclusions(req.Exclusions); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if req.Policy != nil {
		if err := req.Policy.Validate(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}
	if req.Mode != "" && req.Mode != "On" && req.Mode != "DetectionOnly" && req.Mode != "Off" {
		http.Error(w, "Invalid WAF mode", http.StatusBadRequest)
		return
	}
	_, dur := parseRange(req.Range, "14d")
	window := windowFor(domainName, dur)
	impact := analysis.Estimate(window, analysis.Profiles(window), dictionary(),
		analysis.Change{Exclusions: req.Exclusions, Policy: req.Policy, Mode: req.Mode})
	resp := map[string]any{"impact": toAPIImpact(impact)}
	var preview service.Preview
	var err error
	switch {
	case req.Policy != nil:
		preview, err = service.PreviewPolicy(domainName, *req.Policy)
	case len(req.Exclusions) > 0:
		current, rerr := readExclusions(domainName)
		if rerr != nil {
			http.Error(w, "Error reading exclusions", http.StatusInternalServerError)
			return
		}
		preview, err = service.PreviewExclusions(domainName, append(current, req.Exclusions...))
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	resp["diff"] = preview.Diff
	writeJSONValue(w, http.StatusOK, resp)
}

// HandleAPIChanges returns the change journal, newest first.
func HandleAPIChanges(w http.ResponseWriter, r *http.Request) {
	entries, err := journal.List(journal.Filter{Site: r.URL.Query().Get("site"), Limit: atoiDefault(r.URL.Query().Get("limit"), 100)})
	if err != nil {
		http.Error(w, "Error reading the change journal", http.StatusInternalServerError)
		return
	}
	if entries == nil {
		entries = []journal.Entry{}
	}
	writeJSONValue(w, http.StatusOK, map[string]any{"changes": entries})
}

// BackfillRequest is the body of Loki imports.
type BackfillRequest struct {
	From time.Time `json:"from"`
	To   time.Time `json:"to"`
}

// HandleAPIBackfill imports shipped events from Loki.
func HandleAPIBackfill(w http.ResponseWriter, r *http.Request) {
	rt := currentRuntime()
	if rt == nil || rt.Store == nil || !rt.Loki.Configured() {
		http.Error(w, "Loki history is not configured", http.StatusServiceUnavailable)
		return
	}
	var req BackfillRequest
	if err := decodeJSONBody(w, r, &req); err != nil {
		return
	}
	now := time.Now().UTC()
	if req.To.IsZero() || req.To.After(now) {
		req.To = now
	}
	if req.From.IsZero() {
		req.From = req.To.Add(-24 * time.Hour)
	}
	if !req.From.Before(req.To) || req.To.Sub(req.From) > 31*24*time.Hour {
		http.Error(w, "Invalid range (from < to, at most 31 days)", http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 25*time.Second)
	defer cancel()
	res, err := events.Backfill(ctx, rt.Loki, rt.Store, req.From, req.To)
	status := http.StatusOK
	body := map[string]any{"fetched": res.Fetched, "imported": res.Imported, "queries": res.Queries}
	if err != nil {
		status = http.StatusBadGateway
		body["error"] = err.Error()
	}
	writeJSONValue(w, status, body)
}
