package ui

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/developmi/caddy-waf-ui/internal/analysis"
	"github.com/developmi/caddy-waf-ui/internal/config"
	"github.com/developmi/caddy-waf-ui/internal/crs"
	"github.com/developmi/caddy-waf-ui/internal/domain"
	"github.com/developmi/caddy-waf-ui/internal/events"
	"github.com/developmi/caddy-waf-ui/internal/feedback"
	"github.com/developmi/caddy-waf-ui/internal/journal"
	"github.com/developmi/caddy-waf-ui/internal/service"
	"github.com/developmi/caddy-waf-ui/internal/waf"
)

const eventPageSize = 50

// wafData carries the models of the event, rule, analysis and policy pages.
// It is embedded in pageData so templates address its fields directly.
type wafData struct {
	HistoryError           string
	HistoryWarning         string
	HistoryBackend         string
	HistorySource          string
	CloudNext              string
	LocalLevel, CloudLevel string
	PipelineError          string
	CloudStats             events.Stats
	StoreReady             bool
	StoreStats             events.Stats
	IngestReady            bool
	Ingest                 events.IngestStatus
	LokiReady              bool
	DictVersion            string
	CRSSeen                []string
	CRSMismatch            bool

	EventRows    []eventRow
	EventTotal   int
	EventPage    int
	EventPages   int
	EventPrev    string
	EventNext    string
	EventFilter  eventFilter
	RangeOptions []rangeOption

	Feedback       *feedback.Record
	Event          *events.Event
	EventHits      []hitView
	Suggestions    []analysis.Suggestion
	CombinedImpact *analysis.Impact
	ExploreURL     string
	EventSource    string
	// NoDecision: Coraza interrupted the request without a decision or
	// direct-block rule (typically the request body limit, HTTP 413).
	NoDecision bool

	// LocalPossible: the event was ingested on this node, so its raw audit
	// record may still exist locally (rotated archives are kept 48 hours).
	LocalPossible    bool
	LocalRecord      *events.LocalRecord
	LocalRecordError string

	RuleList   []crs.Rule
	RuleQuery  string
	RuleKind   string
	RuleDetail *ruleView
	RuleEvents string

	Report     *analysis.Report
	Trend      []trendDay
	TrendMax   int64
	RangeLabel string

	Policy        waf.Policy
	PolicyForm    policyForm
	PolicyPreview *service.Preview
	PolicyImpact  *analysis.Impact
	FormError     string
	Groups        []groupOption

	ExclusionForm    exclusionForm
	ExclusionPreview *service.Preview
	ExclusionImpact  *analysis.Impact
	ExclusionRows    []exclusionListRow
	TopRules         []analysis.RuleSummary
	FPCandidates     []analysis.FPCandidate

	Changes []journal.Entry
}

type eventFilter struct {
	Site, Action, IP, Rule, Path, Query, Range, Source string
}

type trendDay struct {
	Day                           string
	Blocked, WouldBlock, Detected int64
	Total                         int64
	Height                        int
}

type groupOption struct {
	ID, Label string
	Checked   bool
}

var groupLabels = map[string]string{
	"911": "911 Method enforcement", "913": "913 Scanner detection", "920": "920 Protocol enforcement",
	"921": "921 Protocol attack", "922": "922 Multipart attack", "930": "930 Local file inclusion",
	"931": "931 Remote file inclusion", "932": "932 Remote code execution", "933": "933 PHP injection",
	"934": "934 Generic attacks (Node.js, SSRF, ...)", "941": "941 Cross-site scripting", "942": "942 SQL injection",
	"943": "943 Session fixation", "944": "944 Java attacks", "950": "950 Data leakage", "951": "951 SQL error leakage",
	"952": "952 Java leakage", "953": "953 PHP leakage", "954": "954 IIS leakage", "955": "955 Web shells", "956": "956 Ruby leakage",
}

// policyForm holds the raw form values so a rejected form re-renders as typed.
type policyForm struct {
	BlockingPL, DetectionPL, Inbound, Outbound string
	EarlyBlocking, Tuning                      bool
	Methods, ContentTypes, BodyLimit, Reason   string
	Groups                                     map[string]bool
}

// exclusionForm holds the add-exclusion form values.
type exclusionForm struct {
	Type, Value, Param, Path, PathMatch, Note, Reason, Expires string
}

// exclusionListRow is an active exclusion with its removal key.
type exclusionListRow struct {
	Index    int
	Ex       waf.Exclusion
	Describe string
	RuleMsg  string
}

func (f policyForm) toPolicy() (waf.Policy, error) {
	p := waf.Policy{EarlyBlocking: f.EarlyBlocking, Tuning: f.Tuning}
	var err error
	parse := func(raw string, dst *int, name string) {
		if err != nil || strings.TrimSpace(raw) == "" {
			return
		}
		n, perr := strconv.Atoi(strings.TrimSpace(raw))
		if perr != nil {
			err = fmt.Errorf("%s must be a number", name)
			return
		}
		*dst = n
	}
	parse(f.BlockingPL, &p.BlockingPL, "blocking paranoia level")
	parse(f.DetectionPL, &p.DetectionPL, "detection paranoia level")
	parse(f.Inbound, &p.InboundThreshold, "inbound threshold")
	parse(f.Outbound, &p.OutboundThreshold, "outbound threshold")
	if err != nil {
		return waf.Policy{}, err
	}
	if s := strings.TrimSpace(f.BodyLimit); s != "" {
		n, perr := strconv.ParseInt(s, 10, 64)
		if perr != nil {
			return waf.Policy{}, errors.New("request body limit must be a number of bytes")
		}
		p.RequestBodyLimit = n
	}
	p.AllowedMethods = splitList(f.Methods)
	p.AllowedContentTypes = splitList(f.ContentTypes)
	for g, on := range f.Groups {
		if on {
			p.DisabledGroups = append(p.DisabledGroups, g)
		}
	}
	p = p.Normalize()
	return p, p.Validate()
}

func splitList(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == '\n' || r == '\t' || r == '\r' })
}

func formFromPolicy(p waf.Policy) policyForm {
	p = p.Normalize()
	f := policyForm{
		BlockingPL: strconv.Itoa(p.BlockingPL), DetectionPL: strconv.Itoa(p.DetectionPL),
		Inbound: strconv.Itoa(p.InboundThreshold), Outbound: strconv.Itoa(p.OutboundThreshold),
		EarlyBlocking: p.EarlyBlocking, Tuning: p.Tuning,
		Methods: strings.Join(p.AllowedMethods, " "), ContentTypes: strings.Join(p.AllowedContentTypes, " "),
		Groups: map[string]bool{},
	}
	if p.RequestBodyLimit > 0 {
		f.BodyLimit = strconv.FormatInt(p.RequestBodyLimit, 10)
	}
	for _, g := range p.DisabledGroups {
		f.Groups[g] = true
	}
	return f
}

func policyFormFromRequest(r *http.Request) policyForm {
	f := policyForm{
		BlockingPL: r.FormValue("blocking_pl"), DetectionPL: r.FormValue("detection_pl"),
		Inbound: r.FormValue("inbound_threshold"), Outbound: r.FormValue("outbound_threshold"),
		EarlyBlocking: r.FormValue("early_blocking") == "on", Tuning: r.FormValue("tuning") == "on",
		Methods: r.FormValue("allowed_methods"), ContentTypes: r.FormValue("allowed_content_types"),
		BodyLimit: r.FormValue("request_body_limit"), Reason: r.FormValue("reason"), Groups: map[string]bool{},
	}
	for _, g := range r.Form["disabled_groups"] {
		f.Groups[g] = true
	}
	return f
}

func groupOptions(selected map[string]bool) []groupOption {
	out := make([]groupOption, 0, len(waf.DisableableGroups))
	for _, g := range waf.DisableableGroups {
		out = append(out, groupOption{ID: g, Label: groupLabels[g], Checked: selected[g]})
	}
	return out
}

// fillStatus sets the pipeline status shown on every WAF page.
func fillStatus(d *wafData) {
	dict := dictionary()
	d.DictVersion = dict.CRSVersion
	rt := currentRuntime()
	if rt == nil {
		return
	}
	d.LocalLevel, d.CloudLevel = rt.Redaction.Local.Level.String(), rt.Redaction.Cloud.Level.String()
	d.PipelineError = rt.PipelineError
	if rt.CloudStore != nil {
		d.CloudStats = rt.CloudStore.Stats()
	}
	if rt.Store != nil {
		d.StoreReady = true
		d.StoreStats = rt.Store.Stats()
	}
	if rt.Ingester != nil {
		d.IngestReady = true
		d.Ingest = rt.Ingester.Status()
	}
	d.LokiReady = rt.Loki.Configured()
}

// crsVersionsSeen lists the CRS versions reported by recent events.
func crsVersionsSeen(list []*events.Event) []string {
	seen := map[string]bool{}
	var out []string
	for _, e := range list {
		if e.CRS != "" && !seen[e.CRS] {
			seen[e.CRS] = true
			out = append(out, e.CRS)
		}
	}
	sort.Strings(out)
	return out
}

// windowFor returns the site's events of the last d.
func windowFor(site string, d time.Duration) []*events.Event {
	store := eventStore()
	if store == nil {
		return nil
	}
	return store.Window(events.Query{From: time.Now().UTC().Add(-d), Site: site})
}

func buildEventsData(q url.Values, d *wafData) {
	key, dur := parseRange(q.Get("range"), "24h")
	d.EventFilter = eventFilter{Site: q.Get("site"), Action: q.Get("action"), IP: q.Get("ip"), Rule: q.Get("rule"),
		Path: q.Get("path"), Query: q.Get("q"), Range: key, Source: q.Get("source")}
	d.RangeOptions = rangeOptions(key)
	if d.EventFilter.Source == "" && dur > 24*time.Hour && currentRuntime() != nil && currentRuntime().Loki.Configured() {
		d.EventFilter.Source = "loki"
	}
	store := eventStore()
	if store == nil {
		return
	}
	page := atoiDefault(q.Get("page"), 1)
	if page < 1 {
		page = 1
	}
	query := events.Query{From: time.Now().UTC().Add(-dur), Site: d.EventFilter.Site, Action: d.EventFilter.Action,
		IP: d.EventFilter.IP, RuleID: atoiDefault(d.EventFilter.Rule, 0), PathPrefix: d.EventFilter.Path,
		Text: d.EventFilter.Query, Limit: eventPageSize, Offset: (page - 1) * eventPageSize}
	var list []*events.Event
	var total int
	if d.EventFilter.Source == "loki" {
		rt := currentRuntime()
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		history, err := rt.Loki.Search(ctx, query, q.Get("cursor"))
		d.HistorySource = "Grafana Cloud Loki (viewed here)"
		d.HistoryWarning = history.Warning
		if err != nil {
			d.HistoryError = err.Error()
		} else {
			list = history.Events
			total = len(list)
			d.CloudNext = history.Next
			if history.More {
				d.HistoryWarning = "More cloud events are available; use Older to continue"
			}
		}
	} else {
		var err error
		list, total, err = store.QueryDisk(query)
		if err != nil {
			d.HistoryError = err.Error()
		}
		d.HistorySource = "Local retained files (memory cache does not limit history)"
	}
	d.EventRows = buildEventRows(displayEvents(list), dictionary())
	d.EventTotal = total
	d.EventPage = page
	d.EventPages = (total + eventPageSize - 1) / eventPageSize
	link := func(p int) string {
		if p < 1 || p > d.EventPages {
			return ""
		}
		v := url.Values{}
		for k, vals := range q {
			if k != "page" && len(vals) > 0 && vals[0] != "" {
				v.Set(k, vals[0])
			}
		}
		v.Set("tab", "events")
		v.Set("page", strconv.Itoa(p))
		return "/?" + v.Encode()
	}
	d.EventPrev, d.EventNext = link(page-1), link(page+1)
	if d.EventFilter.Source == "loki" {
		d.EventPrev = ""
		d.EventNext = ""
		if d.CloudNext != "" {
			v := url.Values{}
			for k, vals := range q {
				v[k] = append([]string(nil), vals...)
			}
			v.Set("cursor", d.CloudNext)
			v.Set("tab", "events")
			v.Del("page")
			d.EventNext = "/?" + v.Encode()
		}
		d.EventPages = 0
	}
	d.CRSSeen = crsVersionsSeen(list)
	for _, v := range d.CRSSeen {
		if v != d.DictVersion {
			d.CRSMismatch = true
		}
	}
}

func buildEventDetail(q url.Values, d *wafData) {
	store := eventStore()
	if store == nil {
		return
	}
	e, ok := store.GetFor(q.Get("tx"), q.Get("node"))
	if !ok || q.Get("source") == "loki" {
		rt := currentRuntime()
		if rt.Loki.Configured() {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			ts, _ := time.Parse(time.RFC3339Nano, q.Get("ts"))
			var err error
			e, err = rt.Loki.Find(ctx, q.Get("tx"), q.Get("node"), ts)
			if err != nil {
				d.HistoryError = err.Error()
				return
			}
			ok = true
		}
	}
	if !ok {
		return
	}
	dict := dictionary()
	e = displayEvent(e)
	d.Event = e
	d.HistoryBackend = "local"
	if e.Source == events.SourceLoki {
		d.HistoryBackend = "loki"
	}
	d.Feedback, _ = feedback.Get(e.Node, e.TxID)
	d.EventHits = buildHitViews(e, dict)
	d.NoDecision = e.Interrupted && !hasDecision(e)
	d.LocalPossible = e.Node == "" || e.Node == config.NodeName()
	if d.LocalPossible && q.Get("raw") == "1" {
		// Read on demand only: matched values never enter the event files.
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		rec, err := events.FindLocalRecordWithPolicy(ctx, config.AuditLogPath(), e, localRedaction())
		if err != nil {
			d.LocalRecordError = err.Error()
		} else {
			d.LocalRecord = rec
		}
	}
	window := windowFor(e.Site, 14*24*time.Hour)
	if e.Source == events.SourceLoki {
		rt := currentRuntime()
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		h, err := rt.Loki.Search(ctx, events.Query{From: time.Now().Add(-14 * 24 * time.Hour), Site: e.Site, Limit: events.AnalysisLimit}, "")
		if err == nil {
			window = h.Events
		} else {
			window = nil
			d.HistoryError = err.Error()
		}
		d.HistoryWarning = "Historical estimates use at most 2,000 matching events and may omit unrecorded requests"
	}
	profiles := analysis.Profiles(window)
	d.Suggestions = analysis.Suggest(e, window, profiles, dict)
	// Rules that each add enough points on their own block the request
	// until all of them are excluded: show their combined effect too.
	var narrowest []waf.Exclusion
	for _, s := range d.Suggestions {
		if s.Scope == "narrowest" {
			narrowest = append(narrowest, s.Exclusion)
		}
	}
	if len(narrowest) > 1 {
		combined := analysis.Estimate(window, profiles, dict, analysis.Change{Exclusions: narrowest})
		d.CombinedImpact = &combined
	}
	d.ExploreURL = events.ExploreLink(config.GrafanaExploreURL(), config.GrafanaLokiDatasource(), config.LokiSelector(), e)
	d.EventSource = "local audit log"
	if e.Source == events.SourceLoki {
		d.EventSource = "Grafana Cloud Loki"
	}
	if e.CRS != "" && e.CRS != d.DictVersion {
		d.CRSMismatch = true
		d.CRSSeen = []string{e.CRS}
	}
}

// hasDecision reports whether a threshold decision, a direct-block rule or
// a custom rule unknown to the dictionary explains the event's interruption.
func hasDecision(e *events.Event) bool {
	for _, h := range e.Hits {
		if h.Kind == crs.KindDecision || h.Kind == crs.KindBlocking || h.Kind == "unknown" {
			return true
		}
	}
	return false
}

func buildRulesData(q url.Values, d *wafData) {
	dict := dictionary()
	d.RuleQuery = q.Get("q")
	d.RuleKind = q.Get("kind")
	if id := atoiDefault(q.Get("id"), 0); id > 0 {
		window := windowFor("", 14*24*time.Hour)
		report := analysis.Analyze(window, dict, time.Now().Add(-14*24*time.Hour), time.Now(), "", time.Time{})
		v := buildRuleView(id, dict, &report)
		d.RuleDetail = &v
		d.RuleEvents = eventsURL(map[string]string{"rule": strconv.Itoa(id), "range": "14d"})
		return
	}
	kinds := []string{}
	if d.RuleKind != "" {
		kinds = append(kinds, d.RuleKind)
	}
	d.RuleList = dict.Search(d.RuleQuery, kinds...)
}

func buildAnalysisData(q url.Values, site string, d *wafData) {
	key, dur := parseRange(q.Get("range"), "7d")
	d.RangeOptions = rangeOptions(key)
	for _, r := range ranges {
		if r.Key == key {
			d.RangeLabel = r.Label
		}
	}
	now := time.Now().UTC()
	window := windowFor(site, dur)
	if (q.Get("source") == "loki" || (q.Get("source") == "" && dur > 24*time.Hour)) && currentRuntime() != nil && currentRuntime().Loki.Configured() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		h, err := currentRuntime().Loki.Search(ctx, events.Query{From: now.Add(-dur), To: now, Site: site, Limit: events.AnalysisLimit}, "")
		if err != nil {
			window = nil
			d.HistoryError = err.Error()
		} else {
			window = h.Events
		}
		d.HistoryBackend = "loki"
	}
	d.HistoryWarning = "Analysis uses at most 2,000 newest matching events. Counts describe audited events, not all requests."
	report := analysis.Analyze(window, dictionary(), now.Add(-dur), now, site, now.Add(-24*time.Hour))
	d.Report = &report
	if store := eventStore(); store != nil && d.HistoryBackend != "loki" {
		d.Trend, d.TrendMax = trend(store.Rollups(), site, now)
	}
}

// trend returns 14 days of daily totals from the rollups.
func trend(r *events.Rollups, site string, now time.Time) ([]trendDay, int64) {
	from := now.Add(-13 * 24 * time.Hour)
	byDay := map[string]*trendDay{}
	var order []string
	for d := 0; d < 14; d++ {
		day := from.Add(time.Duration(d) * 24 * time.Hour).Format("2006-01-02")
		byDay[day] = &trendDay{Day: day}
		order = append(order, day)
	}
	for _, row := range r.Range(from, now, site) {
		td := byDay[row.Day]
		if td == nil || row.Rule != 0 {
			continue
		}
		switch row.Action {
		case events.ActionBlocked:
			td.Blocked += row.Count
		case events.ActionWouldBlock:
			td.WouldBlock += row.Count
		default:
			td.Detected += row.Count
		}
		td.Total += row.Count
	}
	var maxTotal int64
	out := make([]trendDay, 0, len(order))
	for _, day := range order {
		if byDay[day].Total > maxTotal {
			maxTotal = byDay[day].Total
		}
	}
	for _, day := range order {
		td := *byDay[day]
		if maxTotal > 0 {
			td.Height = int(td.Total * 100 / maxTotal)
		}
		out = append(out, td)
	}
	return out, maxTotal
}

func buildPolicyData(site *domain.Site, d *wafData) {
	if site == nil {
		return
	}
	state, err := service.ReadSiteState(site.Domain)
	if err != nil {
		d.FormError = "Could not read the stored policy: " + err.Error()
		state.Policy = waf.DefaultPolicy()
	}
	d.Policy = state.Policy
	d.PolicyForm = formFromPolicy(state.Policy)
	d.Groups = groupOptions(d.PolicyForm.Groups)
}

func buildExclusionsData(q url.Values, site *domain.Site, d *wafData) {
	if site == nil {
		return
	}
	dict := dictionary()
	d.ExclusionForm = exclusionForm{Type: "id", Value: q.Get("rule"), Param: q.Get("param"), Path: q.Get("path"), PathMatch: q.Get("path_match")}
	if list, err := readExclusions(site.Domain); err == nil {
		for i, ex := range list {
			row := exclusionListRow{Index: i, Ex: ex, Describe: ex.Describe()}
			if id, err := strconv.Atoi(ex.Value); err == nil && ex.Type == waf.ExcludeByID {
				if r, ok := dict.Lookup(id); ok {
					row.RuleMsg = r.Msg
				}
			}
			d.ExclusionRows = append(d.ExclusionRows, row)
		}
	}
	window := windowFor(site.Domain, 7*24*time.Hour)
	if len(window) > 0 {
		report := analysis.Analyze(window, dict, time.Now().Add(-7*24*time.Hour), time.Now(), site.Domain, time.Time{})
		for _, rs := range report.Rules {
			if len(d.TopRules) >= 8 {
				break
			}
			if rs.Known && !rs.Rule.IsExcludable() {
				continue
			}
			d.TopRules = append(d.TopRules, rs)
		}
		d.FPCandidates = report.FPCandidates
		if len(d.FPCandidates) > 8 {
			d.FPCandidates = d.FPCandidates[:8]
		}
	}
}

func buildHistoryData(site *domain.Site, d *wafData) {
	f := journal.Filter{Limit: 100}
	if site != nil {
		f.Site = site.Domain
	}
	entries, err := journal.List(f)
	if err != nil {
		slog.Warn("could not read the change journal", "error", err)
		return
	}
	d.Changes = entries
}

// buildRecentEvents lists the newest stored events of the last 24 hours.
func buildRecentEvents(d *wafData) {
	store := eventStore()
	if store == nil {
		return
	}
	list, _, err := store.QueryDisk(events.Query{From: time.Now().UTC().Add(-24 * time.Hour), Limit: 5})
	if err != nil {
		d.HistoryError = err.Error()
	}
	d.EventRows = buildEventRows(list, dictionary())
}

// buildWAFData fills the tab-specific WAF models.
func buildWAFData(r *http.Request, tab string, data *pageData) {
	q := r.URL.Query()
	fillStatus(&data.wafData)
	switch tab {
	case "overview":
		buildAnalysisData(url.Values{"range": {"24h"}}, "", &data.wafData)
		buildRecentEvents(&data.wafData)
	case "events":
		buildEventsData(q, &data.wafData)
	case "event":
		buildEventDetail(q, &data.wafData)
	case "rules":
		buildRulesData(q, &data.wafData)
	case "analysis":
		site := ""
		if data.CurrentSite != nil && q.Get("domain") != "" {
			site = data.CurrentSite.Domain
		}
		buildAnalysisData(q, site, &data.wafData)
	case "policy":
		buildPolicyData(data.CurrentSite, &data.wafData)
		data.HistoryBackend = q.Get("source")
	case "exclusions":
		buildExclusionsData(q, data.CurrentSite, &data.wafData)
		data.HistoryBackend = q.Get("source")
	case "rollback":
		buildHistoryData(data.CurrentSite, &data.wafData)
	}
}

// renderWithError re-renders a page (status 200) with a form error and the
// submitted values; nothing was changed.
func renderTab(w http.ResponseWriter, r *http.Request, tab, domainName string, mutate func(*pageData)) {
	q := url.Values{"tab": {tab}, "domain": {domainName}}
	r2 := r.Clone(r.Context())
	r2.URL = &url.URL{Path: "/", RawQuery: q.Encode()}
	data := buildPageData(r2, tab, scanSites())
	mutate(&data)
	if err := executePage(w, tab, data); err != nil {
		slog.Error("error rendering page", "tab", tab, "error", err)
		http.Error(w, "Internal error rendering the page", http.StatusInternalServerError)
	}
}

// HandleFormPolicy previews (impact and diff) or applies a site policy.
func HandleFormPolicy(w http.ResponseWriter, r *http.Request) {
	domainName := r.PathValue("domain")
	_ = r.ParseForm()
	form := policyFormFromRequest(r)
	policy, err := form.toPolicy()
	if err != nil {
		renderTab(w, r, "policy", domainName, func(d *pageData) {
			d.PolicyForm, d.Groups, d.FormError = form, groupOptions(form.Groups), err.Error()
		})
		return
	}
	if r.FormValue("action") == "preview" {
		preview, perr := service.CreatePolicyDraft(domainName, policy)
		window, historyErr := historyWindow(r.Context(), r.FormValue("source"), domainName, 14*24*time.Hour)
		impact := analysis.Estimate(window, analysis.Profiles(window), dictionary(), analysis.Change{Policy: &policy})
		renderTab(w, r, "policy", domainName, func(d *pageData) {
			d.PolicyForm, d.Groups = form, groupOptions(form.Groups)
			d.HistoryBackend = r.FormValue("source")
			d.PolicyImpact = &impact
			if historyErr != nil {
				d.FormError = "History unavailable: " + historyErr.Error()
			} else if perr != nil {
				d.FormError = perr.Error()
			} else {
				d.PolicyPreview = &preview
			}
		})
		return
	}
	if err := service.ApplyPolicyDraft(actor(r, form.Reason), domainName, policy, r.FormValue("draft_id")); err != nil {
		slog.Warn("policy change failed", "domain", domainName, "error", err)
		redirectAfterForm(w, r, "error")
		return
	}
	redirectAfterForm(w, r, "success")
}

func exclusionFromRequest(r *http.Request) (waf.Exclusion, exclusionForm) {
	f := exclusionForm{Type: r.FormValue("type"), Value: strings.TrimSpace(r.FormValue("ruleId")),
		Param: strings.TrimSpace(r.FormValue("param")), Path: strings.TrimSpace(r.FormValue("path")),
		PathMatch: r.FormValue("path_match"), Note: strings.TrimSpace(r.FormValue("note")), Reason: r.FormValue("reason"), Expires: r.FormValue("expires")}
	if f.Type == "" {
		f.Type = string(waf.ExcludeByID)
	}
	if f.Type == string(waf.ExcludeByTag) && f.Value == "" {
		f.Value = strings.TrimSpace(r.FormValue("tag"))
	}
	ex := waf.Exclusion{Type: waf.ExclusionType(f.Type), Value: f.Value, Param: f.Param, Path: f.Path, Note: f.Note}
	if f.Expires != "" {
		ex.Expires, _ = time.Parse("2006-01-02T15:04", f.Expires)
	}
	if ex.Path != "" {
		ex.PathMatch = f.PathMatch
	}
	return ex, f
}

// previewExclusions renders the exclusions page with the diff and impact of
// the candidate list.
func previewExclusions(w http.ResponseWriter, r *http.Request, domainName string, form exclusionForm, candidate waf.Exclusion, merged []waf.Exclusion) {
	preview, err := service.CreateExclusionsDraft(domainName, merged)
	window, historyErr := historyWindow(r.Context(), r.FormValue("source"), domainName, 14*24*time.Hour)
	impact := analysis.Estimate(window, analysis.Profiles(window), dictionary(), analysis.Change{Exclusions: []waf.Exclusion{candidate}})
	renderTab(w, r, "exclusions", domainName, func(d *pageData) {
		d.ExclusionForm = form
		d.HistoryBackend = r.FormValue("source")
		d.ExclusionImpact = &impact
		if historyErr != nil {
			d.FormError = "History unavailable: " + historyErr.Error()
		} else if err != nil {
			d.FormError = err.Error()
		} else {
			d.ExclusionPreview = &preview
		}
	})
}

// HandleFormRemoveExclusion removes one exclusion by its list index.
func HandleFormRemoveExclusion(w http.ResponseWriter, r *http.Request) {
	domainName := r.PathValue("domain")
	current, err := readExclusions(domainName)
	if err != nil {
		redirectAfterForm(w, r, "error")
		return
	}
	idx := atoiDefault(r.FormValue("index"), -1)
	// The index must still point at the exclusion the page showed: the list
	// may have changed since it was rendered.
	if idx < 0 || idx >= len(current) || current[idx].Value != r.FormValue("value") ||
		current[idx].Param != r.FormValue("param") || current[idx].Path != r.FormValue("path") {
		redirectAfterForm(w, r, "error")
		return
	}
	next := append(append([]waf.Exclusion{}, current[:idx]...), current[idx+1:]...)
	if err := service.ApplyExclusions(actor(r, r.FormValue("reason")), domainName, next); err != nil {
		redirectAfterForm(w, r, "error")
		return
	}
	redirectAfterForm(w, r, "success")
}

// HandleFormBackfill imports shipped events from Loki for a time range.
func HandleFormBackfill(w http.ResponseWriter, r *http.Request) {
	rt := currentRuntime()
	if rt == nil || rt.Store == nil || !rt.Loki.Configured() {
		redirectAfterForm(w, r, "error")
		return
	}
	_, dur := parseRange(r.FormValue("range"), "24h")
	ctx, cancel := context.WithTimeout(r.Context(), 25*time.Second)
	defer cancel()
	now := time.Now().UTC()
	res, err := events.Backfill(ctx, rt.Loki, rt.Store, now.Add(-dur), now)
	if err != nil {
		slog.Warn("Loki backfill failed", "error", err, "imported", res.Imported)
		redirectAfterForm(w, r, "error")
		return
	}
	slog.Info("Loki backfill finished", "fetched", res.Fetched, "imported", res.Imported, "queries", res.Queries)
	redirectAfterForm(w, r, "backfill:"+strconv.Itoa(res.Imported))
}
