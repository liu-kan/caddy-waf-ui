package ui

import (
	"bufio"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/developmi/caddy-waf-ui/internal/crs"
	"github.com/developmi/caddy-waf-ui/internal/domain"
	"github.com/developmi/caddy-waf-ui/internal/events"
	"github.com/developmi/caddy-waf-ui/internal/journal"
	"github.com/developmi/caddy-waf-ui/internal/service"
)

// setupWAFRuntime fills an event store with the recorded Coraza fixture
// (current timestamps) and installs it for the handlers. It returns the
// events by request path.
func setupWAFRuntime(t *testing.T) map[string]*events.Event {
	t.Helper()
	store, err := events.OpenStore(filepath.Join(t.TempDir(), "events"), 14*24*time.Hour, 1000)
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(filepath.Join("..", "events", "testdata", "coraza-3.8.0-audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	norm := &events.Normalizer{Dict: crs.Default()}
	byPath := map[string]*events.Event{}
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 4<<20)
	for scanner.Scan() {
		var rec map[string]any
		if err := json.Unmarshal(scanner.Bytes(), &rec); err != nil {
			t.Fatal(err)
		}
		rec["transaction"].(map[string]any)["unix_timestamp"] = time.Now().UnixNano()
		raw, _ := json.Marshal(rec)
		e, err := norm.Normalize(raw)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.Append(e, events.SourceLocal); err != nil {
			t.Fatal(err)
		}
		byPath[e.Path+"|"+e.Action] = e
	}
	SetRuntime(&Runtime{Store: store, Dict: crs.Default(), Loki: &events.LokiClient{}})
	t.Cleanup(func() { SetRuntime(nil) })
	return byPath
}

func getPage(t *testing.T, target string) string {
	t.Helper()
	rec := httptest.NewRecorder()
	HandleIndex(rec, httptest.NewRequest(http.MethodGet, target, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET %s: %d %s", target, rec.Code, rec.Body.String())
	}
	return rec.Body.String()
}

func TestEventsTabListsStoredEvents(t *testing.T) {
	setupUIEnv(t)
	evs := setupWAFRuntime(t)
	body := getPage(t, "/?tab=events&range=1h")
	for _, want := range []string{"WAF Events", "WOULD BLOCK", "BLOCKED", "DETECTED", "rule-pill--detection", "tab=event&amp;tx=" + evs["/.git/config|blocked"].TxID, "Rule dictionary: CRS 4.25.0"} {
		if !strings.Contains(body, want) {
			t.Errorf("events page misses %q", want)
		}
	}
	filtered := getPage(t, "/?tab=events&range=1h&rule=913100")
	if !strings.Contains(filtered, "1 event(s)") || !strings.Contains(filtered, "/index.php") {
		t.Fatal("rule filter not applied")
	}
}

func TestEventDetailExplainsScoreAndSuggestsExclusions(t *testing.T) {
	setupUIEnv(t)
	evs := setupWAFRuntime(t)
	chat := evs["/api/chat|would_block"]
	if chat == nil {
		t.Fatalf("fixture event missing: %v", evs)
	}
	body := getPage(t, "/?tab=event&tx="+chat.TxID)
	for _, want := range []string{
		"POST /api/chat", "decision: inbound score", "5 inbound (PL1, CRITICAL)", "logged only: PL2 is above blocking PL1",
		"ARGS:json.messages.0.content", "[redacted]", "参数中出现操作系统敏感文件路径", "If this was a false positive",
		"narrowest", "tab=exclusions&amp;domain=example.com&amp;rule=930120",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("event detail misses %q", want)
		}
	}
	if missing := getPage(t, "/?tab=event&tx=nope"); !strings.Contains(missing, "Event not found") {
		t.Fatal("unknown events must render an honest empty state")
	}
}

func TestRulesTabSearchAndDetail(t *testing.T) {
	setupUIEnv(t)
	setupWAFRuntime(t)
	list := getPage(t, "/?tab=rules&q=restricted+file")
	if !strings.Contains(list, "930130") || strings.Contains(list, ">942100<") {
		t.Fatal("rule search")
	}
	detail := getPage(t, "/?tab=rules&id=930130")
	for _, want := range []string{"Restricted File Access Attempt", "restricted-files.data", "Explanation (Chinese)", "Rule source", "Last 14 days", "/.git/config"} {
		if !strings.Contains(detail, want) {
			t.Errorf("rule detail misses %q", want)
		}
	}
	custom := getPage(t, "/?tab=rules&id=1000001")
	if !strings.Contains(custom, "Not part of the CRS") {
		t.Fatal("unknown rules must say so")
	}
}

func TestAnalysisAndOverviewSummaries(t *testing.T) {
	setupUIEnv(t)
	setupWAFRuntime(t)
	body := getPage(t, "/?tab=analysis&range=24h")
	for _, want := range []string{"Retrospective Analysis", "Likely attackers", "Top paths", "New rules", "Daily events"} {
		if !strings.Contains(body, want) {
			t.Errorf("analysis misses %q", want)
		}
	}
	overview := getPage(t, "/?tab=overview")
	if !strings.Contains(overview, "WAF events — last 24 hours") {
		t.Fatal("overview misses the event summary")
	}
}

func TestOverviewShowsRecentStoredEvents(t *testing.T) {
	setupUIEnv(t)
	byPath := setupWAFRuntime(t)
	overview := getPage(t, "/?tab=overview")
	if !strings.Contains(overview, "Recent WAF events") {
		t.Fatal("overview misses the recent event list")
	}
	var newest *events.Event
	for _, e := range byPath {
		if newest == nil || e.TS.After(newest.TS) {
			newest = e
		}
	}
	if !strings.Contains(overview, "tab=event&amp;tx="+newest.TxID) {
		t.Fatalf("overview does not link the newest event %s", newest.TxID)
	}
	if strings.Contains(overview, "No Coraza audit entries available yet.") {
		t.Fatal("overview reports no entries while the store holds events")
	}
}

func TestEventDetailExplainsInterruptionWithoutDecision(t *testing.T) {
	setupUIEnv(t)
	byPath := setupWAFRuntime(t)
	// An On-mode upload above SecRequestBodyLimit: Coraza answers 413 before
	// any decision rule runs, and the record carries no rule message.
	raw := `{"transaction":{"unix_timestamp":` + strconv.FormatInt(time.Now().UnixNano(), 10) + `,"id":"bodylimit-1","client_ip":"192.0.2.10",` +
		`"server_id":"example.com","request":{"method":"POST","uri":"/upload"},"producer":{"rule_engine":"On","rulesets":["OWASP_CRS/4.25.0"]},"is_interrupted":true}}`
	e, err := (&events.Normalizer{Dict: crs.Default()}).Normalize([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := eventStore().Append(e, events.SourceLocal); err != nil {
		t.Fatal(err)
	}
	const hint = "without a threshold decision or direct-block rule"
	if body := getPage(t, "/?tab=event&tx=bodylimit-1"); !strings.Contains(body, hint) {
		t.Fatal("an interruption without a decision rule must be explained")
	}
	decided := byPath["/.git/config|blocked"]
	if body := getPage(t, "/?tab=event&tx="+decided.TxID); strings.Contains(body, hint) {
		t.Fatal("a threshold decision needs no extra explanation")
	}
	// A custom rule unknown to the dictionary most likely made the block.
	custom := `{"transaction":{"unix_timestamp":` + strconv.FormatInt(time.Now().UnixNano(), 10) + `,"id":"custom-deny-1","client_ip":"192.0.2.11",` +
		`"server_id":"example.com","request":{"method":"GET","uri":"/admin"},"producer":{"rule_engine":"On","rulesets":["OWASP_CRS/4.25.0"]},"is_interrupted":true},` +
		`"messages":[{"actionset":"custom","data":{"id":1000001,"msg":"Admin area is internal","severity":2}}]}`
	ce, err := (&events.Normalizer{Dict: crs.Default()}).Normalize([]byte(custom))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := eventStore().Append(ce, events.SourceLocal); err != nil {
		t.Fatal(err)
	}
	if body := getPage(t, "/?tab=event&tx=custom-deny-1"); strings.Contains(body, hint) {
		t.Fatal("an unknown custom rule explains the interruption")
	}
}

func seedManagedSite(t *testing.T) {
	t.Helper()
	if err := service.ApplyMode(service.Actor{RemoteIP: "192.0.2.1"}, "example.com", domain.ModeDetectionOnly); err != nil {
		t.Fatal(err)
	}
}

func TestPolicyPreviewValidationAndApply(t *testing.T) {
	setupUIEnv(t)
	setupWAFRuntime(t)
	seedManagedSite(t)
	mux := NewPagesMux()

	rec := formPost(t, mux, "/sites/example.com/policy", url.Values{"blocking_pl": {"9"}, "inbound_threshold": {"5"}, "outbound_threshold": {"4"}, "action": {"preview"}})
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "blocking paranoia level must be 1-4") {
		t.Fatalf("invalid policy must re-render with the error: %d", rec.Code)
	}

	form := url.Values{"blocking_pl": {"2"}, "detection_pl": {"3"}, "inbound_threshold": {"5"}, "outbound_threshold": {"4"},
		"tuning": {"on"}, "allowed_methods": {"GET POST PUT"}, "disabled_groups": {"933"}, "action": {"preview"}}
	rec = formPost(t, mux, "/sites/example.com/policy", form)
	body := rec.Body.String()
	if rec.Code != http.StatusOK || !strings.Contains(body, "Estimated impact on recorded events") ||
		!strings.Contains(body, "blocking_paranoia_level=2") || !strings.Contains(body, "SecRuleRemoveById 933000-933999") {
		t.Fatalf("preview: %d %s", rec.Code, body)
	}
	state, _ := service.ReadSiteState("example.com")
	if state.Policy.BlockingPL != 1 {
		t.Fatal("a preview must not change the stored policy")
	}

	draftMatch := regexp.MustCompile(`name="draft_id" value="([^"]+)"`).FindStringSubmatch(body)
	if len(draftMatch) != 2 {
		t.Fatal("preview did not return a draft token")
	}
	form.Set("draft_id", draftMatch[1])
	form.Set("action", "apply")
	form.Set("reason", "raise to PL2 after a week of detection data")
	rec = formPost(t, mux, "/sites/example.com/policy", form)
	if rec.Code != http.StatusSeeOther || !strings.Contains(rec.Header().Get("Location"), "flash=success") {
		t.Fatalf("apply: %d %s", rec.Code, rec.Header().Get("Location"))
	}
	state, _ = service.ReadSiteState("example.com")
	if state.Policy.BlockingPL != 2 || state.Policy.DetectionPL != 3 || !state.Policy.Tuning || state.Mode != domain.ModeDetectionOnly {
		t.Fatalf("stored state: %+v", state)
	}
	entries, err := journal.List(journal.Filter{Site: "example.com"})
	if err != nil || len(entries) < 2 || entries[0].Action != "policy" || entries[0].Reason != "raise to PL2 after a week of detection data" || entries[0].Diff == "" {
		t.Fatalf("journal: %+v %v", entries, err)
	}
	if history := getPage(t, "/?tab=rollback&domain=example.com"); !strings.Contains(history, "raise to PL2 after a week of detection data") {
		t.Fatal("history must list the change with its reason")
	}
	if page := getPage(t, "/?tab=policy&domain=example.com"); !strings.Contains(page, `value="GET POST PUT"`) {
		t.Fatal("policy page must render the stored values")
	}
}

func TestExclusionPreviewApplyAndRemove(t *testing.T) {
	setupUIEnv(t)
	setupWAFRuntime(t)
	seedManagedSite(t)
	mux := NewPagesMux()
	form := url.Values{"ruleId": {"930120"}, "param": {"json.messages.0.content"}, "path": {"/api/chat"}, "path_match": {"exact"},
		"note": {"chat messages quote commands"}, "action": {"preview"}}
	rec := formPost(t, mux, "/sites/example.com/exclusions", form)
	body := rec.Body.String()
	if rec.Code != http.StatusOK || !strings.Contains(body, "Estimated impact") || !strings.Contains(body, "ctl:ruleRemoveTargetById=930120;ARGS:json.messages.0.content") {
		t.Fatalf("preview: %d %s", rec.Code, body)
	}
	bad := formPost(t, mux, "/sites/example.com/exclusions", url.Values{"ruleId": {"949110"}, "action": {"preview"}})
	if bad.Code != http.StatusOK || !strings.Contains(bad.Body.String(), "cannot be excluded") {
		t.Fatal("decision rules must be refused with an explanation")
	}
	draftMatch := regexp.MustCompile(`name="draft_id" value="([^"]+)"`).FindStringSubmatch(body)
	if len(draftMatch) != 2 {
		t.Fatal("preview did not return a draft token")
	}
	form.Set("draft_id", draftMatch[1])
	form.Set("action", "apply")
	form.Set("reason", "confirmed false positive")
	if rec := formPost(t, mux, "/sites/example.com/exclusions", form); !strings.Contains(rec.Header().Get("Location"), "flash=success") {
		t.Fatalf("apply: %s", rec.Header().Get("Location"))
	}
	list, err := readExclusions("example.com")
	if err != nil || len(list) != 1 || list[0].Note != "chat messages quote commands" || list[0].PathMatch != "exact" {
		t.Fatalf("stored: %+v %v", list, err)
	}
	page := getPage(t, "/?tab=exclusions&domain=example.com")
	if !strings.Contains(page, "skip ARGS:json.messages.0.content in rule 930120 for path /api/chat") {
		t.Fatal("active exclusions must be described")
	}
	stale := formPost(t, mux, "/sites/example.com/exclusions/remove", url.Values{"index": {"0"}, "value": {"942100"}})
	if !strings.Contains(stale.Header().Get("Location"), "flash=error") {
		t.Fatal("a stale removal must not delete another exclusion")
	}
	ok := formPost(t, mux, "/sites/example.com/exclusions/remove", url.Values{"index": {"0"}, "value": {"930120"},
		"param": {"json.messages.0.content"}, "path": {"/api/chat"}})
	if !strings.Contains(ok.Header().Get("Location"), "flash=success") {
		t.Fatalf("remove: %s", ok.Header().Get("Location"))
	}
	if list, _ := readExclusions("example.com"); len(list) != 0 {
		t.Fatalf("not removed: %+v", list)
	}
}

func TestBackfillFormRequiresLoki(t *testing.T) {
	setupUIEnv(t)
	setupWAFRuntime(t)
	rec := formPost(t, NewPagesMux(), "/events/backfill", url.Values{"range": {"24h"}, "tab": {"events"}})
	if !strings.Contains(rec.Header().Get("Location"), "flash=error") {
		t.Fatal("backfill without Loki must fail visibly")
	}
	if got := flashMessage("backfill:12"); got != "Loki backfill finished: 12 event(s) imported." {
		t.Fatalf("flash: %q", got)
	}
}

func apiCall(t *testing.T, mux *http.ServeMux, method, target, body string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, apiRequest(t, method, target, body))
	return rec
}

func TestWAFAPI(t *testing.T) {
	api := setupUIEnv(t)
	if rec := apiCall(t, api, http.MethodGet, "/api/events", ""); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("without a store: %d", rec.Code)
	}
	evs := setupWAFRuntime(t)
	seedManagedSite(t)

	rec := apiCall(t, api, http.MethodGet, "/api/events?range=1h&action=blocked", "")
	var list struct {
		Total  int             `json:"total"`
		Events []*events.Event `json:"events"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil || list.Total != 3 {
		t.Fatalf("events: %d %s", list.Total, rec.Body.String())
	}
	chat := evs["/api/chat|would_block"]
	rec = apiCall(t, api, http.MethodGet, "/api/events/"+chat.TxID+"/explain", "")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"note_zh"`) || !strings.Contains(rec.Body.String(), `"suggested_exclusions"`) {
		t.Fatalf("explain: %d %s", rec.Code, rec.Body.String())
	}
	if rec := apiCall(t, api, http.MethodGet, "/api/events/nope", ""); rec.Code != http.StatusNotFound {
		t.Fatal("unknown event")
	}
	if rec := apiCall(t, api, http.MethodGet, "/api/rules/930130", ""); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "受限文件") {
		t.Fatalf("rule: %s", rec.Body.String())
	}
	if rec := apiCall(t, api, http.MethodGet, "/api/rules/abc", ""); rec.Code != http.StatusBadRequest {
		t.Fatal("invalid rule id")
	}
	if rec := apiCall(t, api, http.MethodGet, "/api/rules/123", ""); rec.Code != http.StatusNotFound {
		t.Fatal("unknown rule id")
	}
	if rec := apiCall(t, api, http.MethodGet, "/api/rules?q=libinjection&kind=detection", ""); !strings.Contains(rec.Body.String(), "942100") {
		t.Fatal("rule search")
	}
	if rec := apiCall(t, api, http.MethodGet, "/api/analysis?range=24h", ""); !strings.Contains(rec.Body.String(), `"attackers":[`) ||
		!strings.Contains(rec.Body.String(), `"fp_candidates"`) || !strings.Contains(rec.Body.String(), `"would_block":`) ||
		strings.Contains(rec.Body.String(), `"Attackers"`) {
		t.Fatalf("analysis must use the snake_case API names: %s", rec.Body.String())
	}
	rec = apiCall(t, api, http.MethodPost, "/api/sites/example.com/impact", `{"exclusions":[{"type":"id","value":"930130","path":"/.git/","path_match":"prefix"}]}`)
	// Both /.git/config records (DetectionOnly and On) come from the same
	// fixture client, which the heuristics flag as an attacker.
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"unblocked":2`) || !strings.Contains(rec.Body.String(), `"attack_sources":1`) ||
		!strings.Contains(rec.Body.String(), "ruleRemoveById=930130") {
		t.Fatalf("impact: %s", rec.Body.String())
	}
	if rec := apiCall(t, api, http.MethodPost, "/api/sites/example.com/impact", `{"policy":{"blocking_pl":7}}`); rec.Code != http.StatusBadRequest {
		t.Fatal("invalid policy in impact")
	}
	rec = apiCall(t, api, http.MethodPut, "/api/sites/example.com/policy", `{"policy":{"blocking_pl":2,"inbound_threshold":7},"reason":"api change"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("set policy: %d %s", rec.Code, rec.Body.String())
	}
	rec = apiCall(t, api, http.MethodGet, "/api/sites/example.com/policy", "")
	if !strings.Contains(rec.Body.String(), `"blocking_pl":2`) || !strings.Contains(rec.Body.String(), `"inbound_threshold":7`) {
		t.Fatalf("get policy: %s", rec.Body.String())
	}
	if rec := apiCall(t, api, http.MethodPut, "/api/sites/example.com/policy", `{"policy":{"detection_pl":0,"blocking_pl":3,"inbound_threshold":0},"reason":""}`); rec.Code != http.StatusOK {
		t.Fatalf("defaults fill zero values: %d", rec.Code)
	}
	if rec := apiCall(t, api, http.MethodPut, "/api/sites/example.com/policy", `{"policy":{"blocking_pl":5}}`); rec.Code != http.StatusBadRequest {
		t.Fatal("invalid policy")
	}
	if rec := apiCall(t, api, http.MethodPut, "/api/sites/bad..domain/policy", `{"policy":{}}`); rec.Code != http.StatusBadRequest {
		t.Fatal("invalid domain")
	}
	if rec := apiCall(t, api, http.MethodGet, "/api/changes?site=example.com", ""); !strings.Contains(rec.Body.String(), "api change") {
		t.Fatalf("changes: %s", rec.Body.String())
	}
	if rec := apiCall(t, api, http.MethodPost, "/api/loki/backfill", `{}`); rec.Code != http.StatusServiceUnavailable {
		t.Fatal("backfill without Loki")
	}
}

func TestEventDetailShowsLocalMatchContextOnDemand(t *testing.T) {
	setupUIEnv(t)
	evs := setupWAFRuntime(t)
	raw, err := os.ReadFile(filepath.Join("..", "events", "testdata", "coraza-3.8.0-audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	audit := filepath.Join(t.TempDir(), "coraza-audit.log")
	if err := os.WriteFile(audit, raw, 0o640); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CADDY_UI_AUDIT_LOG", audit)
	git := evs["/.git/config|blocked"]
	page := getPage(t, "/?tab=event&tx="+git.TxID)
	if !strings.Contains(page, "Local match context") || !strings.Contains(page, "Show matched values") || strings.Contains(page, "<code>.git/</code>") {
		t.Fatal("matched values must only be read on demand")
	}
	page = getPage(t, "/?tab=event&tx="+git.TxID+"&raw=1")
	if !strings.Contains(page, "<code>.git/</code>") || !strings.Contains(page, "REQUEST_FILENAME") {
		t.Fatal("raw=1 must show the local matched fragment")
	}
	t.Setenv("CADDY_UI_AUDIT_LOG", filepath.Join(t.TempDir(), "rotated-away.log"))
	if page := getPage(t, "/?tab=event&tx="+git.TxID+"&raw=1"); !strings.Contains(page, "raw audit record not available locally") {
		t.Fatal("a missing raw record must be explained")
	}
}
