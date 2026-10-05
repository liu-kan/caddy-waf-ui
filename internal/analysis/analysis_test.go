package analysis

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/developmi/caddy-waf-ui/internal/crs"
	"github.com/developmi/caddy-waf-ui/internal/events"
	"github.com/developmi/caddy-waf-ui/internal/waf"
)

var base = time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)

type hitSpec struct {
	id    int
	v     string
	pl    int
	score int
	cat   string
	kind  string
}

func mk(n int, ip, path, action string, hits ...hitSpec) *events.Event {
	e := &events.Event{Kind: "event", TxID: fmt.Sprintf("tx-%s-%d-%s", ip, n, path), TS: base.Add(time.Duration(n) * time.Minute),
		Site: "a.com", ClientIP: ip, Path: path, Action: action, Mode: "On", Engine: "On",
		BlockingPL: 1, DetectionPL: 1, ThrIn: 5, ThrOut: 4, Tuning: true}
	ids := ","
	for _, h := range hits {
		kind := h.kind
		if kind == "" {
			kind = crs.KindDetection
		}
		pl := h.pl
		if pl == 0 {
			pl = 1
		}
		e.Hits = append(e.Hits, events.Hit{ID: h.id, Var: h.v, PL: pl, Score: h.score, Kind: kind, Dir: crs.DirInbound, Category: h.cat})
		ids += fmt.Sprint(h.id) + ","
	}
	e.RuleIDs = ids
	return e
}

// fixtureWindow: five legitimate users posting rich text that trips 942100
// on /api/posts, one attacker probing several categories, one scanner and
// one prober of restricted files.
func fixtureWindow() []*events.Event {
	var evs []*events.Event
	for i := 0; i < 5; i++ {
		evs = append(evs, mk(i, fmt.Sprintf("10.0.0.%d", i+1), fmt.Sprintf("/api/posts/%d", 100+i), events.ActionBlocked,
			hitSpec{id: 942100, v: "ARGS:content", score: 5, cat: "sqli"}, hitSpec{id: 949110, kind: crs.KindDecision}))
	}
	evs = append(evs,
		mk(10, "6.6.6.6", "/api/posts/1", events.ActionBlocked, hitSpec{id: 942100, v: "ARGS:content", score: 5, cat: "sqli"}, hitSpec{id: 949110, kind: crs.KindDecision}),
		mk(11, "6.6.6.6", "/search", events.ActionBlocked, hitSpec{id: 941100, v: "ARGS:q", score: 5, cat: "xss"}, hitSpec{id: 949110, kind: crs.KindDecision}),
		mk(12, "6.6.6.6", "/run", events.ActionBlocked, hitSpec{id: 932235, v: "ARGS:cmd", score: 5, cat: "rce"}, hitSpec{id: 949110, kind: crs.KindDecision}),
		mk(13, "7.7.7.7", "/", events.ActionBlocked, hitSpec{id: 913100, v: "REQUEST_HEADERS:User-Agent", score: 5, cat: "reputation-scanner"}, hitSpec{id: 949110, kind: crs.KindDecision}),
	)
	for i, p := range []string{"/.env", "/.git/config", "/.aws/credentials", "/.htpasswd", "/.docker/config.json"} {
		evs = append(evs, mk(20+i, "8.8.8.8", p, events.ActionBlocked, hitSpec{id: 930130, v: "REQUEST_FILENAME", score: 5, cat: "lfi"}, hitSpec{id: 949110, kind: crs.KindDecision}))
	}
	evs = append(evs, mk(30, "10.0.0.9", "/profile", events.ActionDetected, hitSpec{id: 920320, pl: 1, score: 2, cat: "protocol"}))
	return evs
}

func TestProfilesClassifyAttackers(t *testing.T) {
	byIP := map[string]SourceProfile{}
	for _, p := range Profiles(fixtureWindow()) {
		byIP[p.IP] = p
	}
	if p := byIP["6.6.6.6"]; !p.Attack || !strings.Contains(p.Reason, "3 attack categories") {
		t.Fatalf("multi-category source: %+v", p)
	}
	if p := byIP["7.7.7.7"]; !p.Attack || !p.Scanner {
		t.Fatalf("scanner: %+v", p)
	}
	if p := byIP["8.8.8.8"]; !p.Attack || !strings.Contains(p.Reason, "probed 5") {
		t.Fatalf("restricted file prober: %+v", p)
	}
	if p := byIP["10.0.0.1"]; p.Attack {
		t.Fatalf("a single false positive is not an attack: %+v", p)
	}
}

func TestAnalyzeFindsFalsePositivesAndNewRules(t *testing.T) {
	evs := fixtureWindow()
	r := Analyze(evs, crs.Default(), base, base.Add(time.Hour), "a.com", base.Add(25*time.Minute))
	if r.Events != len(evs) || r.Blocked != len(evs)-1 || r.Detected != 1 || len(r.Attackers) != 3 {
		t.Fatalf("totals: %+v", r)
	}
	if r.Rules[0].ID != 942100 || r.Rules[0].Sources != 6 || r.Rules[0].Attackers != 1 || !r.Rules[0].FPLikely {
		t.Fatalf("942100 summary: %+v", r.Rules[0])
	}
	if r.Rules[0].TopVars[0].Key != "ARGS:content" || r.Rules[0].TopVars[0].Sources != 6 {
		t.Fatalf("top vars: %+v", r.Rules[0].TopVars)
	}
	for _, rs := range r.Rules {
		if rs.ID == 949110 {
			t.Fatal("decision rules are not tuning targets")
		}
		if rs.ID == 930130 && rs.FPLikely {
			t.Fatal("a rule only hit by an attacker is not a false positive")
		}
	}
	// Each path is unique, so no single rule/path/variable has 3 clean sources.
	if len(r.FPCandidates) != 0 {
		t.Fatalf("per-path candidates need repeated sources: %+v", r.FPCandidates)
	}
	if len(r.NewRules) != 1 || r.NewRules[0].ID != 920320 {
		t.Fatalf("new rules: %+v", r.NewRules)
	}
}

func TestFPCandidateOnSharedPath(t *testing.T) {
	var evs []*events.Event
	for i := 0; i < 4; i++ {
		evs = append(evs, mk(i, fmt.Sprintf("10.1.0.%d", i), "/api/ask", events.ActionBlocked,
			hitSpec{id: 932235, v: "ARGS:json.text", score: 5, cat: "rce"}, hitSpec{id: 949110, kind: crs.KindDecision}))
	}
	r := Analyze(evs, crs.Default(), base, base.Add(time.Hour), "", time.Time{})
	if len(r.FPCandidates) != 1 {
		t.Fatalf("expected one candidate: %+v", r.FPCandidates)
	}
	c := r.FPCandidates[0]
	if c.Rule != 932235 || c.Path != "/api/ask" || c.Var != "ARGS:json.text" || c.Sources != 4 || c.Blocking != 4 {
		t.Fatalf("candidate: %+v", c)
	}
}

func TestEstimateExclusionScopes(t *testing.T) {
	evs := fixtureWindow()
	profiles := Profiles(evs)
	dict := crs.Default()
	narrow := Estimate(evs, profiles, dict, Change{Exclusions: []waf.Exclusion{
		{Type: waf.ExcludeByID, Value: "942100", Param: "content", Path: "/api/posts/", PathMatch: waf.PathPrefix}}})
	if narrow.Unblocked != 6 || narrow.AttackEvents != 1 || narrow.AttackSources != 1 || narrow.Sources != 6 {
		t.Fatalf("path+param exclusion: %+v", narrow)
	}
	other := Estimate(evs, profiles, dict, Change{Exclusions: []waf.Exclusion{
		{Type: waf.ExcludeByID, Value: "942100", Param: "title"}}})
	if other.Changed != 0 {
		t.Fatalf("a different parameter must not change anything: %+v", other)
	}
	tag := Estimate(evs, profiles, dict, Change{Exclusions: []waf.Exclusion{{Type: waf.ExcludeByTag, Value: "attack-xss"}}})
	if tag.Unblocked != 1 {
		t.Fatalf("tag exclusion uses the dictionary tags: %+v", tag)
	}
	regex := Estimate(evs, profiles, dict, Change{Exclusions: []waf.Exclusion{{Type: waf.ExcludeByID, Value: "942100", Param: `/^CON/`}}})
	if regex.Unblocked != 6 {
		t.Fatalf("regex parameter (case-insensitive): %+v", regex)
	}
}

func TestEstimatePolicyChanges(t *testing.T) {
	evs := fixtureWindow()
	dict := crs.Default()
	looser := waf.Policy{BlockingPL: 1, InboundThreshold: 10, OutboundThreshold: 4}
	im := Estimate(evs, nil, dict, Change{Policy: &looser})
	if im.Unblocked != len(evs)-1 {
		t.Fatalf("threshold 10 unblocks every single-rule event: %+v", im)
	}
	stricter := waf.Policy{BlockingPL: 1, InboundThreshold: 2, OutboundThreshold: 4}
	im = Estimate(evs, nil, dict, Change{Policy: &stricter})
	if im.NewlyBlocked != 1 {
		t.Fatalf("threshold 2 blocks the sub-threshold notice: %+v", im)
	}
	higher := waf.Policy{BlockingPL: 2, InboundThreshold: 5, OutboundThreshold: 4}
	im = Estimate(evs, nil, dict, Change{Policy: &higher})
	if len(im.Caveats) == 0 || !strings.Contains(strings.Join(im.Caveats, " "), "detection paranoia level") {
		t.Fatalf("raising PL beyond the recorded detection level must be flagged: %+v", im.Caveats)
	}
	im = Estimate(evs, nil, dict, Change{Mode: "DetectionOnly"})
	if im.Changed != len(evs)-1 || im.Unblocked != 0 || im.NewlyBlocked != 0 {
		t.Fatalf("DetectionOnly turns blocks into would-blocks: %+v", im)
	}
}

func TestSuggestNarrowestFirst(t *testing.T) {
	evs := fixtureWindow()
	profiles := Profiles(evs)
	s := Suggest(evs[0], evs, profiles, crs.Default())
	if len(s) != 3 {
		t.Fatalf("expected narrowest, prefix and site-wide parameter scopes: %+v", s)
	}
	if s[0].Scope != "narrowest" || s[0].Exclusion.Path != "/api/posts/100" || s[0].Exclusion.PathMatch != waf.PathExact || s[0].Exclusion.Param != "content" {
		t.Fatalf("narrowest: %+v", s[0].Exclusion)
	}
	if s[0].Impact.Unblocked != 1 || !s[0].ClearsEvent {
		t.Fatalf("narrowest impact: %+v", s[0].Impact)
	}
	if s[1].Exclusion.Path != "/api/posts/" || s[1].Impact.Unblocked != 6 || s[1].Impact.AttackSources != 1 {
		t.Fatalf("prefix scope: %+v %+v", s[1].Exclusion, s[1].Impact)
	}
	if s[2].Exclusion.Path != "" || s[2].Exclusion.Param != "content" {
		t.Fatalf("site-wide parameter: %+v", s[2].Exclusion)
	}
	for _, sug := range s {
		if err := waf.ValidateExclusions([]waf.Exclusion{sug.Exclusion}); err != nil {
			t.Fatalf("suggestions must be valid exclusions: %v", err)
		}
	}
	// A request blocked by a direct-block rule gets a path-scoped suggestion.
	broken := mk(40, "10.0.0.7", "/api/upload", events.ActionBlocked, hitSpec{id: 200002, kind: crs.KindBlocking})
	if s := Suggest(broken, []*events.Event{broken}, nil, crs.Default()); len(s) != 2 || s[0].Exclusion.Param != "" || s[1].Exclusion.Path != "/api/" || !s[0].ClearsEvent {
		t.Fatalf("direct block suggestion: %+v", s)
	}
}
