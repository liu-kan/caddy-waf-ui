// Package analysis answers the retrospective questions of WAF tuning over a
// window of stored events: which rules match where, which sources look like
// attackers and which matches look like false positives, and what a policy
// change would have changed had it been active.
package analysis

import (
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/developmi/caddy-waf-ui/internal/crs"
	"github.com/developmi/caddy-waf-ui/internal/events"
)

// Heuristic thresholds. A rule/path pair hit by many different sources that
// trigger nothing else is typical of a false positive; a source that
// triggers many attack categories, scanner signatures or restricted-file
// probes on many paths is typical of an attack.
const (
	fpMinSources        = 3
	fpCleanRatio        = 0.8
	attackMinCategories = 3
	probeMinPaths       = 5
	topN                = 10
)

// SourceProfile classifies one client address over the window.
type SourceProfile struct {
	IP         string
	Events     int
	Blocked    int
	Rules      []int
	Categories []string
	Paths      int
	Scanner    bool
	Attack     bool
	Reason     string
	FirstSeen  time.Time
	LastSeen   time.Time
}

// RuleSummary aggregates one rule.
type RuleSummary struct {
	ID         int
	Rule       crs.Rule
	Known      bool
	Hits       int
	Events     int
	Blocked    int
	WouldBlock int
	Detected   int
	Sources    int
	Attackers  int
	Sites      []string
	TopPaths   []Count
	TopVars    []Count
	FirstSeen  time.Time
	LastSeen   time.Time
	FPLikely   bool
	FPReason   string
}

// Count is a labelled counter.
type Count struct {
	Key     string
	Count   int
	Sources int
}

// PathSummary aggregates one request path.
type PathSummary struct {
	Path    string
	Events  int
	Sources int
	Rules   []Count
}

// FPCandidate is a rule/path/variable combination that looks like a false
// positive, with the narrowest exclusion that would cover it.
type FPCandidate struct {
	Rule     int
	RuleMsg  string
	Site     string
	Path     string
	Var      string
	Events   int
	Sources  int
	Blocking int
	Reason   string
}

// Report is the analysis of one window.
type Report struct {
	From, To     time.Time
	Site         string
	Events       int
	Blocked      int
	WouldBlock   int
	Detected     int
	Sources      int
	Rules        []RuleSummary
	TopSources   []SourceProfile
	Attackers    []SourceProfile
	Paths        []PathSummary
	FPCandidates []FPCandidate
	NewRules     []RuleSummary
	ScoreGap     int
}

// Analyze builds the report of evs (chronological), using dict for rule
// metadata. newSince marks rules first seen after that time as new.
func Analyze(evs []*events.Event, dict *crs.Dictionary, from, to time.Time, site string, newSince time.Time) Report {
	r := Report{From: from, To: to, Site: site, Events: len(evs)}
	profiles := Profiles(evs)
	attackers := map[string]bool{}
	for _, p := range profiles {
		if p.Attack {
			attackers[p.IP] = true
			r.Attackers = append(r.Attackers, p)
		}
	}
	r.Sources = len(profiles)

	type ruleAcc struct {
		sum      RuleSummary
		events   map[string]bool
		sources  map[string]bool
		attack   map[string]bool
		sites    map[string]bool
		paths    map[string]map[string]bool
		pathHits map[string]int
		vars     map[string]map[string]bool
		varHits  map[string]int
	}
	rules := map[int]*ruleAcc{}
	type pathAcc struct {
		events  int
		sources map[string]bool
		rules   map[int]int
	}
	paths := map[string]*pathAcc{}
	type fpKey struct {
		rule       int
		site, path string
		v          string
	}
	type fpAcc struct {
		events, blocking int
		sources          map[string]bool
	}
	fps := map[fpKey]*fpAcc{}

	for _, e := range evs {
		switch e.Action {
		case events.ActionBlocked:
			r.Blocked++
		case events.ActionWouldBlock:
			r.WouldBlock++
		default:
			r.Detected++
		}
		if e.ReportedIn > 0 && e.ReportedIn != e.ScoreIn {
			r.ScoreGap++
		}
		pa := paths[e.Path]
		if pa == nil {
			pa = &pathAcc{sources: map[string]bool{}, rules: map[int]int{}}
			paths[e.Path] = pa
		}
		pa.events++
		pa.sources[e.ClientIP] = true
		seenInEvent := map[int]bool{}
		seenFP := map[fpKey]bool{}
		for _, h := range e.Hits {
			if h.Kind == crs.KindDecision || h.Kind == crs.KindUI || h.Kind == crs.KindCorrelation {
				continue
			}
			acc := rules[h.ID]
			if acc == nil {
				acc = &ruleAcc{events: map[string]bool{}, sources: map[string]bool{}, attack: map[string]bool{}, sites: map[string]bool{},
					paths: map[string]map[string]bool{}, pathHits: map[string]int{}, vars: map[string]map[string]bool{}, varHits: map[string]int{}}
				acc.sum.ID = h.ID
				acc.sum.Rule, acc.sum.Known = dict.Lookup(h.ID)
				acc.sum.FirstSeen = e.TS
				rules[h.ID] = acc
			}
			acc.sum.Hits++
			acc.sum.LastSeen = e.TS
			if !seenInEvent[h.ID] {
				seenInEvent[h.ID] = true
				acc.sum.Events++
				pa.rules[h.ID]++
				switch e.Action {
				case events.ActionBlocked:
					acc.sum.Blocked++
				case events.ActionWouldBlock:
					acc.sum.WouldBlock++
				default:
					acc.sum.Detected++
				}
			}
			acc.events[e.TxID] = true
			acc.sources[e.ClientIP] = true
			if attackers[e.ClientIP] {
				acc.attack[e.ClientIP] = true
			}
			acc.sites[e.Site] = true
			if acc.paths[e.Path] == nil {
				acc.paths[e.Path] = map[string]bool{}
			}
			acc.paths[e.Path][e.ClientIP] = true
			acc.pathHits[e.Path]++
			if h.Var != "" {
				if acc.vars[h.Var] == nil {
					acc.vars[h.Var] = map[string]bool{}
				}
				acc.vars[h.Var][e.ClientIP] = true
				acc.varHits[h.Var]++
			}
			if h.Kind == crs.KindDetection || h.Kind == crs.KindBlocking {
				k := fpKey{rule: h.ID, site: e.Site, path: e.Path, v: h.Var}
				fa := fps[k]
				if fa == nil {
					fa = &fpAcc{sources: map[string]bool{}}
					fps[k] = fa
				}
				if !seenFP[k] {
					seenFP[k] = true
					fa.events++
					if e.Action != events.ActionDetected {
						fa.blocking++
					}
				}
				fa.sources[e.ClientIP] = true
			}
		}
	}

	for _, acc := range rules {
		s := acc.sum
		s.Sources = len(acc.sources)
		s.Attackers = len(acc.attack)
		s.Sites = sortedKeys(acc.sites)
		s.TopPaths = topCounts(acc.pathHits, acc.paths)
		s.TopVars = topCounts(acc.varHits, acc.vars)
		clean := s.Sources - s.Attackers
		if s.Sources >= fpMinSources && float64(clean) >= fpCleanRatio*float64(s.Sources) {
			s.FPLikely = true
			s.FPReason = "matched by many sources that trigger no other attack signals"
		}
		r.Rules = append(r.Rules, s)
		if !newSince.IsZero() && !s.FirstSeen.Before(newSince) {
			r.NewRules = append(r.NewRules, s)
		}
	}
	sort.Slice(r.Rules, func(i, j int) bool {
		if r.Rules[i].Events != r.Rules[j].Events {
			return r.Rules[i].Events > r.Rules[j].Events
		}
		return r.Rules[i].ID < r.Rules[j].ID
	})
	sort.Slice(r.NewRules, func(i, j int) bool { return r.NewRules[i].FirstSeen.After(r.NewRules[j].FirstSeen) })

	for path, acc := range paths {
		ps := PathSummary{Path: path, Events: acc.events, Sources: len(acc.sources)}
		for id, n := range acc.rules {
			ps.Rules = append(ps.Rules, Count{Key: strconv.Itoa(id), Count: n})
		}
		sort.Slice(ps.Rules, func(i, j int) bool { return ps.Rules[i].Count > ps.Rules[j].Count })
		if len(ps.Rules) > 5 {
			ps.Rules = ps.Rules[:5]
		}
		r.Paths = append(r.Paths, ps)
	}
	sort.Slice(r.Paths, func(i, j int) bool { return r.Paths[i].Events > r.Paths[j].Events })
	if len(r.Paths) > topN {
		r.Paths = r.Paths[:topN]
	}

	for k, fa := range fps {
		total := len(fa.sources)
		clean := 0
		for ip := range fa.sources {
			if !attackers[ip] {
				clean++
			}
		}
		if total < fpMinSources || float64(clean) < fpCleanRatio*float64(total) {
			continue
		}
		rule, _ := dict.Lookup(k.rule)
		if !rule.IsExcludable() && rule.Kind != "" && rule.Kind != "unknown" {
			continue
		}
		r.FPCandidates = append(r.FPCandidates, FPCandidate{Rule: k.rule, RuleMsg: rule.Msg, Site: k.site, Path: k.path, Var: k.v,
			Events: fa.events, Sources: total, Blocking: fa.blocking,
			Reason: "same rule, path and variable matched by many sources without other attack signals"})
	}
	// Candidates that actually block legitimate traffic come first.
	sort.Slice(r.FPCandidates, func(i, j int) bool {
		a, b := r.FPCandidates[i], r.FPCandidates[j]
		if a.Blocking != b.Blocking {
			return a.Blocking > b.Blocking
		}
		if a.Sources != b.Sources {
			return a.Sources > b.Sources
		}
		if a.Events != b.Events {
			return a.Events > b.Events
		}
		return a.Rule < b.Rule
	})

	r.TopSources = profiles
	sort.Slice(r.TopSources, func(i, j int) bool { return r.TopSources[i].Events > r.TopSources[j].Events })
	if len(r.TopSources) > topN {
		r.TopSources = r.TopSources[:topN]
	}
	sort.Slice(r.Attackers, func(i, j int) bool { return len(r.Attackers[i].Categories) > len(r.Attackers[j].Categories) })
	return r
}

// Profiles classifies every source address of evs.
func Profiles(evs []*events.Event) []SourceProfile {
	type acc struct {
		p          SourceProfile
		rules      map[int]bool
		categories map[string]bool
		paths      map[string]bool
		probes     map[string]bool
	}
	byIP := map[string]*acc{}
	var order []string
	for _, e := range evs {
		a := byIP[e.ClientIP]
		if a == nil {
			a = &acc{p: SourceProfile{IP: e.ClientIP, FirstSeen: e.TS}, rules: map[int]bool{}, categories: map[string]bool{}, paths: map[string]bool{}, probes: map[string]bool{}}
			byIP[e.ClientIP] = a
			order = append(order, e.ClientIP)
		}
		a.p.Events++
		a.p.LastSeen = e.TS
		if e.Action == events.ActionBlocked {
			a.p.Blocked++
		}
		a.paths[e.Path] = true
		for _, h := range e.Hits {
			if h.Kind != crs.KindDetection && h.Kind != crs.KindBlocking {
				continue
			}
			a.rules[h.ID] = true
			if h.Category != "" && h.Kind == crs.KindDetection {
				a.categories[h.Category] = true
			}
			if h.Category == "reputation-scanner" {
				a.p.Scanner = true
			}
			if h.ID == 930130 || h.ID == 930140 || h.ID == 920500 || h.ID == 920440 {
				a.probes[e.Path] = true
			}
		}
	}
	out := make([]SourceProfile, 0, len(order))
	for _, ip := range order {
		a := byIP[ip]
		p := a.p
		for id := range a.rules {
			p.Rules = append(p.Rules, id)
		}
		sort.Ints(p.Rules)
		p.Categories = sortedKeys(a.categories)
		p.Paths = len(a.paths)
		switch {
		case p.Scanner:
			p.Attack, p.Reason = true, "security scanner signature"
		case len(p.Categories) >= attackMinCategories:
			p.Attack, p.Reason = true, "matched "+strconv.Itoa(len(p.Categories))+" attack categories: "+strings.Join(p.Categories, ", ")
		case len(a.probes) >= probeMinPaths:
			p.Attack, p.Reason = true, "probed "+strconv.Itoa(len(a.probes))+" restricted files or extensions"
		}
		out = append(out, p)
	}
	return out
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func topCounts(hits map[string]int, sources map[string]map[string]bool) []Count {
	out := make([]Count, 0, len(hits))
	for k, n := range hits {
		out = append(out, Count{Key: k, Count: n, Sources: len(sources[k])})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Key < out[j].Key
	})
	if len(out) > 5 {
		out = out[:5]
	}
	return out
}
