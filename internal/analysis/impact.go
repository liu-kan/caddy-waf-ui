package analysis

import (
	"fmt"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/developmi/caddy-waf-ui/internal/crs"
	"github.com/developmi/caddy-waf-ui/internal/events"
	"github.com/developmi/caddy-waf-ui/internal/waf"
)

// Change is a candidate policy change evaluated against history.
type Change struct {
	Exclusions []waf.Exclusion
	Policy     *waf.Policy
	Mode       string
}

// Outcomes of the score model.
const (
	OutcomePass       = "pass"
	OutcomeBlocked    = events.ActionBlocked
	OutcomeWouldBlock = events.ActionWouldBlock
)

// Impact is the estimated effect of a change over a window of events.
type Impact struct {
	Events        int
	Changed       int
	Unblocked     int
	NewlyBlocked  int
	Sources       int
	AttackSources int
	AttackEvents  int
	Samples       []*events.Event
	Caveats       []string
}

const maxSamples = 10

// Estimate replays the anomaly-score decision of every event with the
// change applied. The baseline is the recorded outcome; the new outcome is
// recomputed from the recorded rule matches. Rules that never ran (above the
// recorded detection paranoia level) and requests that were not recorded
// (no tuning mode) cannot be replayed and are reported as caveats.
func Estimate(evs []*events.Event, profiles []SourceProfile, dict *crs.Dictionary, change Change) Impact {
	attackers := map[string]bool{}
	for _, p := range profiles {
		if p.Attack {
			attackers[p.IP] = true
		}
	}
	var (
		im          = Impact{Events: len(evs)}
		sources     = map[string]bool{}
		attackSrcs  = map[string]bool{}
		mismatch    int
		unreplayed  int
		untuned     int
		noVar       int
		unknownTags int
	)
	matchers := compileExclusions(change.Exclusions)
	for _, e := range evs {
		bpl, dpl, in, out := e.Thresholds()
		mode := e.Mode
		if mode == "" {
			mode = e.Engine
		}
		recorded := recordedOutcome(e)
		if model := evaluate(e, bpl, in, out, mode, nil, dict); model != recorded {
			mismatch++
		}
		nbpl, nin, nout, nmode := bpl, in, out, mode
		if change.Policy != nil {
			p := change.Policy.Normalize()
			nbpl, nin, nout = p.BlockingPL, p.InboundThreshold, p.OutboundThreshold
			if p.BlockingPL > dpl {
				unreplayed++
			}
			if !e.Tuning && (nin < in || nout < out || nbpl > bpl) {
				untuned++
			}
		}
		if change.Mode != "" {
			nmode = change.Mode
		}
		for _, m := range matchers {
			if m.ex.Param != "" {
				for _, h := range e.Hits {
					if h.ID == m.id && h.Var == "" {
						noVar++
					}
				}
			}
			if m.ex.Type == waf.ExcludeByTag {
				for _, h := range e.Hits {
					if _, ok := dict.Lookup(h.ID); !ok && h.Kind != crs.KindDecision {
						unknownTags++
					}
				}
			}
		}
		next := evaluate(e, nbpl, nin, nout, nmode, matchers, dict)
		if next == recorded {
			continue
		}
		im.Changed++
		sources[e.ClientIP] = true
		switch {
		case recorded != OutcomePass && next == OutcomePass:
			im.Unblocked++
			if attackers[e.ClientIP] {
				im.AttackEvents++
				attackSrcs[e.ClientIP] = true
			}
		case recorded == OutcomePass && next != OutcomePass:
			im.NewlyBlocked++
		}
		if len(im.Samples) < maxSamples {
			im.Samples = append(im.Samples, e)
		}
	}
	im.Sources = len(sources)
	im.AttackSources = len(attackSrcs)
	if mismatch > 0 {
		im.Caveats = append(im.Caveats, fmt.Sprintf("%d event(s) recompute to a different baseline than recorded (chained rules, custom score settings or rules that changed since); their estimate is approximate", mismatch))
	}
	if unreplayed > 0 {
		im.Caveats = append(im.Caveats, fmt.Sprintf("%d event(s) were recorded with a detection paranoia level below the new blocking level: rules of the higher level did not run, so new blocks are undercounted. Enable detection PL = blocking PL + 1 first", unreplayed))
	}
	if untuned > 0 {
		im.Caveats = append(im.Caveats, fmt.Sprintf("tuning mode was off for %d event(s): requests below the old threshold were not recorded, so new blocks are undercounted", untuned))
	}
	if noVar > 0 {
		im.Caveats = append(im.Caveats, fmt.Sprintf("%d match(es) of the excluded rule carry no variable name; they are counted as still matching", noVar))
	}
	if unknownTags > 0 {
		im.Caveats = append(im.Caveats, "tag exclusions cannot be evaluated for rules outside the dictionary (custom rules)")
	}
	return im
}

func recordedOutcome(e *events.Event) string {
	switch e.Action {
	case events.ActionBlocked:
		return OutcomeBlocked
	case events.ActionWouldBlock:
		return OutcomeWouldBlock
	}
	return OutcomePass
}

// evaluate applies the CRS anomaly-scoring decision to the recorded hits.
func evaluate(e *events.Event, bpl, in, out int, mode string, matchers []exclusionMatcher, dict *crs.Dictionary) string {
	scoreIn, scoreOut := 0, 0
	direct := false
	for _, h := range e.Hits {
		if excluded(h, e, matchers, dict) {
			continue
		}
		switch h.Kind {
		case crs.KindDetection:
			pl := h.PL
			if pl == 0 {
				pl = 1
			}
			if pl > bpl {
				continue
			}
			if h.Dir == crs.DirOutbound {
				scoreOut += h.Score
			} else {
				scoreIn += h.Score
			}
		case crs.KindBlocking:
			direct = true
		}
	}
	if !direct && scoreIn < in && scoreOut < out {
		return OutcomePass
	}
	switch strings.ToLower(mode) {
	case "on":
		return OutcomeBlocked
	case "detectiononly":
		return OutcomeWouldBlock
	}
	return OutcomePass
}

type exclusionMatcher struct {
	ex    waf.Exclusion
	id    int
	param *regexp.Regexp
}

func compileExclusions(list []waf.Exclusion) []exclusionMatcher {
	var out []exclusionMatcher
	for _, ex := range list {
		m := exclusionMatcher{ex: ex}
		if ex.Type == waf.ExcludeByID {
			m.id, _ = strconv.Atoi(ex.Value)
		}
		if p := ex.Param; strings.HasPrefix(p, "/") && strings.HasSuffix(p, "/") && len(p) > 2 {
			if re, err := regexp.Compile("(?i)" + p[1:len(p)-1]); err == nil {
				m.param = re
			}
		}
		out = append(out, m)
	}
	return out
}

// argKey returns the ARGS key of a matched variable, or "".
func argKey(variable string) string {
	for _, prefix := range []string{"ARGS:", "ARGS_GET:", "ARGS_POST:"} {
		if strings.HasPrefix(variable, prefix) {
			return strings.TrimPrefix(variable, prefix)
		}
	}
	return ""
}

func excluded(h events.Hit, e *events.Event, matchers []exclusionMatcher, dict *crs.Dictionary) bool {
	for _, m := range matchers {
		switch m.ex.Type {
		case waf.ExcludeByID:
			if h.ID != m.id {
				continue
			}
		case waf.ExcludeByTag:
			r, ok := dict.Lookup(h.ID)
			if !ok || !containsTag(r.Tags, m.ex.Value) {
				continue
			}
		}
		if m.ex.Path != "" {
			if m.ex.PathMatch == waf.PathExact {
				if e.Path != m.ex.Path {
					continue
				}
			} else if !strings.HasPrefix(e.Path, m.ex.Path) {
				continue
			}
		}
		if m.ex.Param != "" {
			key := argKey(h.Var)
			if key == "" {
				continue
			}
			if m.param != nil {
				if !m.param.MatchString(key) {
					continue
				}
			} else if !strings.EqualFold(key, m.ex.Param) {
				continue
			}
		}
		return true
	}
	return false
}

func containsTag(tags []string, tag string) bool {
	for _, t := range tags {
		if t == tag {
			return true
		}
	}
	return false
}

// Suggestion is a candidate exclusion for one matched rule of an event,
// from the narrowest scope to broader ones, with its estimated impact.
type Suggestion struct {
	Rule      int
	RuleMsg   string
	Var       string
	Scope     string
	Exclusion waf.Exclusion
	Impact    Impact
	// ClearsEvent reports whether the event itself would pass with all the
	// narrowest suggestions applied together.
	ClearsEvent bool
}

// Suggest proposes exclusions for the score-contributing rules of e and
// estimates each over window (events of the same site).
func Suggest(e *events.Event, window []*events.Event, profiles []SourceProfile, dict *crs.Dictionary) []Suggestion {
	bpl, _, thrIn, thrOut := e.Thresholds()
	type key struct {
		id int
		v  string
	}
	seen := map[key]bool{}
	var narrowest []waf.Exclusion
	var suggestions []Suggestion
	for _, h := range e.Hits {
		if h.Kind != crs.KindDetection && h.Kind != crs.KindBlocking {
			continue
		}
		if h.Kind == crs.KindDetection && h.PL > bpl {
			continue
		}
		if r, ok := dict.Lookup(h.ID); ok && !r.IsExcludable() {
			continue
		}
		k := key{h.ID, h.Var}
		if seen[k] {
			continue
		}
		seen[k] = true
		param := argKey(h.Var)
		if param != "" && waf.ValidateParam(param) != nil {
			param = "" // keys that cannot be expressed safely fall back to path scope
		}
		id := strconv.Itoa(h.ID)
		var scopes []Suggestion
		if e.Path != "" && waf.ValidatePath(e.Path) == nil {
			exact := waf.Exclusion{Type: waf.ExcludeByID, Value: id, Path: e.Path, PathMatch: waf.PathExact, Param: param}
			scopes = append(scopes, Suggestion{Scope: "narrowest", Exclusion: exact})
			narrowest = append(narrowest, exact)
			if dir := path.Dir(e.Path); dir != "/" && dir != "." && dir != e.Path {
				scopes = append(scopes, Suggestion{Scope: "path prefix", Exclusion: waf.Exclusion{Type: waf.ExcludeByID, Value: id, Path: dir + "/", PathMatch: waf.PathPrefix, Param: param}})
			}
		}
		if param != "" {
			scopes = append(scopes, Suggestion{Scope: "parameter, whole site", Exclusion: waf.Exclusion{Type: waf.ExcludeByID, Value: id, Param: param}})
		}
		for _, s := range scopes {
			s.Rule, s.Var = h.ID, h.Var
			if r, ok := dict.Lookup(h.ID); ok {
				s.RuleMsg = r.Msg
			}
			s.Impact = Estimate(window, profiles, dict, Change{Exclusions: []waf.Exclusion{s.Exclusion}})
			suggestions = append(suggestions, s)
		}
	}
	clears := evaluate(e, bpl, thrIn, thrOut, "on", compileExclusions(narrowest), dict) == OutcomePass
	for i := range suggestions {
		suggestions[i].ClearsEvent = clears
	}
	sort.SliceStable(suggestions, func(i, j int) bool { return suggestions[i].Rule < suggestions[j].Rule })
	return suggestions
}
