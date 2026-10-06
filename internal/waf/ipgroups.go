package waf

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/developmi/caddy-waf-ui/internal/crs"
	"github.com/developmi/caddy-waf-ui/internal/domain"
)

// IP group rule actions.
const (
	// GroupBlock denies the request with 403.
	GroupBlock = "block"
	// GroupTrial records what GroupBlock would deny without denying it.
	GroupTrial = "trial"
	// GroupEngine switches the rule engine (On, DetectionOnly, Off).
	GroupEngine = "engine"
	// GroupTune overrides paranoia levels and anomaly thresholds.
	GroupTune = "tune"
)

// MaxIPGroupRules bounds the group rules of a site.
const MaxIPGroupRules = 64

var groupNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,31}$`)

// IPGroupRule applies a per-request policy to clients inside an IP group,
// or outside it with Negate. Rules run in list order before the CRS rules:
// a block ends the evaluation, later engine and tuning rules override
// earlier ones. Group lists are matched with @ipMatchFromFile against the
// client address that Caddy resolved (trusted proxies included).
type IPGroupRule struct {
	Group             string `json:"group"`
	Negate            bool   `json:"negate,omitempty"`
	Action            string `json:"action"`
	Engine            string `json:"engine,omitempty"`
	BlockingPL        int    `json:"blocking_pl,omitempty"`
	DetectionPL       int    `json:"detection_pl,omitempty"`
	InboundThreshold  int    `json:"inbound_threshold,omitempty"`
	OutboundThreshold int    `json:"outbound_threshold,omitempty"`
	Note              string `json:"note,omitempty"`
}

// Scope describes which clients a rule applies to.
func (g IPGroupRule) Scope() string {
	if g.Negate {
		return "outside " + g.Group
	}
	return "inside " + g.Group
}

// Describe returns a short description of the rule.
func (g IPGroupRule) Describe() string {
	switch g.Action {
	case GroupBlock:
		return "block clients " + g.Scope()
	case GroupTrial:
		return "record (trial) clients " + g.Scope() + " that would be blocked"
	case GroupEngine:
		return "rule engine " + g.Engine + " for clients " + g.Scope()
	}
	var parts []string
	for _, v := range []struct {
		name  string
		value int
	}{{"blocking PL", g.BlockingPL}, {"detection PL", g.DetectionPL}, {"inbound threshold", g.InboundThreshold}, {"outbound threshold", g.OutboundThreshold}} {
		if v.value > 0 {
			parts = append(parts, v.name+" "+strconv.Itoa(v.value))
		}
	}
	return strings.Join(parts, ", ") + " for clients " + g.Scope()
}

// validateGroupRule checks one rule against the site policy p.
func validateGroupRule(g IPGroupRule, p Policy) error {
	if !groupNamePattern.MatchString(g.Group) {
		return fmt.Errorf("invalid IP group name %q", g.Group)
	}
	if len(g.Note) > maxNoteLength || noteForbidden.MatchString(g.Note) || strings.Contains(g.Note, "{$") {
		return fmt.Errorf("invalid note: at most %d printable characters, no backticks", maxNoteLength)
	}
	tuned := g.BlockingPL != 0 || g.DetectionPL != 0 || g.InboundThreshold != 0 || g.OutboundThreshold != 0
	switch g.Action {
	case GroupBlock, GroupTrial:
		if tuned || g.Engine != "" {
			return fmt.Errorf("%s rules take no engine or threshold values", g.Action)
		}
	case GroupEngine:
		if g.Engine != string(domain.ModeOn) && g.Engine != string(domain.ModeDetectionOnly) && g.Engine != string(domain.ModeOff) {
			return fmt.Errorf("invalid engine %q: use On, DetectionOnly or Off", g.Engine)
		}
		if tuned {
			return fmt.Errorf("engine rules take no threshold values")
		}
	case GroupTune:
		if g.Engine != "" {
			return fmt.Errorf("tune rules take no engine")
		}
		if !tuned {
			return fmt.Errorf("a tune rule needs at least one paranoia level or threshold")
		}
		for _, pl := range []int{g.BlockingPL, g.DetectionPL} {
			if pl < 0 || pl > 4 {
				return fmt.Errorf("paranoia levels must be 1-4")
			}
		}
		for _, t := range []int{g.InboundThreshold, g.OutboundThreshold} {
			if t < 0 || t > maxThreshold {
				return fmt.Errorf("anomaly thresholds must be 1-%d", maxThreshold)
			}
		}
		bpl := p.BlockingPL
		if g.BlockingPL > 0 {
			bpl = g.BlockingPL
		}
		if g.DetectionPL > 0 && g.DetectionPL < bpl {
			return fmt.Errorf("the detection paranoia level of a tune rule must be at least its blocking level (%d)", bpl)
		}
	default:
		return fmt.Errorf("invalid IP group action %q: use block, trial, engine or tune", g.Action)
	}
	return nil
}

// Effective returns the levels and thresholds that a tune rule leaves in
// force under the site policy p. Raising the blocking level raises the
// detection level with it: CRS rule 901500 rejects a detection level below
// the blocking level.
func (g IPGroupRule) Effective(p Policy) (bpl, dpl, in, out int) {
	bpl, dpl, in, out = p.BlockingPL, p.DetectionPL, p.InboundThreshold, p.OutboundThreshold
	if g.BlockingPL > 0 {
		bpl = g.BlockingPL
	}
	if g.DetectionPL > 0 {
		dpl = g.DetectionPL
	}
	dpl = max(dpl, bpl)
	if g.InboundThreshold > 0 {
		in = g.InboundThreshold
	}
	if g.OutboundThreshold > 0 {
		out = g.OutboundThreshold
	}
	return bpl, dpl, in, out
}

// renderGroups returns the group rules; files maps each group to the list
// path Caddy reads.
func (p Policy) renderGroups(files map[string]string) ([]string, error) {
	out := make([]string, 0, len(p.IPGroups))
	for i, g := range p.IPGroups {
		path, ok := files[g.Group]
		if !ok {
			return nil, fmt.Errorf("IP group %q has no active list: import it before using it in a policy", g.Group)
		}
		if err := validateDirectivePath(path); err != nil {
			return nil, err
		}
		op := "@ipMatchFromFile " + path
		if g.Negate {
			op = "!" + op
		}
		const tag = "tag:'caddy-waf-ui/ipgroup'"
		var actions string
		switch g.Action {
		case GroupBlock:
			actions = fmt.Sprintf("id:%d,phase:1,deny,status:403,t:none,nolog,auditlog,%s,msg:'IP group policy: %s blocked'",
				crs.UIGroupBlockMin+i, tag, g.Scope())
		case GroupTrial:
			actions = fmt.Sprintf("id:%d,phase:1,pass,t:none,nolog,auditlog,ctl:auditEngine=On,%s,msg:'IP group policy (trial): %s would be blocked'",
				crs.UIGroupBlockMin+i, tag, g.Scope())
		case GroupEngine:
			actions = fmt.Sprintf("id:%d,phase:1,pass,t:none,nolog,auditlog,ctl:ruleEngine=%s,%s,msg:'IP group policy: %s engine %s'",
				crs.UIGroupControlMin+i, g.Engine, tag, g.Scope(), g.Engine)
		case GroupTune:
			bpl, dpl, in, outTh := g.Effective(p)
			var setvars []string
			if g.BlockingPL > 0 {
				setvars = append(setvars, "setvar:tx.blocking_paranoia_level="+strconv.Itoa(bpl))
			}
			if g.BlockingPL > 0 || g.DetectionPL > 0 {
				setvars = append(setvars, "setvar:tx.detection_paranoia_level="+strconv.Itoa(dpl))
			}
			if g.InboundThreshold > 0 {
				setvars = append(setvars, "setvar:tx.inbound_anomaly_score_threshold="+strconv.Itoa(in))
			}
			if g.OutboundThreshold > 0 {
				setvars = append(setvars, "setvar:tx.outbound_anomaly_score_threshold="+strconv.Itoa(outTh))
			}
			// The message carries the values in force so events can be
			// scored with the thresholds that applied to the request.
			actions = fmt.Sprintf("id:%d,phase:1,pass,t:none,nolog,auditlog,%s,%s,msg:'IP group policy: %s tune bpl=%d dpl=%d in=%d out=%d'",
				crs.UIGroupControlMin+i, strings.Join(setvars, ","), tag, g.Scope(), bpl, dpl, in, outTh)
		}
		out = append(out, fmt.Sprintf(`SecRule REMOTE_ADDR "%s" "%s"`, op, actions))
	}
	return out, nil
}
