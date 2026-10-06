package waf

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/developmi/caddy-waf-ui/internal/domain"
)

// Policy is the per-site CRS tuning model. Zero values mean "CRS default"
// and are normalized by Normalize.
type Policy struct {
	// BlockingPL is the paranoia level whose rules add to the blocking score.
	BlockingPL int `json:"blocking_pl"`
	// DetectionPL >= BlockingPL also executes and logs higher-level rules
	// without letting them block, to collect data before raising BlockingPL.
	DetectionPL       int  `json:"detection_pl"`
	InboundThreshold  int  `json:"inbound_threshold"`
	OutboundThreshold int  `json:"outbound_threshold"`
	EarlyBlocking     bool `json:"early_blocking,omitempty"`
	// Tuning records transactions with any anomaly score in the audit log,
	// not only the ones that were (or would have been) blocked.
	Tuning              bool     `json:"tuning,omitempty"`
	AllowedMethods      []string `json:"allowed_methods,omitempty"`
	AllowedContentTypes []string `json:"allowed_content_types,omitempty"`
	RequestBodyLimit    int64    `json:"request_body_limit,omitempty"`
	DisabledGroups      []string `json:"disabled_groups,omitempty"`
	// IPGroups are per-client rules for IP groups, applied in order.
	IPGroups []IPGroupRule `json:"ip_groups,omitempty"`
}

// CRS defaults (REQUEST-901-INITIALIZATION).
const (
	DefaultBlockingPL        = 1
	DefaultInboundThreshold  = 5
	DefaultOutboundThreshold = 4
	maxThreshold             = 10000
	maxRequestBodyLimit      = 1 << 30
)

// DisableableGroups are the CRS detection rule files that may be switched off
// per site. Initialization (901), blocking evaluation (949/959) and
// correlation (980) are structural and never offered.
var DisableableGroups = []string{
	"911", "913", "920", "921", "922", "930", "931", "932", "933", "934",
	"941", "942", "943", "944", "950", "951", "952", "953", "954", "955", "956",
}

var (
	methodPattern      = regexp.MustCompile(`^[A-Z][A-Z-]{0,31}$`)
	contentTypePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9!#$&^_.+-]{0,63}/[a-z0-9][a-z0-9!#$&^_.+-]{0,63}$`)
)

// DefaultPolicy returns the CRS defaults.
func DefaultPolicy() Policy {
	return Policy{BlockingPL: DefaultBlockingPL, DetectionPL: DefaultBlockingPL,
		InboundThreshold: DefaultInboundThreshold, OutboundThreshold: DefaultOutboundThreshold}
}

// Normalize fills defaults and canonicalizes lists (sorted, deduplicated).
func (p Policy) Normalize() Policy {
	if p.BlockingPL == 0 {
		p.BlockingPL = DefaultBlockingPL
	}
	if p.DetectionPL == 0 {
		p.DetectionPL = p.BlockingPL
	}
	if p.InboundThreshold == 0 {
		p.InboundThreshold = DefaultInboundThreshold
	}
	if p.OutboundThreshold == 0 {
		p.OutboundThreshold = DefaultOutboundThreshold
	}
	p.AllowedMethods = canonicalList(p.AllowedMethods, strings.ToUpper)
	p.AllowedContentTypes = canonicalList(p.AllowedContentTypes, strings.ToLower)
	p.DisabledGroups = canonicalList(p.DisabledGroups, strings.TrimSpace)
	if len(p.IPGroups) == 0 {
		p.IPGroups = nil
	} else {
		groups := make([]IPGroupRule, len(p.IPGroups))
		for i, g := range p.IPGroups {
			g.Group, g.Action, g.Engine, g.Note = strings.TrimSpace(g.Group), strings.TrimSpace(g.Action), strings.TrimSpace(g.Engine), strings.TrimSpace(g.Note)
			groups[i] = g
		}
		p.IPGroups = groups
	}
	return p
}

func canonicalList(values []string, transform func(string) string) []string {
	seen := map[string]bool{}
	var out []string
	for _, v := range values {
		v = transform(strings.TrimSpace(v))
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

// Validate rejects values that CRS does not support or that could inject
// SecLang/Caddyfile syntax. It validates the normalized policy.
func (p Policy) Validate() error {
	p = p.Normalize()
	if p.BlockingPL < 1 || p.BlockingPL > 4 {
		return fmt.Errorf("blocking paranoia level must be 1-4")
	}
	if p.DetectionPL < p.BlockingPL || p.DetectionPL > 4 {
		return fmt.Errorf("detection paranoia level must be between the blocking level and 4")
	}
	if p.InboundThreshold < 1 || p.InboundThreshold > maxThreshold || p.OutboundThreshold < 1 || p.OutboundThreshold > maxThreshold {
		return fmt.Errorf("anomaly thresholds must be 1-%d", maxThreshold)
	}
	if p.RequestBodyLimit < 0 || p.RequestBodyLimit > maxRequestBodyLimit {
		return fmt.Errorf("request body limit must be 0 (baseline) to %d bytes", maxRequestBodyLimit)
	}
	for _, m := range p.AllowedMethods {
		if !methodPattern.MatchString(m) {
			return fmt.Errorf("invalid HTTP method %q", m)
		}
	}
	for _, ct := range p.AllowedContentTypes {
		if !contentTypePattern.MatchString(ct) || strings.Contains(ct, "{$") {
			return fmt.Errorf("invalid content type %q: use type/subtype", ct)
		}
	}
	allowed := map[string]bool{}
	for _, g := range DisableableGroups {
		allowed[g] = true
	}
	for _, g := range p.DisabledGroups {
		if !allowed[g] {
			return fmt.Errorf("rule group %q cannot be disabled", g)
		}
	}
	if len(p.IPGroups) > MaxIPGroupRules {
		return fmt.Errorf("at most %d IP group rules per site", MaxIPGroupRules)
	}
	for i, g := range p.IPGroups {
		if err := validateGroupRule(g, p); err != nil {
			return fmt.Errorf("IP group rule %d: %w", i+1, err)
		}
	}
	return nil
}

// render returns the pre-CRS policy directives and the post-CRS group
// removals. Every value is validated before rendering.
func (p Policy) render() (pre, post []string) {
	p = p.Normalize()
	action := func(id int, setvars ...string) string {
		return fmt.Sprintf(`SecAction "id:%d,phase:1,pass,t:none,nolog,%s"`, id, strings.Join(setvars, ","))
	}
	pre = append(pre,
		action(policyRuleBase, "setvar:tx.blocking_paranoia_level="+strconv.Itoa(p.BlockingPL)),
		action(policyRuleBase+1, "setvar:tx.detection_paranoia_level="+strconv.Itoa(p.DetectionPL)),
		action(policyRuleBase+2,
			"setvar:tx.inbound_anomaly_score_threshold="+strconv.Itoa(p.InboundThreshold),
			"setvar:tx.outbound_anomaly_score_threshold="+strconv.Itoa(p.OutboundThreshold)),
	)
	if p.EarlyBlocking {
		pre = append(pre, action(policyRuleBase+3, "setvar:tx.early_blocking=1"))
	}
	if len(p.AllowedMethods) > 0 {
		pre = append(pre, action(policyRuleBase+4, "setvar:'tx.allowed_methods="+strings.Join(p.AllowedMethods, " ")+"'"))
	}
	if len(p.AllowedContentTypes) > 0 {
		types := make([]string, len(p.AllowedContentTypes))
		for i, ct := range p.AllowedContentTypes {
			types[i] = "|" + ct + "|"
		}
		pre = append(pre, action(policyRuleBase+5, "setvar:'tx.allowed_request_content_type="+strings.Join(types, " ")+"'"))
	}
	if p.RequestBodyLimit > 0 {
		pre = append(pre, "SecRequestBodyLimit "+strconv.FormatInt(p.RequestBodyLimit, 10))
	}
	for _, g := range p.DisabledGroups {
		post = append(post, fmt.Sprintf("SecRuleRemoveById %s000-%s999", g, g))
	}
	if p.Tuning {
		post = append(post, fmt.Sprintf(`SecRule TX:DETECTION_INBOUND_ANOMALY_SCORE|TX:DETECTION_OUTBOUND_ANOMALY_SCORE "@gt 0" "id:%d,phase:5,pass,t:none,nolog,ctl:auditEngine=On"`, tuningRuleID))
	}
	return pre, post
}

// policyLinePrefix marks the machine-readable policy comment of a WAF
// overlay. It lives outside the coraza_waf block (a Caddyfile comment).
const policyLinePrefix = "# ui-policy: "

// encodePolicyLine returns the policy comment line.
func encodePolicyLine(p Policy) (string, error) {
	data, err := json.Marshal(p.Normalize())
	if err != nil {
		return "", err
	}
	return policyLinePrefix + string(data), nil
}

// ParseManaged extracts the mode and policy of a generated WAF overlay.
// Overlays written before the policy model existed return the default
// policy; a corrupt policy line is an error rather than a silent reset.
func ParseManaged(content []byte) (mode string, policy Policy, err error) {
	policy = DefaultPolicy()
	for _, line := range strings.Split(string(content), "\n") {
		trimmed := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(trimmed, policyLinePrefix):
			var p Policy
			if err := json.Unmarshal([]byte(strings.TrimPrefix(trimmed, policyLinePrefix)), &p); err != nil {
				return "", Policy{}, fmt.Errorf("invalid ui-policy line: %w", err)
			}
			if err := p.Validate(); err != nil {
				return "", Policy{}, err
			}
			policy = p.Normalize()
		case mode == "" && strings.HasPrefix(trimmed, "# domain:"):
			if h, herr := domain.ParseHeader(trimmed); herr == nil && h.HasMode {
				mode = string(h.Mode)
			}
		}
	}
	return mode, policy, nil
}
