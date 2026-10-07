package waf

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/developmi/caddy-waf-ui/internal/domain"
)

var groupFiles = map[string]string{
	"scanners": "/etc/caddy/ui-managed/ipgroups/scanners.aaaaaaaaaaaa.txt",
	"cn":       "/etc/caddy/ui-managed/ipgroups/cn.bbbbbbbbbbbb.txt",
	"office":   "/etc/caddy/ui-managed/ipgroups/office.cccccccccccc.txt",
	"cn+jp+us": "/etc/caddy/ui-managed/ipgroups/_union.dddddddddddd.txt",
}

// groupList resolves rules from groupFiles; several groups use the
// "a+b" key of their merged list.
func groupList(groups []string) (string, error) {
	if path, ok := groupFiles[strings.Join(groups, "+")]; ok {
		return path, nil
	}
	return "", errors.New("IP group " + strings.Join(groups, "+") + " has no active list")
}

func TestIPGroupRulesRenderBeforeCRS(t *testing.T) {
	p := DefaultPolicy()
	p.IPGroups = []IPGroupRule{
		{Groups: []string{"scanners"}, Action: GroupBlock},
		{Groups: []string{"cn"}, Negate: true, Action: GroupTrial},
		{Groups: []string{"office"}, Action: GroupEngine, Engine: "DetectionOnly"},
		{Groups: []string{"cn"}, Negate: true, Action: GroupTune, BlockingPL: 3, InboundThreshold: 10},
	}
	opts := DefaultOptions()
	opts.IPGroupList = groupList
	g, err := Generate("example.com", Config{Mode: domain.ModeOn, Policy: p}, "/data/logs/coraza-audit.log", opts)
	if err != nil {
		t.Fatal(err)
	}
	content := string(g.Content)
	want := []string{
		`SecRule REMOTE_ADDR "@ipMatchFromFile ` + groupFiles["scanners"] + `" "id:9002000,phase:1,deny,status:403,t:none,nolog,auditlog,setvar:tx.blocking_inbound_anomaly_score=0,setvar:tx.blocking_outbound_anomaly_score=0,setvar:tx.detection_inbound_anomaly_score=0,setvar:tx.detection_outbound_anomaly_score=0,tag:'caddy-waf-ui/ipgroup',msg:'IP group policy: inside scanners blocked'"`,
		`SecRule REMOTE_ADDR "!@ipMatchFromFile ` + groupFiles["cn"] + `" "id:9002001,phase:1,pass,t:none,nolog,auditlog,ctl:auditEngine=On,tag:'caddy-waf-ui/ipgroup',msg:'IP group policy (trial): outside cn would be blocked'"`,
		`SecRule REMOTE_ADDR "@ipMatchFromFile ` + groupFiles["office"] + `" "id:9002502,phase:1,pass,t:none,nolog,auditlog,ctl:ruleEngine=DetectionOnly,tag:'caddy-waf-ui/ipgroup',msg:'IP group policy: inside office engine DetectionOnly'"`,
		// Raising the blocking level also raises the detection level so CRS
		// rule 901500 does not reject the request.
		`SecRule REMOTE_ADDR "!@ipMatchFromFile ` + groupFiles["cn"] + `" "id:9002503,phase:1,pass,t:none,nolog,auditlog,setvar:tx.blocking_paranoia_level=3,setvar:tx.detection_paranoia_level=3,setvar:tx.inbound_anomaly_score_threshold=10,tag:'caddy-waf-ui/ipgroup',msg:'IP group policy: outside cn tune bpl=3 dpl=3 in=10 out=4'"`,
	}
	last := strings.Index(content, "# ui-policy-end")
	for _, line := range want {
		i := strings.Index(content, line)
		if i < 0 {
			t.Fatalf("missing directive:\n%s\nin:\n%s", line, content)
		}
		if i < last {
			t.Fatalf("group rules must follow the site policy (and run in order): %s", line)
		}
		last = i
	}
	if crs := strings.Index(content, "Include @owasp_crs/*.conf"); crs < last {
		t.Fatal("group rules must run before the CRS rules")
	}
	_, parsed, err := ParseManaged(g.Content)
	if err != nil || len(parsed.IPGroups) != 4 || parsed.IPGroups[1].Negate != true {
		t.Fatalf("group rules must round-trip through the policy line: %+v %v", parsed.IPGroups, err)
	}
}

func TestIPGroupBanAllowlistOfSeveralGroups(t *testing.T) {
	p := DefaultPolicy()
	p.IPGroups = []IPGroupRule{{Groups: []string{" us", "jp", "cn", "jp"}, Negate: true, Action: GroupBan}}
	p = p.Normalize()
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	rule := p.IPGroups[0]
	if strings.Join(rule.Groups, ",") != "cn,jp,us" || rule.Scope() != "outside cn, jp and us" {
		t.Fatalf("groups must be trimmed, sorted and unique: %q %q", rule.Groups, rule.Scope())
	}
	opts := DefaultOptions()
	opts.IPGroupList = groupList
	on, err := Generate("example.com", Config{Mode: domain.ModeOn, Policy: p}, "/data/logs/coraza-audit.log", opts)
	if err != nil {
		t.Fatal(err)
	}
	// One rule over the merged list: deny clients outside all groups
	// without an audit record.
	ban := `SecRule REMOTE_ADDR "!@ipMatchFromFile ` + groupFiles["cn+jp+us"] + `" "id:9002000,phase:1,deny,status:403,t:none,nolog,ctl:auditEngine=Off,setvar:tx.blocking_inbound_anomaly_score=0,setvar:tx.blocking_outbound_anomaly_score=0,setvar:tx.detection_inbound_anomaly_score=0,setvar:tx.detection_outbound_anomaly_score=0,tag:'caddy-waf-ui/ipgroup',msg:'IP group policy: outside cn+jp+us banned'"`
	if !strings.Contains(string(on.Content), ban) {
		t.Fatalf("missing ban rule:\n%s\nin:\n%s", ban, on.Content)
	}
	// DetectionOnly records the requests that the ban would deny.
	detect, err := Generate("example.com", Config{Mode: domain.ModeDetectionOnly, Policy: p}, "/data/logs/coraza-audit.log", opts)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(detect.Content), "id:9002000,phase:1,deny,status:403,t:none,nolog,auditlog,setvar:tx.blocking_inbound_anomaly_score=0,setvar:tx.blocking_outbound_anomaly_score=0,setvar:tx.detection_inbound_anomaly_score=0,setvar:tx.detection_outbound_anomaly_score=0,tag:'caddy-waf-ui/ipgroup',msg:'IP group policy: outside cn+jp+us banned'") ||
		strings.Contains(string(detect.Content), "ctl:auditEngine=Off") {
		t.Fatalf("a ban must stay visible in DetectionOnly:\n%s", detect.Content)
	}
	if got := (IPGroupRule{Groups: []string{"cn", "jp"}, Action: GroupBan}).Describe(); got != "ban clients inside cn or jp (not recorded)" {
		t.Fatalf("describe: %q", got)
	}
}

func TestIPGroupRuleReadsTheSingleGroupField(t *testing.T) {
	var rules []IPGroupRule
	if err := json.Unmarshal([]byte(`[{"group":"cn","negate":true,"action":"block"},{"groups":["jp","us"],"action":"ban"}]`), &rules); err != nil {
		t.Fatal(err)
	}
	if strings.Join(rules[0].Groups, ",") != "cn" || !rules[0].Negate || rules[0].Action != GroupBlock || strings.Join(rules[1].Groups, ",") != "jp,us" {
		t.Fatalf("rules: %+v", rules)
	}
	out, err := json.Marshal(rules[0])
	if err != nil || string(out) != `{"groups":["cn"],"negate":true,"action":"block"}` {
		t.Fatalf("rules are saved with groups only: %s %v", out, err)
	}
}

func TestIPGroupRulesNeedAnActiveList(t *testing.T) {
	p := DefaultPolicy()
	p.IPGroups = []IPGroupRule{{Groups: []string{"missing"}, Action: GroupBlock}}
	opts := DefaultOptions()
	opts.IPGroupList = groupList
	if _, err := Generate("example.com", Config{Mode: domain.ModeOn, Policy: p}, "/data/logs/coraza-audit.log", opts); err == nil || !strings.Contains(err.Error(), "missing") {
		t.Fatalf("a rule for a group without an active list must fail: %v", err)
	}
	opts.IPGroupList = nil
	if _, err := Generate("example.com", Config{Mode: domain.ModeOn, Policy: p}, "/data/logs/coraza-audit.log", opts); err == nil {
		t.Fatal("group rules need a list resolver")
	}
}

func TestIPGroupRuleValidation(t *testing.T) {
	many := make([]string, MaxRuleGroups+1)
	for i := range many {
		many[i] = "g" + string(rune('a'+i))
	}
	bad := []IPGroupRule{
		{Groups: []string{"Bad Name"}, Action: GroupBlock},
		{Groups: nil, Action: GroupBlock},
		{Groups: many, Action: GroupBlock},
		{Groups: []string{"cn"}, Action: "allow"},
		{Groups: []string{"cn"}, Action: GroupEngine, Engine: "Maybe"},
		{Groups: []string{"cn"}, Action: GroupEngine},
		{Groups: []string{"cn"}, Action: GroupTune},
		{Groups: []string{"cn"}, Action: GroupTune, BlockingPL: 5},
		{Groups: []string{"cn"}, Action: GroupTune, InboundThreshold: 20000},
		{Groups: []string{"cn"}, Action: GroupTune, BlockingPL: 3, DetectionPL: 2},
		{Groups: []string{"cn"}, Action: GroupBlock, InboundThreshold: 10},
		{Groups: []string{"cn"}, Action: GroupBan, Engine: "On"},
		{Groups: []string{"cn"}, Action: GroupBlock, Note: "line\nbreak"},
	}
	for _, r := range bad {
		p := DefaultPolicy()
		p.IPGroups = []IPGroupRule{r}
		if err := p.Validate(); err == nil {
			t.Errorf("accepted %+v", r)
		}
	}
	p := DefaultPolicy()
	for i := 0; i <= MaxIPGroupRules; i++ {
		p.IPGroups = append(p.IPGroups, IPGroupRule{Groups: []string{"cn"}, Action: GroupBlock})
	}
	if err := p.Validate(); err == nil {
		t.Fatal("the number of group rules must be bounded")
	}
	p.IPGroups = []IPGroupRule{{Groups: []string{"cn"}, Action: GroupTune, DetectionPL: 2}}
	if err := p.Validate(); err != nil {
		t.Fatalf("collecting a higher level for one group is valid: %v", err)
	}
}
