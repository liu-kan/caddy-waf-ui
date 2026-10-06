package waf

import (
	"strings"
	"testing"

	"github.com/developmi/caddy-waf-ui/internal/domain"
)

var groupFiles = map[string]string{
	"scanners": "/etc/caddy/ui-managed/ipgroups/scanners.aaaaaaaaaaaa.txt",
	"cn":       "/etc/caddy/ui-managed/ipgroups/cn.bbbbbbbbbbbb.txt",
	"office":   "/etc/caddy/ui-managed/ipgroups/office.cccccccccccc.txt",
}

func TestIPGroupRulesRenderBeforeCRS(t *testing.T) {
	p := DefaultPolicy()
	p.IPGroups = []IPGroupRule{
		{Group: "scanners", Action: GroupBlock},
		{Group: "cn", Negate: true, Action: GroupTrial},
		{Group: "office", Action: GroupEngine, Engine: "DetectionOnly"},
		{Group: "cn", Negate: true, Action: GroupTune, BlockingPL: 3, InboundThreshold: 10},
	}
	opts := DefaultOptions()
	opts.IPGroupFiles = groupFiles
	g, err := Generate("example.com", Config{Mode: domain.ModeOn, Policy: p}, "/data/logs/coraza-audit.log", opts)
	if err != nil {
		t.Fatal(err)
	}
	content := string(g.Content)
	want := []string{
		`SecRule REMOTE_ADDR "@ipMatchFromFile ` + groupFiles["scanners"] + `" "id:9002000,phase:1,deny,status:403,t:none,nolog,auditlog,tag:'caddy-waf-ui/ipgroup',msg:'IP group policy: inside scanners blocked'"`,
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

func TestIPGroupRulesNeedAnActiveList(t *testing.T) {
	p := DefaultPolicy()
	p.IPGroups = []IPGroupRule{{Group: "missing", Action: GroupBlock}}
	opts := DefaultOptions()
	opts.IPGroupFiles = groupFiles
	if _, err := Generate("example.com", Config{Mode: domain.ModeOn, Policy: p}, "/data/logs/coraza-audit.log", opts); err == nil || !strings.Contains(err.Error(), "missing") {
		t.Fatalf("a rule for a group without an active list must fail: %v", err)
	}
}

func TestIPGroupRuleValidation(t *testing.T) {
	bad := []IPGroupRule{
		{Group: "Bad Name", Action: GroupBlock},
		{Group: "cn", Action: "allow"},
		{Group: "cn", Action: GroupEngine, Engine: "Maybe"},
		{Group: "cn", Action: GroupEngine},
		{Group: "cn", Action: GroupTune},
		{Group: "cn", Action: GroupTune, BlockingPL: 5},
		{Group: "cn", Action: GroupTune, InboundThreshold: 20000},
		{Group: "cn", Action: GroupTune, BlockingPL: 3, DetectionPL: 2},
		{Group: "cn", Action: GroupBlock, InboundThreshold: 10},
		{Group: "cn", Action: GroupBlock, Engine: "On"},
		{Group: "cn", Action: GroupBlock, Note: "line\nbreak"},
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
		p.IPGroups = append(p.IPGroups, IPGroupRule{Group: "cn", Action: GroupBlock})
	}
	if err := p.Validate(); err == nil {
		t.Fatal("the number of group rules must be bounded")
	}
	p.IPGroups = []IPGroupRule{{Group: "cn", Action: GroupTune, DetectionPL: 2}}
	if err := p.Validate(); err != nil {
		t.Fatalf("collecting a higher level for one group is valid: %v", err)
	}
}
