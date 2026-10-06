package waf_test

import (
	"strings"
	"testing"

	"github.com/developmi/caddy-waf-ui/internal/domain"
	"github.com/developmi/caddy-waf-ui/internal/waf"
)

func TestPolicyNormalizeAndValidate(t *testing.T) {
	p := waf.Policy{BlockingPL: 2, AllowedMethods: []string{"put", "GET", "GET"}, AllowedContentTypes: []string{"Application/JSON"}}.Normalize()
	if p.DetectionPL != 2 || p.InboundThreshold != 5 || p.OutboundThreshold != 4 {
		t.Fatalf("defaults not applied: %+v", p)
	}
	if strings.Join(p.AllowedMethods, ",") != "GET,PUT" || p.AllowedContentTypes[0] != "application/json" {
		t.Fatalf("lists not canonical: %+v", p)
	}
	invalid := []waf.Policy{
		{BlockingPL: 5},
		{BlockingPL: 3, DetectionPL: 2},
		{InboundThreshold: -1},
		{InboundThreshold: 10001},
		{AllowedMethods: []string{"GET POST"}},
		{AllowedMethods: []string{"GET'\"x"}},
		{AllowedContentTypes: []string{"text/plain;charset=x"}},
		{AllowedContentTypes: []string{"a/{$X}"}},
		{DisabledGroups: []string{"949"}},
		{DisabledGroups: []string{"901"}},
		{RequestBodyLimit: -1},
	}
	for _, p := range invalid {
		if err := p.Validate(); err == nil {
			t.Errorf("policy must be rejected: %+v", p)
		}
	}
	if err := waf.DefaultPolicy().Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestPolicyRendersInExecutionOrder(t *testing.T) {
	policy := waf.Policy{
		BlockingPL: 2, DetectionPL: 3, InboundThreshold: 10, OutboundThreshold: 8,
		EarlyBlocking: true, Tuning: true,
		AllowedMethods:      []string{"GET", "POST", "PUT"},
		AllowedContentTypes: []string{"application/json", "text/plain"},
		RequestBodyLimit:    1048576,
		DisabledGroups:      []string{"933"},
	}
	g, err := waf.Generate("api.example.com", waf.Config{Mode: domain.ModeOn, Policy: policy}, "/audit.log", waf.DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	text := string(g.Content)
	order := []string{
		`# ui-policy: {"blocking_pl":2,"detection_pl":3,"inbound_threshold":10,"outbound_threshold":8`,
		"coraza_waf {",
		"# waf-config-revision: " + g.Revision,
		`SecComponentSignature "caddy-waf-ui;v=1;site=api.example.com;rev=` + g.Revision + `;mode=On;bpl=2;dpl=3;in=10;out=8;tune=1;early=1"`,
		"Include @crs-setup.conf.example",
		`SecAction "id:9001000,phase:1,pass,t:none,nolog,setvar:tx.blocking_paranoia_level=2"`,
		`SecAction "id:9001001,phase:1,pass,t:none,nolog,setvar:tx.detection_paranoia_level=3"`,
		`setvar:tx.inbound_anomaly_score_threshold=10,setvar:tx.outbound_anomaly_score_threshold=8`,
		`setvar:tx.early_blocking=1`,
		`setvar:'tx.allowed_methods=GET POST PUT'`,
		`setvar:'tx.allowed_request_content_type=|application/json| |text/plain|'`,
		"SecRequestBodyLimit 1048576",
		"Include @owasp_crs/*.conf",
		"SecRuleRemoveById 933000-933999",
		`"id:9001100,phase:5,pass,t:none,nolog,ctl:auditEngine=On"`,
		"SecRuleEngine On",
	}
	prev := -1
	for _, fragment := range order {
		idx := strings.Index(text, fragment)
		if idx < 0 {
			t.Fatalf("missing %q in:\n%s", fragment, text)
		}
		if idx < prev {
			t.Fatalf("%q out of order in:\n%s", fragment, text)
		}
		prev = idx
	}
	mode, parsed, err := waf.ParseManaged(g.Content)
	if err != nil || mode != "On" {
		t.Fatalf("ParseManaged: %q %v", mode, err)
	}
	if parsed.BlockingPL != 2 || !parsed.Tuning || parsed.RequestBodyLimit != 1048576 || len(parsed.DisabledGroups) != 1 {
		t.Fatalf("policy did not round-trip: %+v", parsed)
	}
	if waf.Revision(g.Content) != g.Revision {
		t.Fatal("revision extraction failed")
	}
}

func TestParseManagedLegacyAndCorrupt(t *testing.T) {
	legacy := []byte("# Caddy WAF UI managed - do not edit manually\n# domain: a.com | mode: DetectionOnly | updated: 2026-01-01T00:00:00Z\ncoraza_waf {\n}\n")
	mode, p, err := waf.ParseManaged(legacy)
	if err != nil || mode != "DetectionOnly" || p.BlockingPL != 1 || p.InboundThreshold != 5 {
		t.Fatalf("legacy overlay: %q %+v %v", mode, p, err)
	}
	if _, _, err := waf.ParseManaged([]byte("# ui-policy: {not json")); err == nil {
		t.Fatal("corrupt policy must not silently reset to defaults")
	}
	if _, _, err := waf.ParseManaged([]byte(`# ui-policy: {"blocking_pl":9}`)); err == nil {
		t.Fatal("invalid stored policy must be rejected")
	}
}

func TestDefaultPolicyOmitsOptionalDirectives(t *testing.T) {
	g, err := waf.Generate("a.com", waf.Config{Mode: domain.ModeDetectionOnly, Policy: waf.DefaultPolicy()}, "/audit.log", waf.DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	text := string(g.Content)
	for _, absent := range []string{"early_blocking", "allowed_methods", "SecRequestBodyLimit", "ctl:auditEngine", "SecRuleRemoveById"} {
		if strings.Contains(text, absent) {
			t.Errorf("default policy must not render %q", absent)
		}
	}
	if _, err := waf.Generate("bad site", waf.Config{Mode: domain.ModeOn}, "/audit.log", waf.DefaultOptions()); err == nil {
		t.Fatal("invalid site names must be rejected before reaching the signature")
	}
}

func TestSignatureRoundTrip(t *testing.T) {
	s := waf.Signature{Site: "a.example.com", Revision: "abc123", Mode: "DetectionOnly", BlockingPL: 1, DetectionPL: 2, Inbound: 5, Outbound: 4, Tuning: true}
	parsed, ok := waf.ParseSignature(s.String())
	if !ok || parsed != s {
		t.Fatalf("round trip: %+v", parsed)
	}
	if strings.ContainsAny(s.String(), " \t\"") {
		t.Fatal("the signature must be a single token")
	}
	found, ok := waf.FindSignature([]string{"OWASP_CRS/4.25.0"}, "OWASP_CRS/4.25.0 "+s.String())
	if !ok || found.Site != "a.example.com" {
		t.Fatal("signature not found in actionset")
	}
	if _, ok := waf.FindSignature([]string{"OWASP_CRS/4.25.0"}); ok {
		t.Fatal("unexpected signature")
	}
}
