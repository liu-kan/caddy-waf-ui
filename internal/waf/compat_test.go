package waf_test

import (
	"strings"
	"testing"

	"github.com/developmi/caddy-waf-ui/internal/domain"
	"github.com/developmi/caddy-waf-ui/internal/waf"
)

func TestEmbeddedCRSAndCustomRulesSurviveModeGeneration(t *testing.T) {
	opts := waf.DefaultOptions()
	opts.BeforeFile = "/etc/caddy/waf-custom/before.conf"
	opts.AfterFile = "/etc/caddy/waf-custom/after.conf"
	content, err := waf.GenerateExclusions(&domain.Site{Domain: "api.example.com"}, []waf.Exclusion{
		{Type: waf.ExcludeByID, Value: "941100", Param: "q", Path: "/search"},
		{Type: waf.ExcludeByID, Value: "942100"},
		{Type: waf.ExcludeByID, Value: "932235", Param: "q"},
	})
	if err != nil {
		t.Fatal(err)
	}
	opts.Exclusions = string(content)
	for _, mode := range []domain.WAFMode{domain.ModeOn, domain.ModeOff, domain.ModeDetectionOnly} {
		snippet, err := waf.GenerateSnippetWithOptions(&domain.Site{Domain: "api.example.com", Mode: mode}, "/data/logs/coraza-audit.log", opts)
		if err != nil {
			t.Fatal(err)
		}
		text := string(snippet)
		for _, want := range []string{"load_owasp_crs", "Include @coraza.conf-recommended", "Include @crs-setup.conf.example", "SecResponseBodyAccess Off", "SecAuditLogParts AHKZ", "Include " + opts.BeforeFile, "Include " + opts.AfterFile, "SecRuleEngine " + string(mode)} {
			if !strings.Contains(text, want) {
				t.Errorf("missing %q:\n%s", want, text)
			}
		}
		runtime := strings.Index(text, "ctl:ruleRemoveTargetById=941100;ARGS:q")
		crs := strings.Index(text, "Include @owasp_crs/*.conf")
		removal := strings.Index(text, "SecRuleRemoveById 942100")
		update := strings.Index(text, `SecRuleUpdateTargetById 932235 "!ARGS:q"`)
		if runtime < 0 || runtime > crs || removal < crs || update < crs {
			t.Fatalf("exclusions are in the wrong execution order:\n%s", text)
		}
		if strings.Contains(text, "Include /etc/caddy/coraza.conf") {
			t.Fatal("embedded CRS must not require packaged disk files")
		}
	}
}

func TestRevisionChangesInsideDirectives(t *testing.T) {
	site := &domain.Site{Domain: "example.com", Mode: domain.ModeOn}
	first, err := waf.GenerateSnippetWithOptions(site, "/audit.json", waf.DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	second, err := waf.GenerateSnippetWithOptions(site, "/audit.json", waf.DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	extract := func(snippet []byte) string {
		for _, line := range strings.Split(string(snippet), "\n") {
			if strings.Contains(line, "# waf-config-revision:") {
				return line
			}
		}
		t.Fatal("missing a revision inside the directives block")
		return ""
	}
	if extract(first) == extract(second) {
		t.Fatal("same-mode reloads must invalidate the Coraza pool key")
	}
}

func TestRejectsUnsafeWAFSettings(t *testing.T) {
	for _, mutate := range []func(*waf.Options){
		func(o *waf.Options) { o.BeforeFile = "/etc/caddy/before.conf\nSecRuleEngine Off" },
		func(o *waf.Options) { o.AuditParts = "ABCH\nSecRuleEngine Off" },
		func(o *waf.Options) { o.ResponseBodyAccess = "Invalid" },
		func(o *waf.Options) { o.CRSMode = "unknown" },
		func(o *waf.Options) { o.Exclusions = "SecRuleEngine Off" },
		func(o *waf.Options) {
			o.Exclusions = "# ui-exclusion: {\"type\":\"id\",\"value\":\"1\",\"path\":\"/a\\\" x\"}"
		},
	} {
		opts := waf.DefaultOptions()
		mutate(&opts)
		if _, err := waf.GenerateSnippetWithOptions(&domain.Site{Domain: "example.com", Mode: domain.ModeOn}, "/audit.log", opts); err == nil {
			t.Fatal("unsafe or unsupported settings must be rejected")
		}
	}
}
