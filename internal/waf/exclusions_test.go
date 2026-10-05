package waf_test

import (
	"strings"
	"testing"

	"github.com/developmi/caddy-waf-ui/internal/domain"
	"github.com/developmi/caddy-waf-ui/internal/waf"
)

func TestGenerateExclusions(t *testing.T) {
	site := &domain.Site{
		Domain: "api.developmi.com",
		Mode:   domain.ModeDetectionOnly,
	}

	testCases := []struct {
		name       string
		exclusions []waf.Exclusion
		wantErr    bool
		fragments  []string
		notIn      []string
	}{
		{
			name: "valid id",
			exclusions: []waf.Exclusion{
				{Type: waf.ExcludeByID, Value: "941100"},
			},
			wantErr: false,
			fragments: []string{
				"SecRuleRemoveById 941100",
			},
		},
		{
			name: "URI-level exclusion without parameter",
			exclusions: []waf.Exclusion{
				{Type: waf.ExcludeByID, Value: "941100", Param: ""},
			},
			wantErr: false,
			fragments: []string{
				"SecRuleRemoveById 941100",
			},
			notIn: []string{"ARGS:"},
		},
		{
			name: "parameter-only exclusion removes just that target after CRS loads",
			exclusions: []waf.Exclusion{
				{Type: waf.ExcludeByID, Value: "941100", Param: "q"},
			},
			wantErr: false,
			fragments: []string{
				`SecRuleUpdateTargetById 941100 "!ARGS:q"`,
				`# ui-exclusion: {"type":"id","value":"941100","param":"q"}`,
			},
			notIn: []string{"SecRuleRemoveById 941100\n", "ctl:ruleRemoveById=941100", "@unconditionalMatch"},
		},
		{
			name: "path-scoped exclusions get consecutive runtime ids 9000001 and 9000002",
			exclusions: []waf.Exclusion{
				{Type: waf.ExcludeByID, Value: "941100", Param: "q", Path: "/search"},
				{Type: waf.ExcludeByID, Value: "942100", Path: "/api/import", PathMatch: waf.PathExact},
			},
			wantErr: false,
			fragments: []string{
				`SecRule REQUEST_FILENAME "@beginsWith /search" "id:9000001,phase:1,pass,t:none,nolog,ctl:ruleRemoveTargetById=941100;ARGS:q"`,
				`SecRule REQUEST_FILENAME "@streq /api/import" "id:9000002,phase:1,pass,t:none,nolog,ctl:ruleRemoveById=942100"`,
			},
		},
		{
			name: "duplicates deduplicated: same rule and scope does not consume a new id",
			exclusions: []waf.Exclusion{
				{Type: waf.ExcludeByID, Value: "941100", Param: "q", Path: "/a"},
				{Type: waf.ExcludeByID, Value: "941100", Param: "q", Path: "/a", PathMatch: waf.PathPrefix},
			},
			wantErr: false,
			fragments: []string{
				"id:9000001", "ctl:ruleRemoveTargetById=941100;ARGS:q",
			},
			notIn: []string{"9000002"},
		},
		{
			name: "tag with parameter generates a tag target update",
			exclusions: []waf.Exclusion{
				{Type: waf.ExcludeByTag, Value: "attack-xss", Param: "q"},
			},
			wantErr: false,
			fragments: []string{
				`SecRuleUpdateTargetByTag "attack-xss" "!ARGS:q"`,
			},
		},
		{
			name: "JSON key and key pattern parameters",
			exclusions: []waf.Exclusion{
				{Type: waf.ExcludeByID, Value: "932235", Param: "json.messages.0.content", Path: "/api/chat"},
				{Type: waf.ExcludeByID, Value: "942100", Param: `/^json\.messages\.\d+\.content$/`},
			},
			wantErr: false,
			fragments: []string{
				"ctl:ruleRemoveTargetById=932235;ARGS:json.messages.0.content",
				`SecRuleUpdateTargetById 942100 "!ARGS:/^json\.messages\.\d+\.content$/"`,
			},
		},
		{
			name: "pattern with a pipe rejected",
			exclusions: []waf.Exclusion{
				{Type: waf.ExcludeByID, Value: "941100", Param: "/a|b/"},
			},
			wantErr: true,
		},
		{
			name: "path with quote rejected",
			exclusions: []waf.Exclusion{
				{Type: waf.ExcludeByID, Value: "941100", Path: `/a" "id:1`},
			},
			wantErr: true,
		},
		{
			name: "path must be absolute",
			exclusions: []waf.Exclusion{
				{Type: waf.ExcludeByID, Value: "941100", Path: "api"},
			},
			wantErr: true,
		},
		{
			name: "note with backtick rejected",
			exclusions: []waf.Exclusion{
				{Type: waf.ExcludeByID, Value: "941100", Note: "x`y"},
			},
			wantErr: true,
		},
		{
			name: "parameter with only spaces rejected",
			exclusions: []waf.Exclusion{
				{Type: waf.ExcludeByID, Value: "941100", Param: " "},
			},
			wantErr: true,
		},
		{
			name: "parameter with newline rejected",
			exclusions: []waf.Exclusion{
				{Type: waf.ExcludeByID, Value: "941100", Param: "q\nSecRuleEngine Off"},
			},
			wantErr: true,
		},
		{
			name: "valid tag",
			exclusions: []waf.Exclusion{
				{Type: waf.ExcludeByTag, Value: "attack-xss"},
			},
			wantErr: false,
			fragments: []string{
				`SecRuleRemoveByTag "attack-xss"`,
			},
		},
		{
			name: "id with newline",
			exclusions: []waf.Exclusion{
				{Type: waf.ExcludeByID, Value: "941100\nSecRuleEngine Off"},
			},
			wantErr: true,
		},
		{
			name: "tag with quotes",
			exclusions: []waf.Exclusion{
				{Type: waf.ExcludeByTag, Value: `attack-xss" }`},
			},
			wantErr: true,
		},
		{
			name: "unknown type",
			exclusions: []waf.Exclusion{
				{Type: waf.ExclusionType("uri"), Value: "/api/v1"},
			},
			wantErr: true,
		},
		{
			name: "value with hash",
			exclusions: []waf.Exclusion{
				{Type: waf.ExcludeByID, Value: "941100#comment"},
			},
			wantErr: true,
		},
		{
			name: "id with space",
			exclusions: []waf.Exclusion{
				{Type: waf.ExcludeByID, Value: "941100 942100"},
			},
			wantErr: true,
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			resultBytes, err := waf.GenerateExclusions(site, tt.exclusions)

			if tt.wantErr {
				if err == nil {
					t.Fatalf("GenerateExclusions should fail with %+v, but it returned no error", tt.exclusions)
				}
				return
			}

			if err != nil {
				t.Fatalf("GenerateExclusions failed unexpectedly: %v", err)
			}

			result := string(resultBytes)

			for _, fragment := range tt.fragments {
				if !strings.Contains(result, fragment) {
					t.Errorf("the generated block does not contain the expected fragment: %q\nBlock:\n%s", fragment, result)
				}
			}

			for _, fragment := range tt.notIn {
				if strings.Contains(result, fragment) {
					t.Errorf("the generated block must NOT contain the fragment: %q\nBlock:\n%s", fragment, result)
				}
			}
		})
	}
}

func TestValidateExclusions(t *testing.T) {
	valid := []waf.Exclusion{
		{Type: waf.ExcludeByID, Value: "941100"},
		{Type: waf.ExcludeByTag, Value: "attack-sqli"},
	}
	if err := waf.ValidateExclusions(valid); err != nil {
		t.Fatalf("expected valid exclusions, got error: %v", err)
	}

	invalid := []waf.Exclusion{
		{Type: "invalid-type", Value: "123"},
	}
	if err := waf.ValidateExclusions(invalid); err == nil {
		t.Fatal("expected error for invalid exclusion type, got nil")
	}
	for _, id := range []string{"949110", "959100", "901500", "9000001"} {
		if err := waf.ValidateExclusions([]waf.Exclusion{{Type: waf.ExcludeByID, Value: id}}); err == nil {
			t.Errorf("rule %s must not be offered as an exclusion", id)
		}
	}
	if err := waf.ValidateExclusions([]waf.Exclusion{{Type: waf.ExcludeByID, Value: "1000001"}}); err != nil {
		t.Errorf("unknown (operator custom) rule ids remain excludable: %v", err)
	}
}

func TestParseExclusionsRoundTripAndLegacyMigration(t *testing.T) {
	site := &domain.Site{Domain: "example.com"}
	want := []waf.Exclusion{
		{Type: waf.ExcludeByID, Value: "942100", Param: "json.text", Path: "/api/ask", PathMatch: waf.PathPrefix, Note: "chat messages \"quoted\""},
		{Type: waf.ExcludeByTag, Value: "attack-xss"},
	}
	content, err := waf.GenerateExclusions(site, want)
	if err != nil {
		t.Fatal(err)
	}
	got, err := waf.ParseExclusions(content)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("round trip: got %+v", got)
	}

	legacy := "# Caddy WAF UI managed - do not edit manually\n# domain: example.com | updated: 2026-01-01T00:00:00Z\n" +
		"SecRuleRemoveById 941100\n" +
		"SecRuleRemoveByTag \"attack-sqli\"\n" +
		"SecRule ARGS:q \"@unconditionalMatch\" \"id:9000001,phase:2,pass,nolog,ctl:ruleRemoveById=942100\"\n"
	got, err = waf.ParseExclusions([]byte(legacy))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || got[2] != (waf.Exclusion{Type: waf.ExcludeByID, Value: "942100", Param: "q"}) {
		t.Fatalf("legacy parse: %+v", got)
	}
	if _, err := waf.ParseExclusions([]byte("SecRuleEngine Off\n")); err == nil {
		t.Fatal("unknown directives must be rejected")
	}
	stored := []byte(`# ui-exclusion: {"type":"id","value":"949110"}` + "\n")
	if _, err := waf.ParseExclusions(stored); err != nil {
		t.Fatalf("stored entries are only syntax-checked so the site stays manageable: %v", err)
	}
}

func TestExclusionDescribe(t *testing.T) {
	cases := map[string]waf.Exclusion{
		"remove rule 942100 for the whole site":                 {Type: waf.ExcludeByID, Value: "942100"},
		"skip ARGS:q in rule 942100 for the whole site":         {Type: waf.ExcludeByID, Value: "942100", Param: "q"},
		"remove rules tagged attack-xss for paths under /admin": {Type: waf.ExcludeByTag, Value: "attack-xss", Path: "/admin"},
		"skip ARGS:text in rule 941100 for path /api/ask":       {Type: waf.ExcludeByID, Value: "941100", Param: "text", Path: "/api/ask", PathMatch: waf.PathExact},
	}
	for want, ex := range cases {
		if got := ex.Describe(); got != want {
			t.Errorf("Describe(%+v) = %q, want %q", ex, got, want)
		}
	}
}
