package iprules_test

import (
	"strings"
	"testing"

	"github.com/developmi/caddy-waf-ui/internal/domain"
	"github.com/developmi/caddy-waf-ui/internal/iprules"
)

func TestGenerateSnippet(t *testing.T) {
	site := &domain.Site{
		Domain: "api.developmi.com",
		Mode:   domain.ModeDetectionOnly,
	}

	testCases := []struct {
		name      string
		rules     iprules.IPRules
		wantErr   bool
		fragments []string
	}{
		{
			name: "valid CIDR",
			rules: iprules.IPRules{
				Denylist: []string{"10.0.0.0/8"},
			},
			wantErr: false,
			fragments: []string{
				"client_ip 10.0.0.0/8",
			},
		},
		{
			name: "bare IP is normalized to /32",
			rules: iprules.IPRules{
				Denylist: []string{"1.2.3.4"},
			},
			wantErr: false,
			fragments: []string{
				"client_ip 1.2.3.4/32",
			},
		},
		{
			name: "valid IPv6",
			rules: iprules.IPRules{
				Denylist: []string{"::1/128"},
			},
			wantErr: false,
			fragments: []string{
				"client_ip ::1/128",
			},
		},
		{
			name: "string with newline",
			rules: iprules.IPRules{
				Denylist: []string{"1.2.3.4}\nabort @foo"},
			},
			wantErr: true,
		},
		{
			name: "string with closing brace",
			rules: iprules.IPRules{
				Denylist: []string{"1.2.3.4}"},
			},
			wantErr: true,
		},
		{
			name: "garbage",
			rules: iprules.IPRules{
				Denylist: []string{"not-an-ip"},
			},
			wantErr: true,
		},
		{
			name: "allowlist is normalized too",
			rules: iprules.IPRules{
				Allowlist: []string{"203.0.113.5"},
			},
			wantErr: false,
			fragments: []string{
				"client_ip 203.0.113.5/32",
			},
		},
		{
			name: "invalid entry in allowlist",
			rules: iprules.IPRules{
				Allowlist: []string{"bad-ip"},
			},
			wantErr: true,
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			resultBytes, err := iprules.GenerateSnippet(site, tt.rules)

			if tt.wantErr {
				if err == nil {
					t.Fatalf("GenerateSnippet should fail with %+v, but returned no error", tt.rules)
				}
				return
			}

			if err != nil {
				t.Fatalf("GenerateSnippet failed unexpectedly: %v", err)
			}

			result := string(resultBytes)

			for _, fragment := range tt.fragments {
				if !strings.Contains(result, fragment) {
					t.Errorf("the generated block does not contain the expected fragment: %q\nBlock:\n%s", fragment, result)
				}
			}
		})
	}
}

func TestValidateIPRules(t *testing.T) {
	// Valid rules
	valid := iprules.IPRules{
		Denylist:  []string{"192.168.1.1", "10.0.0.0/16"},
		Allowlist: []string{"203.0.113.1/32"},
	}
	if err := iprules.ValidateIPRules(valid); err != nil {
		t.Errorf("ValidateIPRules failed for valid rules: %v", err)
	}

	// Invalid denylist
	invalidDeny := iprules.IPRules{
		Denylist: []string{"invalid-ip"},
	}
	if err := iprules.ValidateIPRules(invalidDeny); err == nil {
		t.Error("ValidateIPRules expected error for invalid denylist, got nil")
	}

	// Invalid allowlist
	invalidAllow := iprules.IPRules{
		Allowlist: []string{"999.999.999.999"},
	}
	if err := iprules.ValidateIPRules(invalidAllow); err == nil {
		t.Error("ValidateIPRules expected error for invalid allowlist, got nil")
	}
}

func TestGenerateSnippetBothAllowAndDeny(t *testing.T) {
	site := &domain.Site{
		Domain: "secure.example.com",
		Mode:   domain.ModeOn,
	}
	rules := iprules.IPRules{
		Denylist:  []string{"198.51.100.1"},
		Allowlist: []string{"192.0.2.1"},
	}
	snippet, err := iprules.GenerateSnippet(site, rules)
	if err != nil {
		t.Fatalf("GenerateSnippet failed: %v", err)
	}
	content := string(snippet)
	if !strings.Contains(content, "client_ip 198.51.100.1/32") {
		t.Errorf("missing denylist rule in snippet: %s", content)
	}
	if !strings.Contains(content, "client_ip 192.0.2.1/32") {
		t.Errorf("missing allowlist rule in snippet: %s", content)
	}
}
