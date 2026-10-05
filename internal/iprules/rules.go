package iprules

import (
	"bytes"
	"fmt"
	"net"
	"strings"
	"text/template"
	"time"

	"github.com/developmi/caddy-waf-ui/internal/domain"
)

// IPRules holds the lists of IP addresses or CIDR blocks.
type IPRules struct {
	Allowlist []string `json:"allowlist"`
	Denylist  []string `json:"denylist"`
}

// Template based on Caddy's native configuration examples.
const ipRulesTemplate = `# Caddy WAF UI managed - do not edit manually
{{ .Header }}

{{ if .DenyStr -}}
# Denylist
@ip_deny_{{ .Slug }} {
    client_ip {{ .DenyStr }}
}
abort @ip_deny_{{ .Slug }}
{{ end }}
{{- if .AllowStr }}
# Allowlist (if set, all other IPs are denied)
@ip_allow_{{ .Slug }} {
    not client_ip {{ .AllowStr }}
}
abort @ip_allow_{{ .Slug }}
{{ end }}
{{- if and (not .DenyStr) (not .AllowStr) -}}
# No IP rules configured for this domain.
{{ end }}
`

type ipRulesData struct {
	Slug     string
	Header   string
	DenyStr  string
	AllowStr string
}

// ipRulesTmpl is parsed ONCE at package level (finding J5-8), same pattern
// as ui/embed.go: the constant template never fails to parse.
var ipRulesTmpl = template.Must(template.New("iprules").Parse(ipRulesTemplate))

// normalizeIPEntry validates an IP or CIDR entry and normalizes it to CIDR
// notation: a bare IP becomes /32 (IPv4) or /128 (IPv6). It returns an error
// on any unparseable value, preventing a malicious entry from escaping
// Caddy's matcher block (e.g.: "1.2.3.4}\nabort @foo").
func normalizeIPEntry(entry string) (string, error) {
	if _, ipnet, err := net.ParseCIDR(entry); err == nil {
		return ipnet.String(), nil
	}

	if ip := net.ParseIP(entry); ip != nil {
		if ip.To4() != nil {
			return ip.String() + "/32", nil
		}
		return ip.String() + "/128", nil
	}

	return "", fmt.Errorf("invalid IP entry %q: expected an IP or a CIDR block", entry)
}

// normalizeIPEntries validates and normalizes a full list of entries.
func normalizeIPEntries(entries []string) ([]string, error) {
	normalized := make([]string, 0, len(entries))
	for _, entry := range entries {
		norm, err := normalizeIPEntry(entry)
		if err != nil {
			return nil, err
		}
		normalized = append(normalized, norm)
	}
	return normalized, nil
}

// ValidateIPRules validates both lists (allow and deny) without generating
// configuration. The service chain (D2) invokes it BEFORE the backup to fail
// fast and not leave snapshots of invalid entries.
func ValidateIPRules(rules IPRules) error {
	if _, err := normalizeIPEntries(rules.Denylist); err != nil {
		return err
	}
	_, err := normalizeIPEntries(rules.Allowlist)
	return err
}

// GenerateSnippet creates the Caddy matcher configuration block for IP
// blocking. It is a pure function and does not interact with the disk[cite: 1].
func GenerateSnippet(site *domain.Site, rules IPRules) ([]byte, error) {
	denyList, err := normalizeIPEntries(rules.Denylist)
	if err != nil {
		return nil, err
	}

	allowList, err := normalizeIPEntries(rules.Allowlist)
	if err != nil {
		return nil, err
	}

	data := ipRulesData{
		Slug:   domain.DomainSlug(site.Domain),
		Header: domain.Header(site.Domain, "", time.Now()),
		// Join the slices into a single space-separated string for the Caddyfile
		DenyStr:  strings.Join(denyList, " "),
		AllowStr: strings.Join(allowList, " "),
	}

	var buf bytes.Buffer
	if err := ipRulesTmpl.Execute(&buf, data); err != nil {
		return nil, fmt.Errorf("error executing ip-rules template: %w", err)
	}

	return buf.Bytes(), nil
}
