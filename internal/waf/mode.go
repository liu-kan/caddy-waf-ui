package waf

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
	"text/template"
	"time"

	"github.com/developmi/caddy-waf-ui/internal/domain"
)

// Options describes the operator-owned baseline. Before/after includes retain
// custom rules when UI actions change the engine mode, policy or exclusions.
type Options struct {
	CRSMode            string
	CorazaConfig       string
	CRSSetup           string
	CRSRules           string
	BeforeFile         string
	AfterFile          string
	ResponseBodyAccess string
	AuditParts         string
	// Exclusions is the raw content of a canonical exclusions file, used by
	// the GenerateSnippetWithOptions compatibility entry point.
	Exclusions string
}

func DefaultOptions() Options {
	return Options{
		CRSMode:            "embedded",
		CorazaConfig:       "@coraza.conf-recommended",
		CRSSetup:           "@crs-setup.conf.example",
		CRSRules:           "@owasp_crs/*.conf",
		ResponseBodyAccess: "Off",
		AuditParts:         "AHKZ",
	}
}

// Config is the per-site managed state compiled into the WAF overlay.
type Config struct {
	Mode       domain.WAFMode
	Policy     Policy
	Exclusions []Exclusion
}

// Generated is a rendered overlay with the identifiers needed to verify that
// Caddy loaded it.
type Generated struct {
	Content   []byte
	Revision  string
	Signature Signature
}

// The coraza_waf block is inline (directly importable in a site block). The
// 3-segment header (# domain: | mode: | updated:) is the contract parsed by
// the scanner; the ui-policy line stores the policy for later edits.
//
// Directive order matters:
//  1. Coraza baseline and CRS setup, then the operator's before-file.
//  2. UI policy (SecAction setvar) so it overrides crs-setup/before values.
//  3. Runtime (path-scoped) exclusions: ctl actions must run before the CRS
//     rules they disable.
//  4. CRS rules, the operator's after-file, then configure-time exclusions
//     (SecRuleRemove*/SecRuleUpdateTarget*) which need the rules loaded.
//  5. Disabled rule groups and the tuning-mode audit rule.
//  6. Engine, response access and audit settings owned by the UI.
//
// The revision comment and the component signature live INSIDE directives:
// Coraza Caddy v2.6.1 pools WAF instances by directive text, so every
// regeneration produces a new instance even when only an external include
// changed. The signature is copied into each audit record.
const wafTemplate = `# Caddy WAF UI managed - do not edit manually
{{ .Header }}
{{ .PolicyLine }}
coraza_waf {
{{ if eq .Options.CRSMode "embedded" }}    load_owasp_crs
{{ end }}    directives ` + "`" + `
        # waf-config-revision: {{ .Revision }}
        SecComponentSignature "{{ .Signature }}"
        Include {{ .Options.CorazaConfig }}
        Include {{ .Options.CRSSetup }}
{{ if .Options.BeforeFile }}        Include {{ .Options.BeforeFile }}
{{ end }}        # ui-policy-begin
{{ range .PolicyPre }}        {{ . }}
{{ end }}        # ui-policy-end
        # ui-runtime-exclusions-begin
{{ range .Runtime }}        {{ . }}
{{ end }}        # ui-runtime-exclusions-end
        Include {{ .Options.CRSRules }}
{{ if .Options.AfterFile }}        Include {{ .Options.AfterFile }}
{{ end }}        # ui-config-exclusions-begin
{{ range .Configuration }}        {{ . }}
{{ end }}        # ui-config-exclusions-end
        # ui-policy-post-begin
{{ range .PolicyPost }}        {{ . }}
{{ end }}        # ui-policy-post-end
        SecRuleEngine {{ .Mode }}
        SecResponseBodyAccess {{ .Options.ResponseBodyAccess }}
        SecAuditEngine RelevantOnly
        SecAuditLog {{ .AuditPath }}
        SecAuditLogFormat JSON
        SecAuditLogParts {{ .Options.AuditParts }}
        SecAuditLogFileMode 0640
        SecAuditLogDirMode 0750
    ` + "`" + `
}
`

var wafTmpl = template.Must(template.New("waf").Parse(wafTemplate))

type templateData struct {
	Header        string
	PolicyLine    string
	Mode          domain.WAFMode
	AuditPath     string
	Revision      string
	Signature     string
	Options       Options
	PolicyPre     []string
	PolicyPost    []string
	Runtime       []string
	Configuration []string
}

// GenerateSnippet retains the original API: default baseline and policy, no
// exclusions. includeDir no longer creates a filesystem Include dependency.
func GenerateSnippet(site *domain.Site, auditPath, _ string) ([]byte, error) {
	return GenerateSnippetWithOptions(site, auditPath, DefaultOptions())
}

// GenerateSnippetWithOptions renders a site with the default policy and the
// exclusions carried as raw canonical-file content in opts.Exclusions.
func GenerateSnippetWithOptions(site *domain.Site, auditPath string, opts Options) ([]byte, error) {
	exclusions, err := ParseExclusions([]byte(opts.Exclusions))
	if err != nil {
		return nil, err
	}
	g, err := Generate(site.Domain, Config{Mode: site.Mode, Policy: DefaultPolicy(), Exclusions: exclusions}, auditPath, opts)
	if err != nil {
		return nil, err
	}
	return g.Content, nil
}

// Generate renders the WAF overlay of a site. It is a pure function apart
// from the random revision.
func Generate(site string, cfg Config, auditPath string, opts Options) (Generated, error) {
	if cfg.Mode != domain.ModeOn && cfg.Mode != domain.ModeOff && cfg.Mode != domain.ModeDetectionOnly {
		return Generated{}, fmt.Errorf("invalid WAF mode %q", cfg.Mode)
	}
	if !siteNamePattern.MatchString(site) {
		return Generated{}, fmt.Errorf("invalid site name %q", site)
	}
	if err := validateOptions(auditPath, opts); err != nil {
		return Generated{}, err
	}
	policy := cfg.Policy.Normalize()
	if err := policy.Validate(); err != nil {
		return Generated{}, err
	}
	runtime, configuration, err := compileExclusions(cfg.Exclusions)
	if err != nil {
		return Generated{}, err
	}
	revision, err := newRevision()
	if err != nil {
		return Generated{}, err
	}
	policyLine, err := encodePolicyLine(policy)
	if err != nil {
		return Generated{}, err
	}
	sig := Signature{Site: site, Revision: revision, Mode: string(cfg.Mode), BlockingPL: policy.BlockingPL,
		DetectionPL: policy.DetectionPL, Inbound: policy.InboundThreshold, Outbound: policy.OutboundThreshold, Tuning: policy.Tuning}
	pre, post := policy.render()
	data := templateData{
		Header:     domain.Header(site, cfg.Mode, time.Now()),
		PolicyLine: policyLine,
		Mode:       cfg.Mode, AuditPath: auditPath, Options: opts, Revision: revision,
		Signature: sig.String(), PolicyPre: pre, PolicyPost: post,
		Runtime: runtime, Configuration: configuration,
	}
	var buf bytes.Buffer
	if err := wafTmpl.Execute(&buf, data); err != nil {
		return Generated{}, err
	}
	return Generated{Content: buf.Bytes(), Revision: revision, Signature: sig}, nil
}

// siteNamePattern mirrors service.ValidateDomain at the generator boundary:
// the name is written into the component signature.
var siteNamePattern = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$`)

func validateOptions(auditPath string, opts Options) error {
	if opts.CRSMode != "embedded" && opts.CRSMode != "files" {
		return fmt.Errorf("CADDY_UI_CRS_MODE must be embedded or files")
	}
	for _, path := range []string{auditPath, opts.CorazaConfig, opts.CRSSetup, opts.CRSRules} {
		if err := validateDirectivePath(path); err != nil {
			return err
		}
	}
	for _, path := range []string{opts.BeforeFile, opts.AfterFile} {
		if path != "" {
			if err := validateDirectivePath(path); err != nil {
				return err
			}
		}
	}
	if opts.ResponseBodyAccess != "On" && opts.ResponseBodyAccess != "Off" {
		return fmt.Errorf("CADDY_UI_RESPONSE_BODY_ACCESS must be On or Off")
	}
	if opts.AuditParts == "" || strings.Trim(opts.AuditParts, "ABCDEFGHIJKZ") != "" {
		return fmt.Errorf("invalid CADDY_UI_AUDIT_LOG_PARTS")
	}
	return nil
}

func validateDirectivePath(path string) error {
	if path == "" || strings.ContainsAny(path, " \t\r\n\"'`{}") {
		return fmt.Errorf("invalid Coraza directive path %q: use a path without whitespace or quotes", path)
	}
	return nil
}

func newRevision() (string, error) {
	var token [16]byte
	if _, err := rand.Read(token[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(token[:]), nil
}

var revisionLine = regexp.MustCompile(`(?m)^ *# waf-config-revision: ([a-f0-9]+)$`)

// Revision returns the revision embedded in a generated overlay, or "".
func Revision(content []byte) string {
	if m := revisionLine.FindSubmatch(content); m != nil {
		return string(m[1])
	}
	return ""
}
