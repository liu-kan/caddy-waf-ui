package waf

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"text/template"
	"time"

	"github.com/developmi/caddy-waf-ui/internal/crs"
	"github.com/developmi/caddy-waf-ui/internal/domain"
)

// ExclusionType defines the exclusion types supported by our UI.
type ExclusionType string

const (
	ExcludeByID  ExclusionType = "id"
	ExcludeByTag ExclusionType = "tag"
)

// Path match modes of a path-scoped exclusion.
const (
	PathPrefix = "prefix"
	PathExact  = "exact"
)

// Exclusion removes a CRS rule (or rules with a tag) for a site, optionally
// narrowed to one parameter and/or one request path:
//
//   - no Param, no Path: the rule is removed for the whole site.
//   - Param only: the parameter is removed from the rule's targets for the
//     whole site; every other parameter is still inspected.
//   - Path only: the rule is removed for requests to that path.
//   - Path and Param: the parameter is removed from the rule's targets only
//     for requests to that path (the narrowest scope).
//
// Param is an ARGS key as shown in audit events (e.g. "q" or
// "json.messages.0.content"), or a /regex/ matching several keys.
type Exclusion struct {
	Type      ExclusionType `json:"type"`
	Value     string        `json:"value"`
	Param     string        `json:"param,omitempty"`
	Path      string        `json:"path,omitempty"`
	PathMatch string        `json:"path_match,omitempty"`
	Expires   time.Time     `json:"expires,omitzero"`
	Note      string        `json:"note,omitempty"`
}

// idBase is the first id of the runtime exclusion rules (D5: 9000001+).
const (
	idBase         = crs.UIExclusionMin
	idMax          = crs.UIExclusionMax
	policyRuleBase = crs.UIPolicyMin
	tuningRuleID   = crs.UITuningRuleID
)

// Strict patterns: they reject control characters, quotes, spaces, "#",
// "|", "," and ";" which would allow injecting SecLang directives, actions,
// target lists or Caddyfile syntax.
var (
	exclusionIDRegex    = regexp.MustCompile(`^[0-9]{1,9}$`)
	exclusionTagRegex   = regexp.MustCompile(`^[A-Za-z0-9_/.-]{1,128}$`)
	exclusionParamRegex = regexp.MustCompile(`^[A-Za-z0-9_.\-\[\]]{1,128}$`)
	paramRegexBody      = regexp.MustCompile(`^[A-Za-z0-9_.\-\\^$*+?()\[\]{}]{1,128}$`)
	exclusionPathRegex  = regexp.MustCompile(`^/[A-Za-z0-9._~!$&()*+=:@%/-]{0,255}$`)
	noteForbidden       = regexp.MustCompile("[\\x00-\\x1f\\x7f`]")
)

const maxNoteLength = 200

// validateParam accepts an exact ARGS key or a /regex/ key.
func validateParam(param string) error {
	if strings.HasPrefix(param, "/") {
		if len(param) < 3 || !strings.HasSuffix(param, "/") {
			return fmt.Errorf("invalid exclusion parameter %q: a pattern must look like /regex/", param)
		}
		body := param[1 : len(param)-1]
		if !paramRegexBody.MatchString(body) || strings.Contains(body, "{$") {
			return fmt.Errorf("invalid exclusion parameter pattern %q: only letters, digits and _.-\\^$*+?()[]{} are allowed", param)
		}
		if _, err := regexp.Compile(body); err != nil {
			return fmt.Errorf("invalid exclusion parameter pattern %q: %v", param, err)
		}
		return nil
	}
	if !exclusionParamRegex.MatchString(param) {
		return fmt.Errorf("invalid exclusion parameter %q: only letters, numbers, dots, hyphens, underscores and [] are allowed", param)
	}
	return nil
}

// ValidateParam reports whether an ARGS key (or /regex/) can be used as an
// exclusion parameter.
func ValidateParam(param string) error { return validateParam(param) }

// ValidatePath reports whether a request path can scope an exclusion.
func ValidatePath(p string) error {
	if !exclusionPathRegex.MatchString(p) {
		return fmt.Errorf("invalid exclusion path %q", p)
	}
	return nil
}

// validateSyntax validates one entry before rendering to prevent CRS
// directive injection (e.g. "\nSecRuleEngine Off") and malformed scopes.
func validateSyntax(ex Exclusion) error {
	switch ex.Type {
	case ExcludeByID:
		if !exclusionIDRegex.MatchString(ex.Value) {
			return fmt.Errorf("invalid id exclusion %q: only digits are allowed", ex.Value)
		}
	case ExcludeByTag:
		if !exclusionTagRegex.MatchString(ex.Value) {
			return fmt.Errorf("invalid tag exclusion %q: only letters, numbers, hyphens, underscores, dots and slashes are allowed", ex.Value)
		}
	default:
		return fmt.Errorf("unknown exclusion type %q: only %q or %q are allowed", ex.Type, ExcludeByID, ExcludeByTag)
	}
	if ex.Param != "" {
		if err := validateParam(ex.Param); err != nil {
			return err
		}
	}
	if ex.Path != "" {
		if !exclusionPathRegex.MatchString(ex.Path) {
			return fmt.Errorf("invalid exclusion path %q: it must start with / and contain no spaces, quotes or braces", ex.Path)
		}
		if ex.PathMatch != "" && ex.PathMatch != PathPrefix && ex.PathMatch != PathExact {
			return fmt.Errorf("invalid path match %q: use %q or %q", ex.PathMatch, PathPrefix, PathExact)
		}
	} else if ex.PathMatch != "" {
		return fmt.Errorf("path match %q requires a path", ex.PathMatch)
	}
	if len(ex.Note) > maxNoteLength || noteForbidden.MatchString(ex.Note) || strings.Contains(ex.Note, "{$") {
		return fmt.Errorf("invalid exclusion note: at most %d printable characters, no backticks", maxNoteLength)
	}
	return nil
}

// validateSemantics rejects exclusions that disable blocking altogether
// (decision rules), break CRS initialization, or target this UI's rules.
func validateSemantics(ex Exclusion) error {
	if ex.Type != ExcludeByID {
		return nil
	}
	var id int
	if _, err := fmt.Sscan(ex.Value, &id); err != nil {
		return fmt.Errorf("invalid id exclusion %q", ex.Value)
	}
	if id >= crs.UIRuleMin && id <= crs.UIRuleMax {
		return fmt.Errorf("rule %d is generated by this UI and cannot be excluded", id)
	}
	if r, ok := crs.Default().Lookup(id); ok && !r.IsExcludable() {
		return fmt.Errorf("rule %d is a %s rule and cannot be excluded: exclude the detection rules that contribute to the score instead", id, r.Kind)
	}
	return nil
}

func validateAllSyntax(exclusions []Exclusion) error {
	for _, ex := range exclusions {
		if err := validateSyntax(ex); err != nil {
			return err
		}
	}
	return nil
}

// ValidateExclusions exposes the full validation (syntax and semantics) to
// the shared service (D2) so the chain validates BEFORE taking the backup
// (validate → backup → generate...). Stored lists are only re-checked for
// syntax, so an older entry never makes a site unmanageable.
func ValidateExclusions(exclusions []Exclusion) error {
	for _, ex := range exclusions {
		if err := validateSyntax(ex); err != nil {
			return err
		}
		if err := validateSemantics(ex); err != nil {
			return err
		}
	}
	return nil
}

// normalize fills the default path match.
func (ex Exclusion) normalize() Exclusion {
	if ex.Path != "" && ex.PathMatch == "" {
		ex.PathMatch = PathPrefix
	}
	return ex
}

// key identifies duplicates: same rule, parameter and path scope.
func (ex Exclusion) key() string {
	ex = ex.normalize()
	return strings.Join([]string{string(ex.Type), ex.Value, ex.Param, ex.Path, ex.PathMatch, ex.Expires.UTC().Format(time.RFC3339Nano)}, "\x00")
}

// dedupeExclusions removes repeated entries; the first occurrence (and its
// note) wins.
func dedupeExclusions(exclusions []Exclusion) []Exclusion {
	seen := make(map[string]struct{}, len(exclusions))
	unique := make([]Exclusion, 0, len(exclusions))
	for _, ex := range exclusions {
		ex = ex.normalize()
		k := ex.key()
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}
		unique = append(unique, ex)
	}
	return unique
}

// Runtime reports whether the exclusion needs a request-time ctl rule
// (placed before CRS); otherwise it is a configure-time directive (after CRS).
func (ex Exclusion) Runtime() bool { return ex.Path != "" || !ex.Expires.IsZero() }

// Describe returns a short human description of the scope.
func (ex Exclusion) Describe() string {
	ex = ex.normalize()
	target := "rule " + ex.Value
	if ex.Type == ExcludeByTag {
		target = "rules tagged " + ex.Value
	}
	switch {
	case ex.Param != "" && ex.Path != "":
		return fmt.Sprintf("skip ARGS:%s in %s for %s %s", ex.Param, target, pathScope(ex), ex.Path)
	case ex.Param != "":
		return fmt.Sprintf("skip ARGS:%s in %s for the whole site", ex.Param, target)
	case ex.Path != "":
		return fmt.Sprintf("remove %s for %s %s", target, pathScope(ex), ex.Path)
	default:
		return fmt.Sprintf("remove %s for the whole site", target)
	}
}

func pathScope(ex Exclusion) string {
	if ex.PathMatch == PathExact {
		return "path"
	}
	return "paths under"
}

// directive renders the SecLang line of an exclusion. id is only used by
// runtime (path-scoped) exclusions.
func (ex Exclusion) directive(id int) string {
	ex = ex.normalize()
	if ex.Path != "" || !ex.Expires.IsZero() {
		op := "@beginsWith"
		if ex.PathMatch == PathExact {
			op = "@streq"
		}
		var ctl string
		switch {
		case ex.Type == ExcludeByID && ex.Param != "":
			ctl = "ctl:ruleRemoveTargetById=" + ex.Value + ";ARGS:" + ex.Param
		case ex.Type == ExcludeByID:
			ctl = "ctl:ruleRemoveById=" + ex.Value
		case ex.Param != "":
			ctl = "ctl:ruleRemoveTargetByTag=" + ex.Value + ";ARGS:" + ex.Param
		default:
			ctl = "ctl:ruleRemoveByTag=" + ex.Value
		}
		if ex.Path == "" {
			return fmt.Sprintf(`SecRule TIME_EPOCH "@lt %d" "id:%d,phase:1,pass,t:none,nolog,%s"`, ex.Expires.Unix(), id, ctl)
		}
		// REQUEST_FILENAME is the decoded but not normalized path. The
		// exclusion applies only when the raw path AND its normalized form
		// (dot segments, backslashes) are in scope, so a request such as
		// /api/upload/../admin never inherits the exclusion of /api/upload,
		// whatever normalization the backend applies.
		normalized := fmt.Sprintf(`SecRule REQUEST_FILENAME "%s %s" "t:none,t:normalizePathWin,%s"`, op, ex.Path, ctl)
		if !ex.Expires.IsZero() {
			return fmt.Sprintf("SecRule TIME_EPOCH \"@lt %d\" \"id:%d,phase:1,pass,t:none,nolog,chain\"\nSecRule REQUEST_FILENAME \"%s %s\" \"t:none,chain\"\n%s", ex.Expires.Unix(), id, op, ex.Path, normalized)
		}
		return fmt.Sprintf("SecRule REQUEST_FILENAME \"%s %s\" \"id:%d,phase:1,pass,t:none,nolog,chain\"\n%s", op, ex.Path, id, normalized)
	}
	switch {
	case ex.Type == ExcludeByID && ex.Param != "":
		return fmt.Sprintf(`SecRuleUpdateTargetById %s "!ARGS:%s"`, ex.Value, ex.Param)
	case ex.Type == ExcludeByID:
		return "SecRuleRemoveById " + ex.Value
	case ex.Param != "":
		return fmt.Sprintf(`SecRuleUpdateTargetByTag "%s" "!ARGS:%s"`, ex.Value, ex.Param)
	default:
		return fmt.Sprintf(`SecRuleRemoveByTag "%s"`, ex.Value)
	}
}

// compileExclusions returns the runtime (pre-CRS) and configure-time
// (post-CRS) directives in list order.
func compileExclusions(exclusions []Exclusion) (runtime, configuration []string, err error) {
	if err := validateAllSyntax(exclusions); err != nil {
		return nil, nil, err
	}
	next := idBase
	for _, ex := range dedupeExclusions(exclusions) {
		if ex.Runtime() {
			if next > idMax {
				return nil, nil, fmt.Errorf("too many path-scoped exclusions (max %d)", idMax-idBase+1)
			}
			runtime = append(runtime, ex.directive(next))
			next++
			continue
		}
		configuration = append(configuration, ex.directive(0))
	}
	return runtime, configuration, nil
}

const exclusionsTemplate = `# Caddy WAF UI managed - do not edit manually
{{ .Header }}
# Canonical exclusion list, compiled into the site's WAF overlay (waf-*.conf).
{{ range .Rows }}
{{ .Meta }}
{{ .Directive }}
{{ else }}
# No exclusions configured for this domain.
{{ end -}}
`

type exclusionRow struct {
	Meta      string
	Directive string
}

var exclusionsTmpl = template.Must(template.New("exclusions").Parse(exclusionsTemplate))

// exclusionMetaPrefix marks the machine-readable form of an exclusion.
const exclusionMetaPrefix = "# ui-exclusion: "

// GenerateExclusions renders the canonical exclusions file: one metadata
// comment (the source of truth) and its compiled directive per entry.
func GenerateExclusions(site *domain.Site, exclusions []Exclusion) ([]byte, error) {
	if err := validateAllSyntax(exclusions); err != nil {
		return nil, err
	}
	var rows []exclusionRow
	next := idBase
	for _, ex := range dedupeExclusions(exclusions) {
		meta, err := json.Marshal(ex)
		if err != nil {
			return nil, err
		}
		id := 0
		if ex.Runtime() {
			id = next
			next++
		}
		rows = append(rows, exclusionRow{Meta: exclusionMetaPrefix + string(meta), Directive: ex.directive(id)})
	}
	var buf bytes.Buffer
	data := struct {
		Header string
		Rows   []exclusionRow
	}{Header: domain.Header(site.Domain, "", time.Now()), Rows: rows}
	if err := exclusionsTmpl.Execute(&buf, data); err != nil {
		return nil, fmt.Errorf("error executing exclusions template: %w", err)
	}
	return buf.Bytes(), nil
}

// Legacy directive formats written before the metadata comments existed.
var (
	legacyRemoveByID   = regexp.MustCompile(`^SecRuleRemoveById\s+(\d+)$`)
	legacyRemoveByTag  = regexp.MustCompile(`^SecRuleRemoveByTag\s+"([A-Za-z0-9_-]+)"$`)
	legacyTargetedRule = regexp.MustCompile(`^SecRule ARGS:([A-Za-z0-9_-]+)\s+"@unconditionalMatch"\s+"id:\d+,phase:2,pass,nolog,ctl:ruleRemoveBy(Id|Tag)=([A-Za-z0-9_-]+)"$`)
)

// ParseExclusions reads a canonical exclusions file. Files with metadata
// comments are read from the metadata only (directives are derived); legacy
// files are read from their directives. Any other directive is rejected:
// the file is never interpreted loosely.
func ParseExclusions(content []byte) ([]Exclusion, error) {
	lines := strings.Split(string(content), "\n")
	hasMeta := false
	for _, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), exclusionMetaPrefix) {
			hasMeta = true
			break
		}
	}
	var out []Exclusion
	for _, line := range lines {
		line = strings.TrimSpace(line)
		switch {
		case line == "":
			continue
		case strings.HasPrefix(line, exclusionMetaPrefix):
			var ex Exclusion
			if err := json.Unmarshal([]byte(strings.TrimPrefix(line, exclusionMetaPrefix)), &ex); err != nil {
				return nil, fmt.Errorf("invalid exclusion metadata: %w", err)
			}
			out = append(out, ex)
		case strings.HasPrefix(line, "#"), hasMeta:
			continue
		default:
			ex, err := parseLegacyExclusion(line)
			if err != nil {
				return nil, err
			}
			out = append(out, ex)
		}
	}
	if err := validateAllSyntax(out); err != nil {
		return nil, err
	}
	return dedupeExclusions(out), nil
}

// parseLegacyExclusion converts a directive written by earlier releases.
// The old parameter form removed the whole rule when the parameter existed;
// it is migrated to the narrower per-parameter target removal.
func parseLegacyExclusion(line string) (Exclusion, error) {
	if m := legacyRemoveByID.FindStringSubmatch(line); m != nil {
		return Exclusion{Type: ExcludeByID, Value: m[1]}, nil
	}
	if m := legacyRemoveByTag.FindStringSubmatch(line); m != nil {
		return Exclusion{Type: ExcludeByTag, Value: m[1]}, nil
	}
	if m := legacyTargetedRule.FindStringSubmatch(line); m != nil {
		typ := ExcludeByID
		if m[2] == "Tag" {
			typ = ExcludeByTag
		}
		return Exclusion{Type: typ, Value: m[3], Param: m[1]}, nil
	}
	return Exclusion{}, fmt.Errorf("unsupported exclusions directive: %s", line)
}
