// Package crs turns SecLang rule files (OWASP CRS, Coraza's recommended
// baseline) into a rule dictionary. The UI uses it to explain rule IDs found
// in audit events, to classify them (detection, decision, direct block) and
// to recompute anomaly scores when estimating the impact of a policy change.
package crs

import (
	"bufio"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Rule kinds. Only "detection" rules add anomaly score; "decision" rules
// compare the accumulated score with a threshold and must never be excluded;
// "blocking" rules deny directly, independent of the anomaly threshold.
const (
	KindDetection   = "detection"
	KindDecision    = "decision"
	KindBlocking    = "blocking"
	KindCorrelation = "correlation"
	KindControl     = "control"
	KindUI          = "ui"
)

// Score directions.
const (
	DirInbound  = "in"
	DirOutbound = "out"
)

// Cond is one chained condition (targets and operator) of a rule chain.
type Cond struct {
	Targets  string `json:"targets"`
	Operator string `json:"operator"`
}

// Rule is the dictionary entry of a SecLang rule that carries an id.
type Rule struct {
	ID       int      `json:"id"`
	File     string   `json:"file"`
	Line     int      `json:"line"`
	Phase    int      `json:"phase,omitempty"`
	Msg      string   `json:"msg,omitempty"`
	Severity string   `json:"severity,omitempty"`
	PL       int      `json:"pl,omitempty"`
	Tags     []string `json:"tags,omitempty"`
	Kind     string   `json:"kind"`
	Dir      string   `json:"dir,omitempty"`
	Score    int      `json:"score,omitempty"`
	Category string   `json:"category,omitempty"`
	Action   string   `json:"action,omitempty"`
	Status   int      `json:"status,omitempty"`
	Targets  string   `json:"targets,omitempty"`
	Operator string   `json:"operator,omitempty"`
	Chain    []Cond   `json:"chain,omitempty"`
	Comment  string   `json:"comment,omitempty"`
	Link     string   `json:"link,omitempty"`
	// Ver is the rule's ver: action, used to detect the ruleset version.
	Ver string `json:"-"`
}

// severityNames maps SecLang numeric severities (syslog levels) to the names
// CRS uses. Coraza's recommended baseline writes severity:2.
var severityNames = map[string]string{
	"0": "EMERGENCY", "1": "ALERT", "2": "CRITICAL", "3": "ERROR",
	"4": "WARNING", "5": "NOTICE", "6": "INFO", "7": "DEBUG",
}

// SeverityName normalizes a numeric or named severity to its upper-case name.
func SeverityName(raw string) string {
	raw = strings.ToUpper(strings.Trim(strings.TrimSpace(raw), "'\""))
	if name, ok := severityNames[raw]; ok {
		return name
	}
	return raw
}

// SeverityScore returns the default CRS anomaly score of a severity
// (tx.critical_anomaly_score=5, error=4, warning=3, notice=2).
func SeverityScore(severity string) int {
	switch SeverityName(severity) {
	case "EMERGENCY", "ALERT", "CRITICAL":
		return 5
	case "ERROR":
		return 4
	case "WARNING":
		return 3
	case "NOTICE":
		return 2
	default:
		return 0
	}
}

var (
	scoreSetvar = regexp.MustCompile(`(?i)^tx\.(inbound|outbound)_anomaly_score_pl([1-4])=\+%\{tx\.(critical|error|warning|notice)_anomaly_score\}$`)
	plTag       = regexp.MustCompile(`^paranoia-level/([1-4])$`)
	fileGroup   = regexp.MustCompile(`^(?:REQUEST|RESPONSE)-\d+-(.+)\.conf$`)
)

// severityVarScores mirrors the CRS defaults of the *_anomaly_score variables
// referenced by setvar actions.
var severityVarScores = map[string]int{"critical": 5, "error": 4, "warning": 3, "notice": 2}

// directive is a logical SecLang line with its starting line number and the
// comment block that immediately precedes it.
type directive struct {
	line    int
	text    string
	comment string
}

// readDirectives joins backslash continuations, strips comments and returns
// the logical directives of a SecLang file.
func readDirectives(r io.Reader) ([]directive, error) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
	var (
		out      []directive
		comment  []string
		blanks   int
		current  strings.Builder
		start    int
		inDirect bool
		lineNo   int
	)
	for scanner.Scan() {
		lineNo++
		raw := strings.TrimRight(scanner.Text(), "\r")
		trimmed := strings.TrimSpace(raw)
		if !inDirect {
			switch {
			case trimmed == "":
				blanks++
				if blanks > 1 {
					comment = nil
				}
				continue
			case strings.HasPrefix(trimmed, "#"):
				if blanks > 0 {
					comment = nil
				}
				blanks = 0
				comment = append(comment, strings.TrimSpace(strings.TrimLeft(trimmed, "#")))
				continue
			}
			start = lineNo
			inDirect = true
			current.Reset()
		} else {
			trimmed = strings.TrimLeft(raw, " \t")
		}
		if strings.HasSuffix(trimmed, "\\") {
			current.WriteString(strings.TrimSuffix(trimmed, "\\"))
			continue
		}
		current.WriteString(trimmed)
		out = append(out, directive{line: start, text: current.String(), comment: cleanComment(comment)})
		comment = nil
		blanks = 0
		inDirect = false
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if inDirect {
		out = append(out, directive{line: start, text: current.String(), comment: cleanComment(comment)})
	}
	return out, nil
}

// cleanComment keeps the descriptive lines of a CRS comment block (drops
// separators and empty lines) and bounds its size.
func cleanComment(lines []string) string {
	var kept []string
	for _, line := range lines {
		if strings.Trim(line, "-=[] ") == "" {
			continue
		}
		if strings.HasPrefix(line, "-=[") && strings.HasSuffix(line, "]=-") {
			line = strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(line, "-=["), "]=-"))
		}
		kept = append(kept, line)
	}
	text := strings.Join(kept, "\n")
	const maxComment = 1500
	if len(text) > maxComment {
		text = text[:maxComment] + "…"
	}
	return text
}

// splitArgs splits a directive into whitespace-separated arguments, honoring
// double quotes and unescaping \" inside them.
func splitArgs(s string) []string {
	var (
		args     []string
		b        strings.Builder
		inQuote  bool
		hasToken bool
	)
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case inQuote && c == '\\' && i+1 < len(s) && s[i+1] == '"':
			b.WriteByte('"')
			i++
		case c == '"':
			inQuote = !inQuote
			hasToken = true
		case !inQuote && (c == ' ' || c == '\t'):
			if hasToken {
				args = append(args, b.String())
				b.Reset()
				hasToken = false
			}
		default:
			b.WriteByte(c)
			hasToken = true
		}
	}
	if hasToken {
		args = append(args, b.String())
	}
	return args
}

type action struct {
	name  string
	value string
}

// splitActions splits a SecLang action list on commas outside single quotes.
func splitActions(s string) []action {
	var (
		parts []string
		inQ   bool
		start int
	)
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\\':
			i++
		case '\'':
			inQ = !inQ
		case ',':
			if !inQ {
				parts = append(parts, s[start:i])
				start = i + 1
			}
		}
	}
	parts = append(parts, s[start:])
	actions := make([]action, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		name, value, _ := strings.Cut(part, ":")
		value = strings.TrimSpace(value)
		if len(value) >= 2 && value[0] == '\'' && value[len(value)-1] == '\'' {
			value = value[1 : len(value)-1]
		}
		actions = append(actions, action{name: strings.ToLower(strings.TrimSpace(name)), value: value})
	}
	return actions
}

// parsedRule accumulates the facts of a rule and its chained conditions.
type parsedRule struct {
	Rule
	chained    bool
	scoreDir   string
	scorePL    int
	scoreValue int
	disruptive string
	nolog      bool
}

// Parse reads a SecLang file and returns its rules that carry an id. file is
// recorded as the rule origin (e.g. "@owasp_crs/REQUEST-930-...conf").
func Parse(r io.Reader, file string) ([]Rule, error) {
	directives, err := readDirectives(r)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", file, err)
	}
	var (
		rules  []*parsedRule
		parent *parsedRule
	)
	for _, d := range directives {
		args := splitArgs(d.text)
		if len(args) == 0 {
			continue
		}
		var targets, operator, actionList string
		switch strings.ToLower(args[0]) {
		case "secrule":
			if len(args) < 3 {
				return nil, fmt.Errorf("%s:%d: SecRule needs targets and an operator", file, d.line)
			}
			targets, operator = args[1], args[2]
			if len(args) > 3 {
				actionList = args[3]
			}
		case "secaction":
			if len(args) > 1 {
				actionList = args[1]
			}
		default:
			parent = nil
			continue
		}
		actions := splitActions(actionList)
		if parent != nil {
			parent.Chain = append(parent.Chain, Cond{Targets: targets, Operator: operator})
			parent.apply(actions)
			if !hasAction(actions, "chain") {
				parent = nil
			}
			continue
		}
		rule := &parsedRule{Rule: Rule{File: file, Line: d.line, Targets: targets, Operator: operator, Comment: d.comment}}
		rule.apply(actions)
		if rule.ID == 0 {
			continue
		}
		rules = append(rules, rule)
		if hasAction(actions, "chain") {
			parent = rule
		}
	}
	out := make([]Rule, 0, len(rules))
	for _, rule := range rules {
		rule.classify()
		out = append(out, rule.Rule)
	}
	return out, nil
}

func hasAction(actions []action, name string) bool {
	for _, a := range actions {
		if a.name == name {
			return true
		}
	}
	return false
}

// apply records the actions of a rule (or of one of its chained conditions;
// chained conditions only contribute non-disruptive actions in SecLang).
func (r *parsedRule) apply(actions []action) {
	for _, a := range actions {
		switch a.name {
		case "id":
			if id, err := strconv.Atoi(strings.Trim(a.value, "'\" ")); err == nil {
				r.ID = id
			}
		case "phase":
			r.Phase = parsePhase(a.value)
		case "msg":
			r.Msg = a.value
		case "ver":
			r.Ver = a.value
		case "severity":
			r.Severity = SeverityName(a.value)
		case "tag":
			r.Tags = append(r.Tags, a.value)
			if m := plTag.FindStringSubmatch(a.value); m != nil {
				r.PL, _ = strconv.Atoi(m[1])
			}
		case "setvar":
			if m := scoreSetvar.FindStringSubmatch(a.value); m != nil {
				r.scoreDir = DirInbound
				if strings.EqualFold(m[1], "outbound") {
					r.scoreDir = DirOutbound
				}
				r.scorePL, _ = strconv.Atoi(m[2])
				r.scoreValue = severityVarScores[strings.ToLower(m[3])]
			}
		case "status":
			r.Status, _ = strconv.Atoi(a.value)
		case "deny", "drop", "block", "pass", "allow", "redirect":
			if r.disruptive == "" {
				r.disruptive = a.name
			}
		case "nolog":
			r.nolog = true
		case "chain":
			r.chained = true
		}
	}
}

// parsePhase converts phase:N or the request/response/logging aliases.
func parsePhase(value string) int {
	switch strings.ToLower(strings.Trim(value, "'\" ")) {
	case "request":
		return 2
	case "response":
		return 4
	case "logging":
		return 5
	}
	n, _ := strconv.Atoi(strings.Trim(value, "'\" "))
	return n
}

// classify derives kind, score, direction and category.
func (r *parsedRule) classify() {
	r.Action = r.disruptive
	if r.scoreDir != "" && r.scoreValue > 0 {
		r.Kind = KindDetection
		r.Dir = r.scoreDir
		r.Score = r.scoreValue
		if r.PL == 0 {
			r.PL = r.scorePL
		}
	} else if r.disruptive == "deny" || r.disruptive == "drop" || r.disruptive == "redirect" {
		if strings.Contains(strings.ToUpper(r.Targets), "ANOMALY_SCORE") {
			r.Kind = KindDecision
			if strings.Contains(strings.ToUpper(r.Targets), "OUTBOUND") {
				r.Dir = DirOutbound
			} else {
				r.Dir = DirInbound
			}
		} else {
			r.Kind = KindBlocking
		}
	} else if r.Phase == 5 && strings.Contains(r.File, "-980-") {
		r.Kind = KindCorrelation
	} else {
		r.Kind = KindControl
	}
	r.Category = categoryOf(r.Tags, r.File)
	sort.Strings(r.Tags)
}

// categoryOf returns the attack category from the CRS tags, falling back to
// the rule file group (e.g. "protocol-enforcement").
func categoryOf(tags []string, file string) string {
	for _, tag := range tags {
		if strings.HasPrefix(tag, "attack-") {
			return strings.TrimPrefix(tag, "attack-")
		}
	}
	base := file
	if i := strings.LastIndexAny(base, "/\\"); i >= 0 {
		base = base[i+1:]
	}
	if m := fileGroup.FindStringSubmatch(base); m != nil {
		return strings.ToLower(m[1])
	}
	return ""
}
