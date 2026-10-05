package events

import (
	"encoding/json"
	"errors"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/developmi/caddy-waf-ui/internal/crs"
	"github.com/developmi/caddy-waf-ui/internal/waf"
)

// auditRecord is the subset of a Coraza v3 JSON audit record used here.
// Severity is a number in Coraza v3 and a string in legacy writers.
type auditRecord struct {
	Transaction struct {
		Timestamp     string `json:"timestamp"`
		UnixTimestamp int64  `json:"unix_timestamp"`
		ID            string `json:"id"`
		ClientIP      string `json:"client_ip"`
		ServerID      string `json:"server_id"`
		Request       *struct {
			Method  string              `json:"method"`
			URI     string              `json:"uri"`
			Headers map[string][]string `json:"headers"`
		} `json:"request"`
		Response *struct {
			Status int `json:"status"`
		} `json:"response"`
		Producer *struct {
			RuleEngine string   `json:"rule_engine"`
			Rulesets   []string `json:"rulesets"`
		} `json:"producer"`
		IsInterrupted *bool  `json:"is_interrupted"`
		Action        string `json:"action"`
	} `json:"transaction"`
	Messages []struct {
		Actionset    string `json:"actionset"`
		Message      string `json:"message"`
		ErrorMessage string `json:"error_message"`
		Data         *struct {
			ID       int             `json:"id"`
			Msg      string          `json:"msg"`
			Data     string          `json:"data"`
			Severity json.RawMessage `json:"severity"`
			Ver      string          `json:"ver"`
			Tags     []string        `json:"tags"`
			Raw      string          `json:"raw"`
		} `json:"data"`
	} `json:"messages"`
}

// ErrNotAuditRecord marks JSON that is not a Coraza transaction.
var ErrNotAuditRecord = errors.New("not a Coraza audit record (no transaction.id)")

// Normalizer converts audit records to events.
type Normalizer struct {
	Dict *crs.Dictionary
	Node string
	// SiteForHost maps a Host to a managed site when a record carries no
	// UI signature (overlays generated before signatures existed).
	SiteForHost func(host string) string
}

const (
	maxHits      = 50
	maxDataLen   = 160
	maxValueLen  = 200
	maxPathLen   = 512
	maxQueryKeys = 20
	maxMsgLen    = 300
	redacted     = "[redacted]"
)

var (
	matchedData   = regexp.MustCompile(`^Matched Data: `)
	foundWithin   = regexp.MustCompile(` found within ([A-Z_]+(?::[^\s:]+(?::[^\s:]+)*)?): `)
	totalScore    = regexp.MustCompile(`Total Score: (\d+)`)
	crsVersionTag = regexp.MustCompile(`OWASP_CRS/(\d+\.\d+\.\d+)`)
	plTagPattern  = regexp.MustCompile(`^paranoia-level/([1-4])$`)
	// Sensitive targets whose matched content is never stored.
	sensitiveVar = regexp.MustCompile(`(?i)^(?:REQUEST_COOKIES(?:_NAMES)?(?::.*)?|REQUEST_HEADERS:(?:authorization|proxy-authorization|cookie|set-cookie|x-api-key|api-key|x-auth-token|x-access-token|x-csrf-token|x-xsrf-token)|(?:ARGS|ARGS_GET|ARGS_POST|ARGS_NAMES):.*(?:pass|pwd|secret|token|apikey|api_key|auth|session|sess|csrf|xsrf|otp|totp|credential|private|signature|jwt|bearer).*)$`)
)

// Normalize parses one JSON audit record.
func (n *Normalizer) Normalize(raw []byte) (*Event, error) {
	var rec auditRecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		return nil, err
	}
	return n.normalize(&rec)
}

func (n *Normalizer) normalize(rec *auditRecord) (*Event, error) {
	tx := rec.Transaction
	if tx.ID == "" {
		return nil, ErrNotAuditRecord
	}
	e := &Event{Kind: "event", V: SchemaVersion, TxID: tx.ID, Node: n.Node, ClientIP: tx.ClientIP,
		TS: recordTime(tx.Timestamp, tx.UnixTimestamp)}
	if tx.Request != nil {
		e.Method = tx.Request.Method
		e.Path, e.QueryKeys = splitURI(tx.Request.URI)
	}
	e.Host = tx.ServerID
	if e.Host == "" && tx.Request != nil {
		e.Host = headerValue(tx.Request.Headers, "host")
	}
	if i := strings.LastIndex(e.Host, ":"); i > 0 && !strings.Contains(e.Host, "]") && strings.Count(e.Host, ":") == 1 {
		e.Host = e.Host[:i]
	}
	if tx.Response != nil {
		e.Status = tx.Response.Status
	}
	var rulesets []string
	if tx.Producer != nil {
		e.Engine = tx.Producer.RuleEngine
		rulesets = tx.Producer.Rulesets
	}
	actionsets := make([]string, 0, len(rec.Messages))
	for _, m := range rec.Messages {
		actionsets = append(actionsets, m.Actionset)
	}
	if sig, ok := waf.FindSignature(rulesets, actionsets...); ok {
		e.Site, e.Mode, e.Revision = sig.Site, sig.Mode, sig.Revision
		e.BlockingPL, e.DetectionPL, e.ThrIn, e.ThrOut, e.Tuning = sig.BlockingPL, sig.DetectionPL, sig.Inbound, sig.Outbound, sig.Tuning
	}
	if e.Site == "" {
		e.Site = e.Host
		if n.SiteForHost != nil {
			if site := n.SiteForHost(e.Host); site != "" {
				e.Site = site
			}
		}
	}
	if e.Engine == "" {
		e.Engine = e.Mode
	}
	e.CRS = crsVersion(rulesets, rec)

	directBlock := false
	seen := map[int]bool{}
	var ids []string
	for _, m := range rec.Messages {
		if m.Data == nil || m.Data.ID == 0 {
			continue
		}
		// Coraza also logs the match data of chained conditions as separate
		// messages without msg/logdata. The chain added its score once.
		if m.Data.Msg == "" && m.Data.Data == "" && len(e.Hits) > 0 && e.Hits[len(e.Hits)-1].ID == m.Data.ID {
			continue
		}
		h := n.hit(m.Data.ID, m.Data.Msg, m.Data.Data, m.Data.Severity, m.Data.Tags, m.Data.Raw)
		if h.Kind == crs.KindBlocking || (h.Kind == "unknown" && disruptiveLog(m.ErrorMessage)) {
			directBlock = true
		}
		if h.Kind == crs.KindDecision {
			if s := totalScore.FindStringSubmatch(h.Msg); s != nil {
				score, _ := strconv.Atoi(s[1])
				if h.Dir == crs.DirOutbound {
					e.ReportedOut = score
				} else {
					e.ReportedIn = score
				}
			}
		}
		if !seen[h.ID] {
			seen[h.ID] = true
			ids = append(ids, strconv.Itoa(h.ID))
		}
		e.Hits = append(e.Hits, h)
	}
	e.RuleIDs = "," + strings.Join(ids, ",") + ","
	if len(ids) == 0 {
		e.RuleIDs = ""
	}
	e.computeScores()
	e.Interrupted = interrupted(tx.IsInterrupted, tx.Action)
	e.Action = e.classify(directBlock)
	if len(e.Hits) > maxHits {
		e.Hits = e.Hits[:maxHits]
	}
	if e.Hits == nil {
		e.Hits = []Hit{}
	}
	return e, nil
}

// hit builds one rule match, resolving its kind and score from the rule
// dictionary, then from the rule text Coraza logged, then from severity.
func (n *Normalizer) hit(id int, msg, logdata string, severity json.RawMessage, tags []string, raw string) Hit {
	h := Hit{ID: id, Msg: truncate(msg, maxMsgLen), Severity: severityName(severity)}
	for _, tag := range tags {
		if m := plTagPattern.FindStringSubmatch(tag); m != nil {
			h.PL, _ = strconv.Atoi(m[1])
		}
	}
	h.Var, h.Data, h.Value = splitLogdata(logdata)
	if h.Var != "" && sensitiveVar.MatchString(h.Var) {
		h.Data, h.Value = redacted, redacted
	}
	rule, ok := n.Dict.Lookup(id)
	if !ok && raw != "" {
		if parsed, err := crs.Parse(strings.NewReader(raw), "audit"); err == nil && len(parsed) > 0 && parsed[0].ID == id {
			rule, ok = parsed[0], true
		}
	}
	if ok {
		h.Kind, h.Dir, h.Category = rule.Kind, rule.Dir, rule.Category
		if rule.Kind == crs.KindDetection {
			h.Score = rule.Score
		}
		if h.PL == 0 {
			h.PL = rule.PL
		}
		if h.Severity == "" {
			h.Severity = rule.Severity
		}
	}
	if h.Kind == "" {
		h.Kind = "unknown"
	}
	return h
}

// computeScores sums the anomaly score that the recorded policy would have
// counted (blocking PL) and the score of every recorded rule (detection PL).
func (e *Event) computeScores() {
	bpl, _, _, _ := e.Thresholds()
	e.ScoreIn, e.ScoreOut, e.DetectIn = 0, 0, 0
	for _, h := range e.Hits {
		if h.Kind != crs.KindDetection {
			continue
		}
		pl := h.PL
		if pl == 0 {
			pl = 1
		}
		switch h.Dir {
		case crs.DirOutbound:
			if pl <= bpl {
				e.ScoreOut += h.Score
			}
		default:
			e.DetectIn += h.Score
			if pl <= bpl {
				e.ScoreIn += h.Score
			}
		}
	}
}

// classify derives the action. A blocked event was interrupted; a
// would-block event reached a blocking decision without interruption
// (DetectionOnly); anything else is a sub-threshold detection.
func (e *Event) classify(directBlock bool) string {
	if e.Interrupted {
		return ActionBlocked
	}
	for _, h := range e.Hits {
		if h.Kind == crs.KindDecision {
			return ActionWouldBlock
		}
	}
	if directBlock {
		return ActionWouldBlock
	}
	_, _, in, out := e.Thresholds()
	if strings.EqualFold(e.Engine, "DetectionOnly") && (e.ScoreIn >= in || e.ScoreOut >= out) {
		return ActionWouldBlock
	}
	return ActionDetected
}

// disruptiveLog reports whether Coraza's error log line names a disruptive
// action ("Coraza: Access denied (phase 2). ..."); it also does so in
// DetectionOnly, where the action is recorded but not enforced.
func disruptiveLog(line string) bool {
	return strings.Contains(line, "Coraza: Access denied") || strings.Contains(line, "Coraza: Access dropped") ||
		strings.Contains(line, "Coraza: Access redirected")
}

func interrupted(flag *bool, legacyAction string) bool {
	if flag != nil {
		return *flag
	}
	switch strings.ToLower(strings.TrimSpace(legacyAction)) {
	case "deny", "drop", "redirect":
		return true
	}
	return false
}

// recordTime prefers unix_timestamp (nanoseconds in Coraza v3, seconds in
// older writers) and falls back to the formatted timestamp.
func recordTime(ts string, unix int64) time.Time {
	switch {
	case unix > 1e17:
		return time.Unix(0, unix).UTC()
	case unix > 1e14:
		return time.UnixMicro(unix).UTC()
	case unix > 1e11:
		return time.UnixMilli(unix).UTC()
	case unix > 0:
		return time.Unix(unix, 0).UTC()
	}
	for _, layout := range []string{"2006/01/02 15:04:05", "02/Jan/2006:15:04:05 -0700", time.RFC3339Nano} {
		if t, err := time.Parse(layout, ts); err == nil {
			return t.UTC()
		}
	}
	return time.Now().UTC()
}

// splitURI returns the decoded path (as Coraza's REQUEST_FILENAME) and the
// sorted query parameter names; values are never stored.
func splitURI(uri string) (string, []string) {
	path := uri
	query := ""
	if u, err := url.ParseRequestURI(uri); err == nil {
		path, query = u.Path, u.RawQuery
	} else if i := strings.IndexByte(uri, '?'); i >= 0 {
		path, query = uri[:i], uri[i+1:]
	}
	path = truncate(path, maxPathLen)
	if query == "" {
		return path, nil
	}
	seen := map[string]bool{}
	var keys []string
	for _, pair := range strings.Split(query, "&") {
		key, _, _ := strings.Cut(pair, "=")
		if k, err := url.QueryUnescape(key); err == nil {
			key = k
		}
		key = truncate(key, 64)
		if key == "" || seen[key] {
			continue
		}
		seen[key] = true
		keys = append(keys, key)
	}
	sort.Strings(keys)
	if len(keys) > maxQueryKeys {
		keys = keys[:maxQueryKeys]
	}
	return path, keys
}

// splitLogdata extracts the variable, matched fragment and value from the
// CRS logdata format "Matched Data: X found within VAR: VALUE".
func splitLogdata(logdata string) (variable, data, value string) {
	if !matchedData.MatchString(logdata) {
		return "", truncate(logdata, maxDataLen), ""
	}
	rest := strings.TrimPrefix(logdata, "Matched Data: ")
	loc := foundWithin.FindStringSubmatchIndex(rest)
	if loc == nil {
		return "", truncate(rest, maxDataLen), ""
	}
	return rest[loc[2]:loc[3]], truncate(rest[:loc[0]], maxDataLen), truncate(rest[loc[1]:], maxValueLen)
}

func severityName(raw json.RawMessage) string {
	text := strings.TrimSpace(string(raw))
	if text == "" || text == "null" {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return crs.SeverityName(s)
	}
	if n, err := strconv.Atoi(text); err == nil && n < 0 {
		return "" // Coraza writes -1 for rules without a severity
	}
	return crs.SeverityName(text)
}

func crsVersion(rulesets []string, rec *auditRecord) string {
	for _, name := range rulesets {
		if m := crsVersionTag.FindStringSubmatch(name); m != nil {
			return m[1]
		}
	}
	for _, m := range rec.Messages {
		if m.Data != nil {
			if v := crsVersionTag.FindStringSubmatch(m.Data.Ver); v != nil {
				return v[1]
			}
		}
	}
	return ""
}

func headerValue(headers map[string][]string, name string) string {
	for k, v := range headers {
		if strings.EqualFold(k, name) && len(v) > 0 {
			return v[0]
		}
	}
	return ""
}

// truncate bounds a string on a UTF-8 boundary.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	cut := n
	for cut > 0 && !utf8RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "…"
}

func utf8RuneStart(b byte) bool { return b&0xC0 != 0x80 }
