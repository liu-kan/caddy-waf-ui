// Package events turns Coraza audit records into compact, redacted WAF
// events, stores them locally (daily JSON lines kept for a retention window,
// plus long-term daily rollups) and answers the queries behind the event,
// rule and analysis pages. The same event files are what Alloy ships to
// Grafana Cloud Loki, so local and remote history share one schema.
package events

import (
	"strconv"
	"strings"
	"time"
)

// Event actions.
const (
	// ActionBlocked: Coraza interrupted the transaction.
	ActionBlocked = "blocked"
	// ActionWouldBlock: DetectionOnly matched a blocking decision (the
	// request would have been blocked in On mode).
	ActionWouldBlock = "would_block"
	// ActionDetected: rules matched without reaching a blocking decision
	// (sub-threshold matches, recorded in tuning mode).
	ActionDetected = "detected"
)

// SchemaVersion is the event schema version written in "v".
const SchemaVersion = 1

// Hit is one rule match (one matched variable) of an event.
type Hit struct {
	ID       int    `json:"id"`
	Var      string `json:"var,omitempty"`
	Data     string `json:"data,omitempty"`
	Value    string `json:"value,omitempty"`
	Msg      string `json:"msg,omitempty"`
	Severity string `json:"sev,omitempty"`
	PL       int    `json:"pl,omitempty"`
	Dir      string `json:"dir,omitempty"`
	Score    int    `json:"score,omitempty"`
	Kind     string `json:"kind,omitempty"`
	Category string `json:"cat,omitempty"`
}

// Event is one audited transaction.
type Event struct {
	Kind        string    `json:"kind"`
	V           int       `json:"v"`
	TS          time.Time `json:"ts"`
	TxID        string    `json:"tx"`
	Node        string    `json:"node,omitempty"`
	Site        string    `json:"site"`
	Host        string    `json:"host,omitempty"`
	ClientIP    string    `json:"ip"`
	Method      string    `json:"method,omitempty"`
	Path        string    `json:"path,omitempty"`
	QueryKeys   []string  `json:"qkeys,omitempty"`
	Status      int       `json:"status,omitempty"`
	Interrupted bool      `json:"interrupted"`
	Engine      string    `json:"engine,omitempty"`
	Action      string    `json:"action"`
	Mode        string    `json:"mode,omitempty"`
	Revision    string    `json:"rev,omitempty"`
	BlockingPL  int       `json:"bpl,omitempty"`
	DetectionPL int       `json:"dpl,omitempty"`
	ThrIn       int       `json:"thr_in,omitempty"`
	ThrOut      int       `json:"thr_out,omitempty"`
	Tuning      bool      `json:"tune,omitempty"`
	ScoreIn     int       `json:"score_in"`
	ScoreOut    int       `json:"score_out"`
	DetectIn    int       `json:"det_in,omitempty"`
	ReportedIn  int       `json:"reported_in,omitempty"`
	ReportedOut int       `json:"reported_out,omitempty"`
	CRS         string    `json:"crs,omitempty"`
	RuleIDs     string    `json:"rule_ids_csv"`
	Hits        []Hit     `json:"hits"`
	Source      string    `json:"source,omitempty"`
}

// HasRule reports whether the event matched rule id.
func (e *Event) HasRule(id int) bool {
	return strings.Contains(e.RuleIDs, ","+strconv.Itoa(id)+",")
}

// Thresholds returns the effective policy recorded with the event, with CRS
// defaults for events produced without a UI signature.
func (e *Event) Thresholds() (bpl, dpl, in, out int) {
	bpl, dpl, in, out = e.BlockingPL, e.DetectionPL, e.ThrIn, e.ThrOut
	if bpl == 0 {
		bpl = 1
	}
	if dpl < bpl {
		dpl = bpl
	}
	if in == 0 {
		in = 5
	}
	if out == 0 {
		out = 4
	}
	return bpl, dpl, in, out
}

// Categories returns the distinct attack categories of the detection hits.
func (e *Event) Categories() []string {
	seen := map[string]bool{}
	var out []string
	for _, h := range e.Hits {
		if h.Category == "" || h.Kind != "detection" || seen[h.Category] {
			continue
		}
		seen[h.Category] = true
		out = append(out, h.Category)
	}
	return out
}
