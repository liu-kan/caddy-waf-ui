package events

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/developmi/caddy-waf-ui/internal/crs"
)

// ErrIncompleteHistory is explicit: importing a full page is not proof
// that the requested time interval was completely retrieved.
var ErrIncompleteHistory = errors.New("incomplete Loki history")

type HistoryPage struct {
	Events  []*Event  `json:"events"`
	Next    string    `json:"next_cursor,omitempty"`
	More    bool      `json:"more"`
	Warning string    `json:"warning,omitempty"`
	From    time.Time `json:"from"`
	To      time.Time `json:"to"`
}
type historyCursor struct {
	End  int64    `json:"end"`
	Seen []string `json:"seen"`
}

// DecodeEventLine accepts the normalized event contract. Legacy CSV ids
// without delimiter guards are canonicalized before exact rule filtering.
func DecodeEventLine(line string, ts time.Time) (*Event, error) {
	var e Event
	if err := json.Unmarshal([]byte(line), &e); err != nil {
		return nil, fmt.Errorf("decode Loki event: %w", err)
	}
	if e.Kind != "event" || e.TxID == "" || e.V > SchemaVersion {
		return nil, errors.New("loki selector returned unsupported events; collect normalized events-*.jsonl")
	}
	if e.TS.IsZero() {
		e.TS = ts
	}
	if e.Hits == nil {
		e.Hits = []Hit{}
	}
	ids := crs.ParseIDs(e.RuleIDs)
	if len(ids) > 0 {
		parts := make([]string, 0, len(ids))
		for _, id := range ids {
			parts = append(parts, strconv.Itoa(id))
		}
		e.RuleIDs = "," + strings.Join(parts, ",") + ","
	}
	if len(e.Hits) == 0 && len(ids) > 0 {
		e.HitsIncomplete = true
		for _, id := range ids {
			e.Hits = append(e.Hits, Hit{ID: id, Kind: "unknown"})
		}
	}
	e.Source = SourceLoki
	return &e, nil
}

func (c *LokiClient) selectorQuery(q Query, tx, node string) string {
	selector := c.Selector
	if selector == "" {
		selector = `{job="caddy-waf-ui",kind="event"}`
	}
	expr := selector + ` | json | __error__ = ""`
	for _, f := range [][2]string{{"site", q.Site}, {"action", q.Action}, {"ip", q.IP}, {"tx", tx}, {"node", node}} {
		if f[1] != "" {
			expr += " | " + f[0] + " = " + strconv.Quote(f[1])
		}
	}
	if q.RuleID > 0 {
		expr += ` | rule_ids_csv =~ ` + strconv.Quote("(^|.*,)"+strconv.Itoa(q.RuleID)+"(,.*|$)")
	}
	if q.PathPrefix != "" {
		expr += ` | path =~ ` + strconv.Quote("^"+regexpQuote(q.PathPrefix)+".*")
	}
	if q.Text != "" {
		expr += ` |~ ` + strconv.Quote("(?i)"+regexpQuote(q.Text))
	}
	return expr
}

func regexpQuote(s string) string {
	var b strings.Builder
	for _, r := range s {
		if strings.ContainsRune(`\.+*?()|[]{}^$`, r) {
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}

// Search queries cloud storage directly; no imported copy or startup
// backfill is necessary. The cursor retains ids at a timestamp boundary.
func (c *LokiClient) Search(ctx context.Context, q Query, cursor string) (HistoryPage, error) {
	page := HistoryPage{From: q.From, To: q.To, Events: []*Event{}}
	if !c.Configured() {
		return page, errors.New("loki history is not configured")
	}
	if q.To.IsZero() {
		q.To = time.Now().UTC()
	}
	if q.From.IsZero() {
		q.From = q.To.Add(-24 * time.Hour)
	}
	page.From, page.To = q.From, q.To
	if !q.From.Before(q.To) || q.To.Sub(q.From) > 31*24*time.Hour {
		return page, errors.New("invalid history range (maximum 31 days)")
	}
	if q.Limit < 1 || q.Limit > 2000 {
		q.Limit = 50
	}
	var state historyCursor
	if cursor != "" {
		if len(cursor) > 1<<20 {
			return page, errors.New("history cursor too large")
		}
		raw, err := base64.RawURLEncoding.DecodeString(cursor)
		if err != nil || json.Unmarshal(raw, &state) != nil || len(state.Seen) > maxLokiLimit {
			return page, errors.New("invalid history cursor")
		}
		end := time.Unix(0, state.End)
		if !end.After(q.From) || end.After(q.To) {
			return page, errors.New("history cursor outside range")
		}
		q.To = end
	}
	seen := map[string]bool{}
	for _, key := range state.Seen {
		seen[key] = true
	}
	limit := q.Limit + len(state.Seen) + 1
	if limit > maxLokiLimit {
		limit = maxLokiLimit
	}
	entries, err := c.queryDirection(ctx, c.selectorQuery(q, "", ""), q.From, q.To, limit, "backward")
	if err != nil {
		return page, err
	}
	for i := len(entries) - 1; i >= 0; i-- {
		entry := entries[i]
		e, err := DecodeEventLine(entry.Line, entry.TS)
		if err != nil {
			return page, err
		}
		if seen[e.Key()] {
			continue
		}
		if !q.Match(e) {
			continue
		}
		seen[e.Key()] = true
		page.Events = append(page.Events, e)
		if len(page.Events) > q.Limit {
			page.More = true
			page.Events = page.Events[:q.Limit]
			break
		}
	}
	if len(entries) == limit && !page.More {
		page.Warning = ErrIncompleteHistory.Error() + ": duplicate or timestamp-boundary records filled this page; narrow the interval or node selector"
		return page, nil
	}
	if page.More && len(page.Events) > 0 {
		last := page.Events[len(page.Events)-1]
		next := historyCursor{End: last.TS.UnixNano() + 1}
		if next.End == state.End {
			next.Seen = append(next.Seen, state.Seen...)
		}
		for _, e := range page.Events {
			if e.TS.Equal(last.TS) {
				next.Seen = append(next.Seen, e.Key())
			}
		}
		raw, _ := json.Marshal(next)
		page.Next = base64.RawURLEncoding.EncodeToString(raw)
	}
	return page, nil
}

// Find returns a cloud event to the local detail page, optionally scoped
// by node and a tight time interval carried in the event link.
func (c *LokiClient) Find(ctx context.Context, tx, node string, ts time.Time) (*Event, error) {
	now := time.Now().UTC()
	q := Query{From: now.Add(-14 * 24 * time.Hour), To: now, Limit: 2}
	if !ts.IsZero() {
		q.From = ts.Add(-time.Minute)
		q.To = ts.Add(time.Minute)
	}
	entries, err := c.queryDirection(ctx, c.selectorQuery(q, tx, node), q.From, q.To, 2, "backward")
	if err != nil {
		return nil, err
	}
	var found *Event
	for _, entry := range entries {
		e, err := DecodeEventLine(entry.Line, entry.TS)
		if err != nil {
			return nil, err
		}
		if e.TxID != tx || (node != "" && e.Node != node) {
			continue
		}
		if found != nil && found.Key() != e.Key() {
			return nil, errors.New("transaction id is ambiguous; include its node")
		}
		found = e
	}
	if found == nil {
		return nil, errors.New("event not found in Loki")
	}
	return found, nil
}
