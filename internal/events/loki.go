package events

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// LokiClient reads shipped events back from Loki (Grafana Cloud). It only
// needs a token with the logs:read scope; writes go through Alloy.
type LokiClient struct {
	URL      string
	User     string
	Token    string
	Selector string
	HTTP     *http.Client
}

// Configured reports whether Loki history is enabled.
func (c *LokiClient) Configured() bool {
	return c != nil && c.URL != "" && c.Token != ""
}

type lokiEntry struct {
	TS   time.Time
	Line string
}

type lokiResponse struct {
	Status string `json:"status"`
	Data   struct {
		Result []struct {
			Values [][2]string `json:"values"`
		} `json:"result"`
	} `json:"data"`
}

// maxLokiLimit is the Grafana Cloud limit of entries per query.
const maxLokiLimit = 5000

// queryRange runs one /loki/api/v1/query_range request (direction forward).
func (c *LokiClient) queryRange(ctx context.Context, query string, start, end time.Time, limit int) ([]lokiEntry, error) {
	base, err := url.Parse(strings.TrimRight(c.URL, "/"))
	if err != nil || (base.Scheme != "https" && base.Scheme != "http") || base.Host == "" || base.User != nil {
		return nil, fmt.Errorf("invalid CADDY_UI_LOKI_URL")
	}
	params := url.Values{}
	params.Set("query", query)
	params.Set("start", strconv.FormatInt(start.UnixNano(), 10))
	params.Set("end", strconv.FormatInt(end.UnixNano(), 10))
	params.Set("limit", strconv.Itoa(limit))
	params.Set("direction", "forward")
	endpoint := base.JoinPath("loki", "api", "v1", "query_range")
	endpoint.RawQuery = params.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(c.User, c.Token)
	client := c.HTTP
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	resp, err := client.Do(req) //nolint:gosec // G704: operator-configured Loki endpoint (CADDY_UI_LOKI_URL), validated above.
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("loki query_range: HTTP %d: %s", resp.StatusCode, truncate(string(body), 300))
	}
	var parsed lokiResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, fmt.Errorf("loki query_range: %w", err)
	}
	var out []lokiEntry
	for _, stream := range parsed.Data.Result {
		for _, v := range stream.Values {
			ns, err := strconv.ParseInt(v[0], 10, 64)
			if err != nil {
				continue
			}
			out = append(out, lokiEntry{TS: time.Unix(0, ns).UTC(), Line: v[1]})
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].TS.Before(out[j].TS) })
	return out, nil
}

// BackfillResult reports one import run.
type BackfillResult struct {
	From, To time.Time
	Fetched  int
	Imported int
	Queries  int
}

// Backfill imports shipped events between from and to that the store does
// not hold yet (other nodes, or history lost with a local volume). Queries
// cover at most one day and page forward by the last timestamp received.
func Backfill(ctx context.Context, c *LokiClient, store *Store, from, to time.Time) (BackfillResult, error) {
	res := BackfillResult{From: from, To: to}
	if !c.Configured() {
		return res, errors.New("loki is not configured (CADDY_UI_LOKI_URL, CADDY_UI_LOKI_TOKEN)")
	}
	selector := c.Selector
	if selector == "" {
		selector = `{job="caddy-waf-ui",kind="event"}`
	}
	for windowStart := from; windowStart.Before(to); windowStart = windowStart.Add(24 * time.Hour) {
		windowEnd := windowStart.Add(24 * time.Hour)
		if windowEnd.After(to) {
			windowEnd = to
		}
		cursor := windowStart
		for {
			if err := ctx.Err(); err != nil {
				return res, err
			}
			entries, err := c.queryRange(ctx, selector, cursor, windowEnd, maxLokiLimit)
			res.Queries++
			if err != nil {
				return res, err
			}
			res.Fetched += len(entries)
			newOnPage := 0
			for _, entry := range entries {
				var e Event
				if json.Unmarshal([]byte(entry.Line), &e) != nil || e.TxID == "" || e.Kind != "event" {
					continue
				}
				if e.Hits == nil {
					e.Hits = []Hit{}
				}
				added, err := store.Append(&e, SourceLoki)
				if err != nil {
					return res, err
				}
				if added {
					res.Imported++
					newOnPage++
				}
			}
			if len(entries) < maxLokiLimit {
				break
			}
			last := entries[len(entries)-1].TS
			if !last.After(cursor) && newOnPage == 0 {
				break // a full page at one timestamp: nothing more to learn
			}
			cursor = last
		}
	}
	return res, nil
}

// ExploreLink builds a Grafana Explore URL showing the event's log line.
func ExploreLink(grafanaURL, datasource, selector string, e *Event) string {
	if grafanaURL == "" || e == nil {
		return ""
	}
	if selector == "" {
		selector = `{job="caddy-waf-ui",kind="event"}`
	}
	expr := selector + ` |= "` + strings.ReplaceAll(e.TxID, `"`, ``) + `"`
	panes := map[string]any{"a": map[string]any{
		"datasource": datasource,
		"queries": []map[string]any{{
			"refId": "A", "expr": expr, "queryType": "range",
			"datasource": map[string]string{"type": "loki", "uid": datasource},
		}},
		"range": map[string]string{
			"from": strconv.FormatInt(e.TS.Add(-5*time.Minute).UnixMilli(), 10),
			"to":   strconv.FormatInt(e.TS.Add(5*time.Minute).UnixMilli(), 10),
		},
	}}
	data, err := json.Marshal(panes)
	if err != nil {
		return ""
	}
	u, err := url.Parse(strings.TrimRight(grafanaURL, "/") + "/explore")
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") {
		return ""
	}
	q := url.Values{}
	q.Set("schemaVersion", "1")
	q.Set("panes", string(data))
	q.Set("orgId", "1")
	u.RawQuery = q.Encode()
	return u.String()
}
