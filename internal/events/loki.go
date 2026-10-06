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
	return c.queryDirection(ctx, query, start, end, limit, "forward")
}

func (c *LokiClient) queryDirection(ctx context.Context, query string, start, end time.Time, limit int, direction string) ([]lokiEntry, error) {
	base, err := url.Parse(strings.TrimRight(c.URL, "/"))
	if err != nil || (base.Scheme != "https" && base.Scheme != "http") || base.Host == "" || base.User != nil {
		return nil, fmt.Errorf("invalid CADDY_UI_LOKI_URL")
	}
	params := url.Values{}
	params.Set("query", query)
	params.Set("start", strconv.FormatInt(start.UnixNano(), 10))
	params.Set("end", strconv.FormatInt(end.UnixNano()-1, 10))
	params.Set("limit", strconv.Itoa(limit))
	params.Set("direction", direction)
	endpoint := base.JoinPath("loki", "api", "v1", "query_range")
	endpoint.RawQuery = params.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(c.User, c.Token)
	client := c.HTTP
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	resp, err := client.Do(req) //nolint:gosec // G704: operator-configured Loki endpoint (CADDY_UI_LOKI_URL), validated above.
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, (16<<20)+1))
	if err != nil {
		return nil, err
	}
	if len(body) > 16<<20 {
		return nil, errors.New("loki response exceeds the 16 MiB memory budget; narrow the query")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("loki query_range: HTTP %d: %s", resp.StatusCode, truncate(string(body), 300))
	}
	var parsed lokiResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, fmt.Errorf("loki query_range: %w", err)
	}
	if parsed.Status != "success" {
		return nil, errors.New("loki returned an unsuccessful query status")
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
	if !from.Before(to) || to.Sub(from) > 31*24*time.Hour {
		return res, errors.New("invalid Loki import range (maximum 31 days)")
	}
	var importWindow func(time.Time, time.Time) error
	importWindow = func(start, end time.Time) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if res.Queries >= 128 {
			return fmt.Errorf("%w: query budget reached; narrow the range", ErrIncompleteHistory)
		}
		entries, err := c.queryRange(ctx, selector, start, end, maxLokiLimit)
		res.Queries++
		if err != nil {
			return err
		}
		res.Fetched += len(entries)
		for _, entry := range entries {
			e, err := DecodeEventLine(entry.Line, entry.TS)
			if err != nil {
				return err
			}
			added, err := store.Append(e, SourceLoki)
			if err != nil {
				return err
			}
			if added {
				res.Imported++
			}
		}
		if len(entries) < maxLokiLimit {
			return nil
		}
		if entries[0].TS.Equal(entries[len(entries)-1].TS) {
			return fmt.Errorf("%w: at least %d entries share timestamp %s", ErrIncompleteHistory, maxLokiLimit, entries[0].TS.Format(time.RFC3339Nano))
		}
		if end.Sub(start) <= time.Nanosecond {
			return ErrIncompleteHistory
		}
		mid := start.Add(end.Sub(start) / 2)
		if err := importWindow(start, mid); err != nil {
			return err
		}
		return importWindow(mid, end)
	}
	for start := from; start.Before(to); start = start.Add(24 * time.Hour) {
		end := start.Add(24 * time.Hour)
		if end.After(to) {
			end = to
		}
		if err := importWindow(start, end); err != nil {
			return res, err
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
