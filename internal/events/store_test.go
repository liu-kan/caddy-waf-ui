package events

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/developmi/caddy-waf-ui/internal/crs"
)

func newStore(t *testing.T) (*Store, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "events")
	s, err := OpenStore(dir, 14*24*time.Hour, 1000)
	if err != nil {
		t.Fatal(err)
	}
	return s, dir
}

func event(tx string, ts time.Time, site, action, ip, path string, rules ...int) *Event {
	e := &Event{Kind: "event", V: 1, TxID: tx, TS: ts, Site: site, Action: action, ClientIP: ip, Path: path, Hits: []Hit{}}
	ids := ","
	for _, id := range rules {
		e.Hits = append(e.Hits, Hit{ID: id, Kind: crs.KindDetection, Dir: crs.DirInbound, Score: 5, PL: 1, Category: "sqli"})
		ids += fmt.Sprintf("%d,", id)
	}
	e.RuleIDs = ids
	return e
}

func TestStoreAppendQueryAndReload(t *testing.T) {
	s, dir := newStore(t)
	now := time.Now().UTC()
	added := 0
	s.OnAdd = func(*Event) { added++ }
	for i, e := range []*Event{
		event("a", now.Add(-3*time.Hour), "a.com", ActionBlocked, "1.1.1.1", "/login", 942100),
		event("b", now.Add(-2*time.Hour), "b.com", ActionDetected, "2.2.2.2", "/search", 941100),
		event("c", now.Add(-1*time.Hour), "a.com", ActionWouldBlock, "1.1.1.1", "/api/x", 942100, 949110),
	} {
		ok, err := s.Append(e, SourceLocal)
		if err != nil || !ok {
			t.Fatalf("append %d: %v %v", i, ok, err)
		}
	}
	if ok, _ := s.Append(event("a", now, "a.com", ActionBlocked, "1.1.1.1", "/"), SourceLocal); ok {
		t.Fatal("duplicate transactions must be ignored")
	}
	if added != 3 {
		t.Fatalf("OnAdd ran %d times", added)
	}
	got, total := s.Query(Query{Site: "a.com"})
	if total != 2 || got[0].TxID != "c" || got[1].TxID != "a" {
		t.Fatalf("newest first by site: %v", got)
	}
	if _, total := s.Query(Query{RuleID: 942100, IP: "1.1.1.1", Action: ActionBlocked}); total != 1 {
		t.Fatalf("rule+ip+action filter: %d", total)
	}
	if _, total := s.Query(Query{PathPrefix: "/api/"}); total != 1 {
		t.Fatal("path prefix filter")
	}
	if _, total := s.Query(Query{Text: "SEARCH"}); total != 1 {
		t.Fatal("text filter is case-insensitive")
	}
	if _, total := s.Query(Query{From: now.Add(-90 * time.Minute)}); total != 1 {
		t.Fatal("time filter")
	}
	page, total := s.Query(Query{Limit: 1, Offset: 1})
	if total != 3 || len(page) != 1 || page[0].TxID != "b" {
		t.Fatalf("pagination: %v %d", page, total)
	}
	// Imported (older) events are ordered by time and written separately.
	if ok, err := s.Append(event("old", now.Add(-48*time.Hour), "c.com", ActionBlocked, "3.3.3.3", "/"), SourceLoki); !ok || err != nil {
		t.Fatal(err)
	}
	if w := s.Window(Query{}); w[0].TxID != "old" || len(w) != 4 {
		t.Fatalf("window order: %v", w)
	}
	names, _ := filepath.Glob(filepath.Join(dir, "*.jsonl"))
	var imported, local int
	for _, n := range names {
		if strings.HasPrefix(filepath.Base(n), importedPrefix) {
			imported++
		} else {
			local++
		}
	}
	if imported != 1 || local < 1 {
		t.Fatalf("files: %v", names)
	}
	if err := s.Rollups().Flush(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenStore(dir, 14*24*time.Hour, 1000)
	if err != nil {
		t.Fatal(err)
	}
	if st := reopened.Stats(); st.Count != 4 {
		t.Fatalf("reload: %+v", st)
	}
	if e, ok := reopened.Get("c"); !ok || e.Hits[0].ID != 942100 {
		t.Fatal("get after reload")
	}
	rows := reopened.Rollups().Range(now.Add(-72*time.Hour), now, "a.com")
	var total942, events int64
	for _, r := range rows {
		if r.Rule == 942100 {
			total942 += r.Count
		}
		if r.Rule == 0 {
			events += r.Count
		}
	}
	if total942 != 2 || events != 2 {
		t.Fatalf("rollups: %+v", rows)
	}
}

func TestStoreRetentionAndMemoryBound(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "events")
	s, err := OpenStore(dir, 48*time.Hour, 2)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if ok, _ := s.Append(event("expired", now.Add(-96*time.Hour), "a.com", ActionBlocked, "1.1.1.1", "/"), SourceLocal); ok {
		t.Fatal("events older than retention are not stored")
	}
	for i := 0; i < 3; i++ {
		if _, err := s.Append(event(fmt.Sprint(i), now.Add(time.Duration(i)*time.Minute), "a.com", ActionBlocked, "1.1.1.1", "/"), SourceLocal); err != nil {
			t.Fatal(err)
		}
	}
	if st := s.Stats(); st.Count != 2 || !s.Has("0") {
		t.Fatalf("memory bound: %+v", st)
	}
	stale := filepath.Join(dir, "events-2000-01-01.jsonl")
	if err := os.WriteFile(stale, []byte("{}\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := s.Prune(now); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Fatal("expired files must be deleted")
	}
}

func TestBackfillImportsMissingEventsAcrossPages(t *testing.T) {
	s, _ := newStore(t)
	now := time.Now().UTC().Truncate(time.Second)
	if _, err := s.Append(event("local", now.Add(-time.Hour), "a.com", ActionBlocked, "1.1.1.1", "/"), SourceLocal); err != nil {
		t.Fatal(err)
	}
	var lines []string
	for i := 0; i < 3; i++ {
		e := event(fmt.Sprintf("remote-%d", i), now.Add(-time.Duration(50-i)*time.Minute), "b.com", ActionDetected, "9.9.9.9", "/")
		data, _ := json.Marshal(e)
		lines = append(lines, string(data))
	}
	dup, _ := json.Marshal(event("local", now.Add(-time.Hour), "a.com", ActionBlocked, "1.1.1.1", "/"))
	lines = append(lines, string(dup))
	var queries []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, _ := r.BasicAuth()
		if r.URL.Path != "/loki/api/v1/query_range" || user != "123" || pass != "glc_token" {
			http.Error(w, "unexpected", http.StatusUnauthorized)
			return
		}
		queries = append(queries, r.URL.Query().Get("query"))
		var values [][2]string
		for _, l := range lines {
			var e Event
			_ = json.Unmarshal([]byte(l), &e)
			if ns := e.TS.UnixNano(); fmt.Sprint(ns) >= r.URL.Query().Get("start") && fmt.Sprint(ns) <= r.URL.Query().Get("end") {
				values = append(values, [2]string{fmt.Sprint(ns), l})
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "success", "data": map[string]any{
			"resultType": "streams", "result": []map[string]any{{"stream": map[string]string{"job": "caddy-waf-ui"}, "values": values}}}})
	}))
	defer server.Close()
	client := &LokiClient{URL: server.URL, User: "123", Token: "glc_token"}
	res, err := Backfill(context.Background(), client, s, now.Add(-2*time.Hour), now)
	if err != nil {
		t.Fatal(err)
	}
	if res.Imported != 3 || res.Fetched != 4 {
		t.Fatalf("backfill: %+v", res)
	}
	if e, ok := s.Get("remote-1"); !ok || e.Source != SourceLoki {
		t.Fatal("imported event not stored as loki source")
	}
	if len(queries) == 0 || queries[0] != `{job="caddy-waf-ui",kind="event"}` {
		t.Fatalf("selector: %v", queries)
	}
	if _, err := Backfill(context.Background(), &LokiClient{}, s, now, now); err == nil {
		t.Fatal("unconfigured Loki must fail")
	}
	bad := &LokiClient{URL: "ftp://x", Token: "t"}
	if _, err := Backfill(context.Background(), bad, s, now.Add(-time.Hour), now); err == nil {
		t.Fatal("invalid Loki URL must fail")
	}
}

func TestExploreLink(t *testing.T) {
	e := event("tx-1", time.Unix(1791242354, 0).UTC(), "a.com", ActionBlocked, "1.1.1.1", "/")
	link := ExploreLink("https://stack.grafana.net/", "grafanacloud-logs", "", e)
	if !strings.HasPrefix(link, "https://stack.grafana.net/explore?") || !strings.Contains(link, "tx-1") || !strings.Contains(link, "grafanacloud-logs") {
		t.Fatalf("link: %s", link)
	}
	if ExploreLink("", "x", "", e) != "" || ExploreLink("javascript:alert(1)", "x", "", e) != "" {
		t.Fatal("unsafe or missing Grafana URL must not produce a link")
	}
}
