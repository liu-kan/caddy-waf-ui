package events

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestCloudCursorDoesNotLoseEventsSharingTimestamp(t *testing.T) {
	now := time.Now().UTC()
	var all [][2]string
	for i := 0; i < 7; i++ {
		e := event(fmt.Sprint(i), now, "example.com", ActionBlocked, "203.0.113.1", "/", 930130, 949110)
		e.Node = "origin"
		b, _ := json.Marshal(e)
		all = append(all, [2]string{strconv.FormatInt(now.UnixNano(), 10), string(b)})
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if strings.Contains(q.Get("query"), `\"\"`) {
			t.Error("invalid escaped LogQL string")
		}
		limit, _ := strconv.Atoi(q.Get("limit"))
		if limit > len(all) {
			limit = len(all)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "success", "data": map[string]any{"result": []any{map[string]any{"values": all[:limit]}}}})
	}))
	defer server.Close()
	c := &LokiClient{URL: server.URL, Token: "test"}
	q := Query{From: now.Add(-time.Second), To: now.Add(time.Second), Limit: 2}
	cursor := ""
	seen := map[string]bool{}
	for page := 0; page < 10; page++ {
		p, err := c.Search(context.Background(), q, cursor)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range p.Events {
			if seen[e.Key()] {
				t.Fatal("duplicate across cloud pages")
			}
			seen[e.Key()] = true
		}
		cursor = p.Next
		if cursor == "" {
			break
		}
	}
	if len(seen) != len(all) {
		t.Fatalf("received %d of %d", len(seen), len(all))
	}
}

func TestAppendAfterTornRecordKeepsNextEventReadable(t *testing.T) {
	dir := t.TempDir()
	now := time.Now().UTC()
	name := filepath.Join(dir, "events-"+now.Format("2006-01-02")+".jsonl")
	if err := os.WriteFile(name, []byte(`{"kind":"event","tx":"torn`), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := OpenStore(dir, 24*time.Hour, 1)
	if err != nil {
		t.Fatal(err)
	}
	e := event("complete", now, "example.com", ActionBlocked, "", "/", 930130)
	if _, err := s.Append(e, SourceLocal); err != nil {
		t.Fatal(err)
	}
	s, err = OpenStore(dir, 24*time.Hour, 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := s.Get("complete"); !ok {
		t.Fatal("complete event lost after torn append")
	}
}
func TestRetainedIndexSeparatesNodesAndSurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	now := time.Now().UTC()
	s, _ := OpenStore(dir, 24*time.Hour, 1)
	for _, node := range []string{"a", "b"} {
		e := event("same", now, "example.com", ActionBlocked, "", "/", 930130)
		e.Node = node
		if added, err := s.Append(e, SourceLocal); err != nil || !added {
			t.Fatal(added, err)
		}
	}
	s, _ = OpenStore(dir, 24*time.Hour, 1)
	if _, ok := s.Get("same"); ok {
		t.Fatal("ambiguous id must not select a node silently")
	}
	if e, ok := s.GetFor("same", "a"); !ok || e.Node != "a" {
		t.Fatal("evicted event unavailable after restart")
	}
	if added, err := s.Append(&Event{Kind: "event", TxID: "same", Node: "a", TS: now}, SourceLoki); added || err != nil {
		t.Fatal("durable duplicate admitted")
	}
}
