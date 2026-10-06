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

	"github.com/developmi/caddy-waf-ui/internal/crs"
)

func TestReliabilityMemoryEvictionDedup(t *testing.T) {
	s, err := OpenStore(t.TempDir(), 14*24*time.Hour, 2)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	for i := 0; i < 3; i++ {
		e := &Event{Kind: "event", TxID: fmt.Sprint(i), TS: now.Add(time.Duration(i) * time.Nanosecond), Site: "example.com", Action: ActionBlocked}
		if _, err := s.Append(e, SourceLocal); err != nil {
			t.Fatal(err)
		}
	}
	e := &Event{Kind: "event", TxID: "0", TS: now, Site: "example.com", Action: ActionBlocked}
	added, err := s.Append(e, SourceLoki)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("reimport oldest already-stored event: added=%v", added)
	if added {
		t.Error("duplicate transaction counted again after memory eviction")
	}
}
func TestReliabilitySameTimestampPaging(t *testing.T) {
	s, err := OpenStore(t.TempDir(), 14*24*time.Hour, 10000)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	values := make([][2]string, 5001)
	for i := range values {
		b, _ := json.Marshal(Event{Kind: "event", TxID: fmt.Sprint(i), TS: now, Site: "example.com"})
		values[i] = [2]string{strconv.FormatInt(now.UnixNano(), 10), string(b)}
	}
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "success", "data": map[string]any{"result": []any{map[string]any{"values": values[:5000]}}}})
	}))
	defer srv.Close()
	c := &LokiClient{URL: srv.URL, Token: "test", HTTP: srv.Client()}
	res, err := Backfill(context.Background(), c, s, now.Add(-time.Second), now.Add(time.Second))
	t.Logf("5001 records at one timestamp: imported=%d queries=%d", res.Imported, calls)
	if res.Imported != 5001 && err == nil {
		t.Error("saturated timestamp must report incomplete history")
	}
}
func TestReliabilityRedactionFallback(t *testing.T) {
	n := &Normalizer{Dict: crs.Default()}
	raw := []byte(`{"transaction":{"id":"redact-test","unix_timestamp":1801690000000000000},"messages":[{"data":{"id":200002,"msg":"Failed parsing request body","data":"invalid body: secret=MY_PRIVATE_VALUE","severity":2}}]}`)
	e, err := n.Normalize(raw)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(e)
	if strings.Contains(string(b), "MY_PRIVATE_VALUE") {
		t.Error("unrecognized logdata leaked into event shipped to cloud")
	}
}
func TestReliabilityDiskContainsHistoricalButQueryDoesNot(t *testing.T) {
	s, _ := OpenStore(t.TempDir(), 14*24*time.Hour, 2)
	now := time.Now().UTC()
	for i := 0; i < 3; i++ {
		_, _ = s.Append(&Event{Kind: "event", TxID: fmt.Sprint(i), TS: now.Add(time.Duration(i) * time.Nanosecond), Site: "example.com"}, SourceLocal)
	}
	_, total := s.Query(Query{From: now.Add(-time.Hour)})
	b, err := os.ReadFile(filepath.Join(s.Dir(), "events-"+now.Format("2006-01-02")+".jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("history on disk=%d, visible through query=%d", strings.Count(string(b), "\n"), total)
	if total != 3 {
		t.Error("query silently limited by in-memory cache")
	}
}
