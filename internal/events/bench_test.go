package events

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/developmi/caddy-waf-ui/internal/crs"
)

// uniqueRecords returns n audit records with distinct transaction ids.
func uniqueRecords(t testing.TB, n int) []string {
	t.Helper()
	raw, err := os.ReadFile("testdata/coraza-3.8.0-audit.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	var base map[string]any
	if err := json.Unmarshal([]byte(strings.SplitN(string(raw), "\n", 2)[0]), &base); err != nil {
		t.Fatal(err)
	}
	out := make([]string, 0, n)
	for i := 0; i < n; i++ {
		tx := base["transaction"].(map[string]any)
		tx["id"] = fmt.Sprintf("bench-%06d", i)
		tx["unix_timestamp"] = time.Now().UnixNano()
		b, err := json.Marshal(base)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, string(b))
	}
	return out
}

// BenchmarkIngestPoll measures the ingestion of 500 audit records per poll.
func BenchmarkIngestPoll(b *testing.B) {
	lines := uniqueRecords(b, 500)
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		root := b.TempDir()
		store, err := OpenStore(filepath.Join(root, "events"), 24*time.Hour, 1000)
		if err != nil {
			b.Fatal(err)
		}
		logPath := filepath.Join(root, "audit.log")
		if err := os.WriteFile(logPath, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
			b.Fatal(err)
		}
		in := &Ingester{Path: logPath, StatePath: filepath.Join(root, "state.json"), Store: store, Norm: &Normalizer{Dict: crs.Default()}}
		b.StartTimer()
		if err := in.Poll(); err != nil {
			b.Fatal(err)
		}
	}
}
