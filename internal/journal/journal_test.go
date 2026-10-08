package journal

import (
	"os"
	"strings"
	"testing"
	"time"
)

func TestAppendAndList(t *testing.T) {
	t.Setenv("CADDY_UI_DATA_DIR", t.TempDir())
	t.Setenv("CADDY_UI_NODE", "node-a")
	if entries, err := List(Filter{}); err != nil || entries != nil {
		t.Fatalf("missing journal must be empty: %v %v", entries, err)
	}
	base := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	for i, site := range []string{"a.com", "b.com", "a.com"} {
		e := Entry{TS: base.Add(time.Duration(i) * time.Minute), Site: site, Action: "mode", Summary: "x", Result: ResultSuccess}
		if i == 2 {
			e.Diff = strings.Repeat("x", maxDiffBytes+10)
		}
		if err := Append(e); err != nil {
			t.Fatal(err)
		}
	}
	// A torn line (crash during write) must not hide the history.
	f, err := os.OpenFile(Path(), os.O_APPEND|os.O_WRONLY, 0o640)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.WriteString(`{"kind":"change","ts":`)
	_ = f.Close()
	entries, err := List(Filter{Site: "a.com", Limit: 10})
	if err != nil || len(entries) != 2 {
		t.Fatalf("filter: %+v %v", entries, err)
	}
	if !entries[0].TS.After(entries[1].TS) || entries[0].Kind != "change" || entries[0].Node != "node-a" {
		t.Fatalf("newest first with kind and node: %+v", entries)
	}
	if !strings.HasSuffix(entries[0].Diff, "(diff truncated)") {
		t.Fatal("long diffs are truncated")
	}
	if all, _ := List(Filter{Limit: 1}); len(all) != 1 {
		t.Fatal("limit")
	}
}

// TestJournalRotatesAndKeepsOnePreviousGeneration: maintenance and IP group
// refreshes append entries continuously, so the journal is bounded: past
// maxJournalBytes the file becomes changes.jsonl.1 (replacing the previous
// generation) and the history reads both files.
func TestJournalRotatesAndKeepsOnePreviousGeneration(t *testing.T) {
	t.Setenv("CADDY_UI_DATA_DIR", t.TempDir())
	prev := maxJournalBytes
	maxJournalBytes = 2 << 10
	t.Cleanup(func() { maxJournalBytes = prev })

	base := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	const n = 200
	for i := 0; i < n; i++ {
		e := Entry{TS: base.Add(time.Duration(i) * time.Second), Site: "a.com", Action: "maintenance", Summary: strings.Repeat("s", 100), Result: ResultSuccess}
		if err := Append(e); err != nil {
			t.Fatal(err)
		}
	}
	var currentSize int64 // the last append may have rotated the file away
	if current, err := os.Stat(Path()); err == nil {
		currentSize = current.Size()
	} else if !os.IsNotExist(err) {
		t.Fatal(err)
	}
	previous, err := os.Stat(Path() + ".1")
	if err != nil {
		t.Fatalf("the previous generation must exist: %v", err)
	}
	if currentSize > maxJournalBytes || previous.Size() > maxJournalBytes+512 {
		t.Fatalf("journal files exceed the bound: %d and %d bytes", currentSize, previous.Size())
	}
	entries, err := List(Filter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) == 0 || len(entries) >= n {
		t.Fatalf("expected a bounded history, got %d entries", len(entries))
	}
	if !entries[0].TS.Equal(base.Add((n - 1) * time.Second)) {
		t.Fatalf("the newest entry must be kept, got %v", entries[0].TS)
	}
	if lines := strings.Count(readFile(t, Path()), "\n") + strings.Count(readFile(t, Path()+".1"), "\n"); lines != len(entries) {
		t.Fatalf("history must include both generations: %d lines, %d entries", lines, len(entries))
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	return string(b)
}
