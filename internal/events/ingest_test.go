package events

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/developmi/caddy-waf-ui/internal/crs"
)

// fixtureLines returns the raw JSON records of the recorded audit log with
// current timestamps, so they stay inside the store's retention window.
func fixtureLines(t *testing.T) []string {
	t.Helper()
	f, err := os.Open("testdata/coraza-3.8.0-audit.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	var lines []string
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 4<<20)
	for scanner.Scan() {
		var rec map[string]any
		if err := json.Unmarshal(scanner.Bytes(), &rec); err != nil {
			t.Fatal(err)
		}
		rec["transaction"].(map[string]any)["unix_timestamp"] = time.Now().UnixNano()
		data, err := json.Marshal(rec)
		if err != nil {
			t.Fatal(err)
		}
		lines = append(lines, string(data))
	}
	return lines
}

func newIngester(t *testing.T, logPath string, store *Store) *Ingester {
	t.Helper()
	return &Ingester{Path: logPath, StatePath: filepath.Join(filepath.Dir(store.Dir()), "state", "ingest.json"),
		Store: store, Norm: &Normalizer{Dict: crs.Default()}}
}

func appendFile(t *testing.T, path, data string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o640)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(data); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestIngestPartialLinesAndRestart(t *testing.T) {
	store, _ := newStore(t)
	if err := os.MkdirAll(filepath.Join(filepath.Dir(store.Dir()), "state"), 0o750); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(t.TempDir(), "audit.log")
	lines := fixtureLines(t)
	half := len(lines[2]) / 2
	appendFile(t, logPath, lines[0]+"\n"+lines[1]+"\n"+lines[2][:half])
	in := newIngester(t, logPath, store)
	if err := in.Poll(); err != nil {
		t.Fatal(err)
	}
	if st := in.Status(); st.Ingested != 2 || st.Offset != int64(len(lines[0])+len(lines[1])+2) {
		t.Fatalf("partial record must wait: %+v", st)
	}
	appendFile(t, logPath, lines[2][half:]+"\n")
	if err := in.Poll(); err != nil {
		t.Fatal(err)
	}
	if in.Status().Ingested != 3 || store.Stats().Count != 3 {
		t.Fatalf("completed record not ingested: %+v", in.Status())
	}
	restarted := newIngester(t, logPath, store)
	if err := restarted.Poll(); err != nil {
		t.Fatal(err)
	}
	if restarted.Status().Ingested != 0 || restarted.Status().Offset != in.Status().Offset {
		t.Fatalf("restart must resume from the saved offset: %+v", restarted.Status())
	}
}

func TestIngestConcatenatedObjectsAndGarbage(t *testing.T) {
	store, _ := newStore(t)
	logPath := filepath.Join(t.TempDir(), "audit.log")
	lines := fixtureLines(t)
	// Older writers concatenate objects without newlines; a corrupt line
	// in between must not stop ingestion.
	appendFile(t, logPath, lines[0]+lines[1]+"\nnot json at all\n{\"transaction\":{\"id\":\nbroken\n"+lines[3]+"\n")
	in := newIngester(t, logPath, store)
	if err := in.Poll(); err != nil {
		t.Fatal(err)
	}
	if got := store.Stats().Count; got != 3 {
		t.Fatalf("expected 3 events around garbage, got %d", got)
	}
}

func TestIngestTruncatesAfterFullIngestion(t *testing.T) {
	store, _ := newStore(t)
	logPath := filepath.Join(t.TempDir(), "audit.log")
	lines := fixtureLines(t)
	appendFile(t, logPath, lines[0]+"\n"+lines[1]+"\n")
	in := newIngester(t, logPath, store)
	in.MaxBytes = 10
	if err := in.Poll(); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(logPath)
	if err != nil || fi.Size() != 0 || in.Status().Truncations != 1 || in.Status().Offset != 0 {
		t.Fatalf("audit log must be truncated after ingestion: size=%v status=%+v", fi, in.Status())
	}
	appendFile(t, logPath, lines[2]+"\n")
	if err := in.Poll(); err != nil {
		t.Fatal(err)
	}
	if store.Stats().Count != 3 {
		t.Fatal("records written after truncation must be ingested")
	}
}

func TestIngestDetectsRotationAndExternalTruncation(t *testing.T) {
	store, _ := newStore(t)
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	lines := fixtureLines(t)
	appendFile(t, logPath, lines[0]+"\n"+lines[1]+"\n")
	in := newIngester(t, logPath, store)
	if err := in.Poll(); err != nil {
		t.Fatal(err)
	}
	rotated := filepath.Join(dir, "audit.new")
	appendFile(t, rotated, lines[2]+"\n")
	if err := os.Rename(rotated, logPath); err != nil {
		t.Fatal(err)
	}
	if err := in.Poll(); err != nil {
		t.Fatal(err)
	}
	if store.Stats().Count != 3 {
		t.Fatalf("a replaced file must be read from the start: %d", store.Stats().Count)
	}
	if err := os.Truncate(logPath, 0); err != nil {
		t.Fatal(err)
	}
	appendFile(t, logPath, lines[3]+"\n")
	if err := in.Poll(); err != nil {
		t.Fatal(err)
	}
	if store.Stats().Count != 4 {
		t.Fatalf("an externally truncated file must be read from the start: %d", store.Stats().Count)
	}
	missing := newIngester(t, filepath.Join(dir, "missing.log"), store)
	if err := missing.Poll(); err != nil {
		t.Fatalf("a missing audit log is not an error before the first event: %v", err)
	}
}
