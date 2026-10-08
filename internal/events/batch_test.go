package events

import (
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestAppendBatchStoresInOrderAndIndexesOffsets: a batch is written with one
// open and one fsync per day file; every stored event must still be readable
// through its durable offset after it leaves the memory cache, and the
// batch reports which events were new.
func TestAppendBatchStoresInOrderAndIndexesOffsets(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "events")
	store, err := OpenStore(dir, 24*time.Hour, 2)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if _, err := store.Append(event("existing", now, "example.com", ActionBlocked, "192.0.2.1", "/a"), SourceLocal); err != nil {
		t.Fatal(err)
	}
	batch := []*Event{
		event("b1", now, "example.com", ActionBlocked, "192.0.2.1", "/b1"),
		event("existing", now, "example.com", ActionBlocked, "192.0.2.1", "/dup"),
		event("b2", now, "example.com", ActionDetected, "192.0.2.2", "/b2"),
		event("b1", now, "example.com", ActionBlocked, "192.0.2.1", "/b1-again"),
		event("old", now.Add(-72*time.Hour), "example.com", ActionBlocked, "192.0.2.1", "/old"),
		event("b3", now, "example.com", ActionDetected, "192.0.2.3", "/b3"),
	}
	added, err := store.AppendBatch(batch, SourceLocal)
	if err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprint(added); got != "[true false true false false true]" {
		t.Fatalf("added flags: %s", got)
	}
	for _, tx := range []string{"existing", "b1", "b2", "b3"} {
		e, ok := store.Get(tx)
		if !ok || e.TxID != tx {
			t.Fatalf("%s is not readable through its durable offset", tx)
		}
	}
	if e, _ := store.Get("b1"); e.Path != "/b1" {
		t.Fatalf("the first occurrence of a transaction wins, got %s", e.Path)
	}
	reopened, err := OpenStore(dir, 24*time.Hour, 10)
	if err != nil {
		t.Fatal(err)
	}
	if st := reopened.Stats(); st.Stored != 4 {
		t.Fatalf("expected 4 stored events after reopening, got %d", st.Stored)
	}
}

// TestAppendBatchStopsAtTheDiskBudget: events that do not fit are not
// written, and the batch reports how many leading events were processed so
// the ingester can keep its cursor before the first unstored record.
func TestAppendBatchStopsAtTheDiskBudget(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "events"), 24*time.Hour, 10)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	one, _ := json.Marshal(event("x1", now, "example.com", ActionBlocked, "192.0.2.1", "/p"))
	store.MaxDiskBytes = int64(2*(len(one)+1) + 1)
	batch := []*Event{
		event("x1", now, "example.com", ActionBlocked, "192.0.2.1", "/p"),
		event("x2", now, "example.com", ActionBlocked, "192.0.2.1", "/p"),
		event("x3", now, "example.com", ActionBlocked, "192.0.2.1", "/p"),
	}
	added, err := store.AppendBatch(batch, SourceLocal)
	if !errors.Is(err, ErrStorageFull) || len(added) != 2 {
		t.Fatalf("expected 2 processed events and ErrStorageFull, got %d %v", len(added), err)
	}
	if store.Has("x3") {
		t.Fatal("an event over the budget was stored")
	}
}

// TestIngestCursorStopsBeforeTheFirstUnstoredRecord: with batched writes, a
// store failure in the middle of a poll keeps the cursor right after the
// last stored record; the next poll stores the rest without duplicates.
func TestIngestCursorStopsBeforeTheFirstUnstoredRecord(t *testing.T) {
	root := t.TempDir()
	store, err := OpenStore(filepath.Join(root, "events"), 24*time.Hour, 100)
	if err != nil {
		t.Fatal(err)
	}
	lines := uniqueRecords(t, 6)
	logPath := filepath.Join(root, "audit.log")
	appendFile(t, logPath, strings.Join(lines, "\n")+"\n")
	in := newIngester(t, logPath, store)

	probe, err := in.Norm.Normalize([]byte(lines[0]))
	if err != nil {
		t.Fatal(err)
	}
	size, _ := json.Marshal(probe)
	store.MaxDiskBytes = int64(2*(len(size)+1) + len(size)/2)
	if err := in.Poll(); !errors.Is(err, ErrStorageFull) {
		t.Fatalf("expected ErrStorageFull, got %v", err)
	}
	stored := store.Stats().Stored
	if stored == 0 || stored == len(lines) {
		t.Fatalf("setup: expected a partial store, got %d", stored)
	}
	want := int64(0)
	for _, l := range lines[:stored] {
		want += int64(len(l) + 1)
	}
	if got := in.Status().Offset; got != want && got != want-1 {
		t.Fatalf("cursor at %d, expected the end of record %d (%d)", got, stored, want)
	}
	store.MaxDiskBytes = 0
	if err := in.Poll(); err != nil {
		t.Fatal(err)
	}
	if got := store.Stats().Stored; got != len(lines) {
		t.Fatalf("expected %d events after the retry, got %d", len(lines), got)
	}
}
