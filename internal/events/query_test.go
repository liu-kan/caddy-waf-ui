package events

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// TestQueryDiskRunsAlongsideAppendsAndPrunes: queries parse retained files
// without holding the store lock, so ingestion and pruning proceed while a
// page scans 14 days of history (run under -race).
func TestQueryDiskRunsAlongsideAppendsAndPrunes(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "events"), 48*time.Hour, 50)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	for i := 0; i < 200; i++ {
		if _, err := store.Append(event(fmt.Sprintf("seed-%d", i), now.Add(-time.Duration(i)*time.Minute), "example.com", ActionBlocked, "192.0.2.1", "/p"), SourceLocal); err != nil {
			t.Fatal(err)
		}
	}
	var wg sync.WaitGroup
	errs := make(chan error, 64)
	for g := 0; g < 4; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 20; i++ {
				if _, _, err := store.QueryDisk(Query{From: now.Add(-24 * time.Hour), Limit: 50}); err != nil {
					errs <- err
				}
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			if _, err := store.Append(event(fmt.Sprintf("live-%d", i), time.Now().UTC(), "example.com", ActionBlocked, "192.0.2.2", "/q"), SourceLocal); err != nil {
				errs <- err
			}
			if i%25 == 0 {
				if err := store.Prune(time.Now().UTC()); err != nil {
					errs <- err
				}
			}
		}
	}()
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	if _, total, err := store.QueryDisk(Query{From: now.Add(-24 * time.Hour)}); err != nil || total != 300 {
		t.Fatalf("expected 300 events, got %d %v", total, err)
	}
}

// TestQueryDiskSkipsFilesPrunedDuringTheScan: a day file removed by the
// retention between the index snapshot and its scan holds only expired
// events; the query continues with the other files.
func TestQueryDiskSkipsFilesPrunedDuringTheScan(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "events"), 72*time.Hour, 10)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if _, err := store.Append(event("today", now, "example.com", ActionBlocked, "192.0.2.1", "/p"), SourceLocal); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Append(event("yesterday", now.Add(-24*time.Hour), "example.com", ActionBlocked, "192.0.2.1", "/p"), SourceLocal); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(store.Dir(), "events-"+now.Add(-24*time.Hour).Format("2006-01-02")+".jsonl")); err != nil {
		t.Fatal(err)
	}
	list, _, err := store.QueryDisk(Query{From: now.Add(-48 * time.Hour)})
	if err != nil || len(list) != 1 || list[0].TxID != "today" {
		t.Fatalf("expected the remaining event, got %d %v", len(list), err)
	}
}

// TestWindowIsReusedBriefly: the rules, exclusions and analysis pages ask
// for the same 7/14-day window on every render; it is reused for
// windowCacheTTL instead of re-parsing the retained files each time.
func TestWindowIsReusedBriefly(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "events"), 72*time.Hour, 10)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if _, err := store.Append(event("w1", now, "example.com", ActionBlocked, "192.0.2.1", "/p"), SourceLocal); err != nil {
		t.Fatal(err)
	}
	q := Query{From: now.Add(-48 * time.Hour), Site: "example.com"}
	first := store.Window(q)
	if len(first) != 1 {
		t.Fatalf("expected 1 event, got %d", len(first))
	}
	first[0] = nil // callers own the returned slice
	if err := os.Remove(filepath.Join(store.Dir(), "events-"+now.Format("2006-01-02")+".jsonl")); err != nil {
		t.Fatal(err)
	}
	q.From = q.From.Add(time.Second) // a later render of the same page
	if again := store.Window(q); len(again) != 1 || again[0] == nil {
		t.Fatal("the window was not reused within its TTL")
	}

	prev := windowCacheTTL
	windowCacheTTL = 0
	t.Cleanup(func() { windowCacheTTL = prev })
	if fresh := store.Window(q); len(fresh) != 0 {
		t.Fatalf("an expired window must be recomputed, got %d events", len(fresh))
	}
}
