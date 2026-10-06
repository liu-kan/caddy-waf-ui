package events

import (
	"bufio"
	"container/heap"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// ErrStorageFull stops ingestion before its input cursor advances. No
// unacknowledged local events are deleted to make room for cloud imports.
var ErrStorageFull = errors.New("event disk budget reached; free space or reduce retention")

type recordRef struct {
	File   string
	Offset int64
	Size   int
	TS     time.Time
}

func walkEventFile(path string, visit func(*Event, int64, int) error) error {
	f, err := os.Open(path) //nolint:gosec // G304: retained day files and durable index offsets, never raw request paths.
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 4<<20)
	offset := int64(0)
	for scanner.Scan() {
		raw := scanner.Bytes()
		var e Event
		if json.Unmarshal(raw, &e) == nil && e.TxID != "" {
			if e.Hits == nil {
				e.Hits = []Hit{}
			}
			if err := visit(&e, offset, len(raw)); err != nil {
				return err
			}
		}
		offset += int64(len(raw) + 1)
	}
	return scanner.Err()
}

type eventHeap []*Event

func (h eventHeap) Len() int { return len(h) }
func (h eventHeap) Less(i, j int) bool {
	if h[i].TS.Equal(h[j].TS) {
		return h[i].Key() < h[j].Key()
	}
	return h[i].TS.Before(h[j].TS)
}
func (h eventHeap) Swap(i, j int) { h[i], h[j] = h[j], h[i] }
func (h *eventHeap) Push(x any)   { *h = append(*h, x.(*Event)) }
func (h *eventHeap) Pop() any     { a := *h; x := a[len(a)-1]; *h = a[:len(a)-1]; return x }

// QueryDisk scans retained files without materializing the entire history.
// Only the requested page is retained; the durable index removes old duplicates.
func (s *Store) QueryDisk(q Query) ([]*Event, int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if q.Limit <= 0 {
		q.Limit = 50
	}
	if q.Offset < 0 {
		q.Offset = 0
	}
	if q.Limit+q.Offset > 20000 {
		return nil, 0, fmt.Errorf("local pagination budget exceeded: narrow the time range")
	}
	keep := q.Limit + q.Offset
	h := &eventHeap{}
	heap.Init(h)
	total := 0
	names := map[string]bool{}
	for _, ref := range s.index {
		if (!q.From.IsZero() && ref.TS.Before(q.From)) || (!q.To.IsZero() && !ref.TS.Before(q.To)) {
			continue
		}
		names[ref.File] = true
	}
	for name := range names {
		err := walkEventFile(filepath.Join(s.dir, name), func(e *Event, offset int64, _ int) error {
			ref, ok := s.index[e.Key()]
			if !ok || ref.File != name || ref.Offset != offset || !q.Match(e) {
				return nil
			}
			total++
			heap.Push(h, e)
			if h.Len() > keep {
				heap.Pop(h)
			}
			return nil
		})
		if err != nil {
			return nil, total, err
		}
	}
	out := []*Event(*h)
	sort.Slice(out, func(i, j int) bool {
		if out[i].TS.Equal(out[j].TS) {
			return out[i].Key() > out[j].Key()
		}
		return out[i].TS.After(out[j].TS)
	})
	if q.Offset >= len(out) {
		return nil, total, nil
	}
	return out[q.Offset:], total, nil
}
