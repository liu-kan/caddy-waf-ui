package events

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// Sources of stored events.
const (
	SourceLocal = ""
	SourceLoki  = "loki"
)

// File name prefixes: local events are shipped to Loki by Alloy; imported
// events came from Loki and must not be shipped back.
const (
	localPrefix    = "events-"
	importedPrefix = "imported-"
)

var dayFile = regexp.MustCompile(`^(events|imported)-(\d{4}-\d{2}-\d{2})\.jsonl$`)

// Store keeps recent events in memory and daily JSON-lines files on disk.
type Store struct {
	dir       string
	retention time.Duration
	max       int

	mu      sync.RWMutex
	events  []*Event
	byTx    map[string]*Event
	rollups *Rollups
	oldest  time.Time

	// OnAdd runs for every new locally ingested event (metrics).
	OnAdd func(*Event)
}

// OpenStore loads the events of the retention window from dir. max bounds
// the number of events kept in memory (oldest are dropped first; their
// files remain on disk until retention removes them).
func OpenStore(dir string, retention time.Duration, max int) (*Store, error) {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, err
	}
	rollups, err := OpenRollups(filepath.Join(filepath.Dir(dir), "rollups"))
	if err != nil {
		return nil, err
	}
	s := &Store{dir: dir, retention: retention, max: max, byTx: map[string]*Event{}, rollups: rollups}
	if err := s.load(time.Now().UTC()); err != nil {
		return nil, err
	}
	return s, nil
}

// Dir returns the events directory.
func (s *Store) Dir() string { return s.dir }

// Rollups returns the long-term daily counters.
func (s *Store) Rollups() *Rollups { return s.rollups }

func (s *Store) cutoff(now time.Time) time.Time {
	return now.Add(-s.retention).Truncate(24 * time.Hour)
}

func (s *Store) load(now time.Time) error {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return err
	}
	cutoff := s.cutoff(now)
	var names []string
	for _, entry := range entries {
		m := dayFile.FindStringSubmatch(entry.Name())
		if m == nil {
			continue
		}
		day, err := time.Parse("2006-01-02", m[2])
		if err != nil || day.Before(cutoff) {
			continue
		}
		names = append(names, entry.Name())
	}
	sort.Strings(names)
	var loaded []*Event
	for _, name := range names {
		events, err := readEventFile(filepath.Join(s.dir, name))
		if err != nil {
			return fmt.Errorf("load %s: %w", name, err)
		}
		loaded = append(loaded, events...)
	}
	sort.SliceStable(loaded, func(i, j int) bool { return loaded[i].TS.Before(loaded[j].TS) })
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, e := range loaded {
		if _, dup := s.byTx[e.TxID]; dup || e.TS.Before(cutoff) {
			continue
		}
		s.byTx[e.TxID] = e
		s.events = append(s.events, e)
	}
	s.trimLocked()
	return nil
}

func readEventFile(path string) ([]*Event, error) {
	f, err := os.Open(path) //nolint:gosec // G304: file names come from os.ReadDir of the data dir, filtered by dayFile.
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	var out []*Event
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 4<<20)
	for scanner.Scan() {
		var e Event
		if err := json.Unmarshal(scanner.Bytes(), &e); err != nil || e.TxID == "" {
			continue // a torn last line after a crash
		}
		if e.Hits == nil {
			e.Hits = []Hit{}
		}
		out = append(out, &e)
	}
	return out, scanner.Err()
}

// Append stores a new event (deduplicated by transaction id). Local events
// are written to events-<day>.jsonl; events imported from Loki to
// imported-<day>.jsonl.
func (s *Store) Append(e *Event, source string) (bool, error) {
	s.mu.Lock()
	if _, dup := s.byTx[e.TxID]; dup {
		s.mu.Unlock()
		return false, nil
	}
	if e.TS.Before(s.cutoff(time.Now().UTC())) {
		s.mu.Unlock()
		return false, nil
	}
	e.Source = source
	prefix := localPrefix
	if source == SourceLoki {
		prefix = importedPrefix
	}
	if err := appendLine(filepath.Join(s.dir, prefix+e.TS.UTC().Format("2006-01-02")+".jsonl"), e); err != nil {
		s.mu.Unlock()
		return false, err
	}
	s.byTx[e.TxID] = e
	s.insertLocked(e)
	s.trimLocked()
	s.mu.Unlock()
	s.rollups.Add(e)
	if source == SourceLocal && s.OnAdd != nil {
		s.OnAdd(e)
	}
	return true, nil
}

func appendLine(path string, e *Event) error {
	line, err := json.Marshal(e)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o640) //nolint:gosec // G304/G302: data-dir file named from the event date; shared UID/GID, no world access.
	if err != nil {
		return err
	}
	if _, err := f.Write(append(line, '\n')); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// insertLocked keeps events ordered by time (imports may be older).
func (s *Store) insertLocked(e *Event) {
	n := len(s.events)
	if n == 0 || !e.TS.Before(s.events[n-1].TS) {
		s.events = append(s.events, e)
		return
	}
	i := sort.Search(n, func(i int) bool { return s.events[i].TS.After(e.TS) })
	s.events = append(s.events, nil)
	copy(s.events[i+1:], s.events[i:])
	s.events[i] = e
}

func (s *Store) trimLocked() {
	if s.max > 0 && len(s.events) > s.max {
		drop := len(s.events) - s.max
		for _, e := range s.events[:drop] {
			delete(s.byTx, e.TxID)
		}
		s.events = append([]*Event(nil), s.events[drop:]...)
	}
	if len(s.events) > 0 {
		s.oldest = s.events[0].TS
	}
}

// Prune deletes day files older than the retention window and drops expired
// events from memory. Rollups are kept.
func (s *Store) Prune(now time.Time) error {
	cutoff := s.cutoff(now)
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		m := dayFile.FindStringSubmatch(entry.Name())
		if m == nil {
			continue
		}
		if day, err := time.Parse("2006-01-02", m[2]); err == nil && day.Before(cutoff) {
			if err := os.Remove(filepath.Join(s.dir, entry.Name())); err != nil && !os.IsNotExist(err) {
				slog.Warn("could not remove expired event file", "file", entry.Name(), "error", err)
			}
		}
	}
	s.mu.Lock()
	i := sort.Search(len(s.events), func(i int) bool { return !s.events[i].TS.Before(cutoff) })
	for _, e := range s.events[:i] {
		delete(s.byTx, e.TxID)
	}
	s.events = append([]*Event(nil), s.events[i:]...)
	if len(s.events) > 0 {
		s.oldest = s.events[0].TS
	}
	s.mu.Unlock()
	return s.rollups.Flush()
}

// Has reports whether a transaction is stored.
func (s *Store) Has(tx string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.byTx[tx]
	return ok
}

// Get returns a stored event by transaction id.
func (s *Store) Get(tx string) (*Event, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	e, ok := s.byTx[tx]
	return e, ok
}

// Stats summarizes the in-memory window.
type Stats struct {
	Count  int
	Oldest time.Time
	Newest time.Time
}

// Stats returns the size and time span held in memory.
func (s *Store) Stats() Stats {
	s.mu.RLock()
	defer s.mu.RUnlock()
	st := Stats{Count: len(s.events)}
	if len(s.events) > 0 {
		st.Oldest, st.Newest = s.events[0].TS, s.events[len(s.events)-1].TS
	}
	return st
}

// Query filters events. Zero fields are ignored.
type Query struct {
	From, To   time.Time
	Site       string
	Action     string
	IP         string
	RuleID     int
	PathPrefix string
	Text       string
	Limit      int
	Offset     int
}

// Match reports whether an event satisfies the query filters.
func (q Query) Match(e *Event) bool {
	if !q.From.IsZero() && e.TS.Before(q.From) {
		return false
	}
	if !q.To.IsZero() && !e.TS.Before(q.To) {
		return false
	}
	if q.Site != "" && e.Site != q.Site {
		return false
	}
	if q.Action != "" && e.Action != q.Action {
		return false
	}
	if q.IP != "" && e.ClientIP != q.IP {
		return false
	}
	if q.RuleID != 0 && !e.HasRule(q.RuleID) {
		return false
	}
	if q.PathPrefix != "" && !strings.HasPrefix(e.Path, q.PathPrefix) {
		return false
	}
	if q.Text != "" {
		needle := strings.ToLower(q.Text)
		hay := strings.ToLower(e.ClientIP + " " + e.Path + " " + e.RuleIDs + " " + e.Host + " " + e.TxID)
		if !strings.Contains(hay, needle) {
			found := false
			for _, h := range e.Hits {
				if strings.Contains(strings.ToLower(h.Msg+" "+h.Var+" "+h.Data), needle) {
					found = true
					break
				}
			}
			if !found {
				return false
			}
		}
	}
	return true
}

// Query returns matching events, newest first, and the total match count.
func (s *Store) Query(q Query) ([]*Event, int) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	limit := q.Limit
	if limit <= 0 {
		limit = 50
	}
	var out []*Event
	total := 0
	for i := len(s.events) - 1; i >= 0; i-- {
		e := s.events[i]
		if !q.From.IsZero() && e.TS.Before(q.From) {
			break
		}
		if !q.Match(e) {
			continue
		}
		if total >= q.Offset && len(out) < limit {
			out = append(out, e)
		}
		total++
	}
	return out, total
}

// Window returns matching events in chronological order (analysis input).
func (s *Store) Window(q Query) []*Event {
	s.mu.RLock()
	defer s.mu.RUnlock()
	start := 0
	if !q.From.IsZero() {
		start = sort.Search(len(s.events), func(i int) bool { return !s.events[i].TS.Before(q.From) })
	}
	var out []*Event
	for _, e := range s.events[start:] {
		if q.Match(e) {
			out = append(out, e)
		}
	}
	return out
}

// Sites returns the distinct sites in memory.
func (s *Store) Sites() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	seen := map[string]bool{}
	var out []string
	for _, e := range s.events {
		if !seen[e.Site] {
			seen[e.Site] = true
			out = append(out, e.Site)
		}
	}
	sort.Strings(out)
	return out
}
