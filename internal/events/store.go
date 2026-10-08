package events

import (
	"encoding/json"
	"fmt"
	"io"
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

	mu           sync.RWMutex
	events       []*Event
	byTx         map[string]*Event
	rollups      *Rollups
	oldest       time.Time
	index        map[string]recordRef
	diskBytes    int64
	MaxDiskBytes int64

	// OnAdd runs for every new locally ingested event (metrics).
	OnAdd func(*Event)

	windowMu sync.Mutex
	windows  map[string]cachedWindow
}

// cachedWindow is a recently computed analysis window.
type cachedWindow struct {
	at     time.Time
	events []*Event
}

// windowCacheTTL is how long an analysis window is reused: the pages that
// analyze 7-14 days ask for the same window on every render. It is a
// variable so tests can expire it.
var windowCacheTTL = 15 * time.Second

// maxCachedWindows bounds the distinct windows kept (sites x ranges).
const maxCachedWindows = 16

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
	s := &Store{dir: dir, retention: retention, max: max, byTx: map[string]*Event{}, index: map[string]recordRef{}, rollups: rollups}
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
	days := map[string]bool{}
	for _, name := range names {
		days[dayFile.FindStringSubmatch(name)[2]] = true
	}
	var dayList []string
	for day := range days {
		dayList = append(dayList, day)
	}
	s.rollups.ResetDays(dayList)
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, name := range names {
		path := filepath.Join(s.dir, name)
		if fi, err := os.Stat(path); err == nil {
			s.diskBytes += fi.Size()
		}
		if err := walkEventFile(path, func(e *Event, offset int64, size int) error {
			key := e.Key()
			if _, dup := s.index[key]; dup || e.TS.Before(cutoff) {
				return nil
			}
			s.index[key] = recordRef{File: name, Offset: offset, Size: size, TS: e.TS}
			s.rollups.Add(e)
			s.byTx[key] = e
			s.insertLocked(e)
			s.trimLocked()
			return nil
		}); err != nil {
			return fmt.Errorf("load %s: %w", name, err)
		}
	}
	return s.rollups.Flush()
}

// Append stores a new event (deduplicated by transaction id). Local events
// are written to events-<day>.jsonl; events imported from Loki to
// imported-<day>.jsonl.
func (s *Store) Append(e *Event, source string) (bool, error) {
	added, err := s.AppendBatch([]*Event{e}, source)
	if err != nil {
		return false, err
	}
	return added[0], nil
}

// pendingRecord is an event of a batch waiting to be written.
type pendingRecord struct {
	index int
	event *Event
	line  []byte
	file  string
}

// AppendBatch stores events in order like Append, writing each run of
// events of the same day file with one open and one fsync instead of one
// per event. It returns, for the leading events it processed, whether each
// was newly stored (false: duplicate or outside the retention window). On an
// error the events from len(added) on were not stored.
func (s *Store) AppendBatch(list []*Event, source string) ([]bool, error) {
	prefix := localPrefix
	if source == SourceLoki {
		prefix = importedPrefix
	}
	s.mu.Lock()
	cutoff := s.cutoff(time.Now().UTC())
	added := make([]bool, 0, len(list))
	var pending []pendingRecord
	seen := map[string]bool{}
	budget := s.diskBytes
	var stop error
	for i, e := range list {
		key := e.Key()
		if _, dup := s.index[key]; dup || seen[key] || e.TS.Before(cutoff) {
			added = append(added, false)
			continue
		}
		stored := *e
		stored.Source = source
		line, err := json.Marshal(&stored)
		if err != nil {
			stop = err
			break
		}
		if s.MaxDiskBytes > 0 && budget+int64(len(line)+1) > s.MaxDiskBytes {
			stop = ErrStorageFull
			break
		}
		budget += int64(len(line) + 1)
		seen[key] = true
		e.Source = source
		pending = append(pending, pendingRecord{index: i, event: e, line: line, file: prefix + e.TS.UTC().Format("2006-01-02") + ".jsonl"})
		added = append(added, true)
	}
	var stored []*Event
	for start := 0; start < len(pending); {
		end := start + 1
		for end < len(pending) && pending[end].file == pending[start].file {
			end++
		}
		if err := s.writeRunLocked(pending[start:end]); err != nil {
			added = added[:pending[start].index]
			stop = err
			break
		}
		for _, p := range pending[start:end] {
			stored = append(stored, p.event)
		}
		start = end
	}
	s.trimLocked()
	s.mu.Unlock()
	for _, e := range stored {
		s.rollups.Add(e)
		if source == SourceLocal && s.OnAdd != nil {
			s.OnAdd(e)
		}
	}
	return added, stop
}

// writeRunLocked appends records of one day file with a single write and
// fsync, then indexes them.
func (s *Store) writeRunLocked(run []pendingRecord) error {
	path := filepath.Join(s.dir, run[0].file)
	offset, padding, err := prepareAppend(path)
	if err != nil {
		return err
	}
	s.diskBytes += padding
	var buf []byte
	for _, p := range run {
		buf = append(buf, p.line...)
		buf = append(buf, '\n')
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o640) //nolint:gosec // G304/G302: data-dir file named from the event date; shared UID/GID, no world access.
	if err != nil {
		return err
	}
	if _, err := f.Write(buf); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	for _, p := range run {
		key := p.event.Key()
		s.byTx[key] = p.event
		s.index[key] = recordRef{File: p.file, Offset: offset, Size: len(p.line), TS: p.event.TS}
		s.insertLocked(p.event)
		offset += int64(len(p.line) + 1)
	}
	s.diskBytes += int64(len(buf))
	return nil
}

// A torn final record must not absorb the next successfully written event.
// Preserve it for diagnosis and isolate it with a newline before appending.
func prepareAppend(path string) (int64, int64, error) {
	f, err := os.OpenFile(path, os.O_RDWR, 0) //nolint:gosec // G304: generated retained event file.
	if os.IsNotExist(err) {
		return 0, 0, nil
	}
	if err != nil {
		return 0, 0, err
	}
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil {
		return 0, 0, err
	}
	n := fi.Size()
	if n == 0 {
		return 0, 0, nil
	}
	var tail [1]byte
	if _, err = f.ReadAt(tail[:], n-1); err != nil {
		return 0, 0, err
	}
	if tail[0] == '\n' {
		return n, 0, nil
	}
	if _, err = f.Seek(0, io.SeekEnd); err != nil {
		return 0, 0, err
	}
	if _, err = f.Write([]byte{'\n'}); err != nil {
		return 0, 0, err
	}
	return n + 1, 1, f.Sync()
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
			delete(s.byTx, e.Key())
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
	s.mu.Lock()
	defer s.mu.Unlock()
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
	for key, ref := range s.index {
		if ref.TS.Before(cutoff) {
			delete(s.index, key)
		}
	}
	s.diskBytes = 0
	if remaining, err := os.ReadDir(s.dir); err == nil {
		for _, f := range remaining {
			if dayFile.MatchString(f.Name()) {
				if fi, err := f.Info(); err == nil {
					s.diskBytes += fi.Size()
				}
			}
		}
	}
	i := sort.Search(len(s.events), func(i int) bool { return !s.events[i].TS.Before(cutoff) })
	for _, e := range s.events[:i] {
		delete(s.byTx, e.Key())
	}
	s.events = append([]*Event(nil), s.events[i:]...)
	if len(s.events) > 0 {
		s.oldest = s.events[0].TS
	}
	return s.rollups.Flush()
}

// Has reports whether a transaction is stored.
func (s *Store) Has(tx string) bool { _, ok := s.Get(tx); return ok }

// Get returns a transaction only when its id is unambiguous across nodes.
func (s *Store) Get(tx string) (*Event, bool) { return s.GetFor(tx, "") }

// GetFor reads evicted events directly by their persisted file offset.
func (s *Store) GetFor(tx, node string) (*Event, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	key := node + "\x00" + tx
	if node == "" {
		found := false
		for k := range s.index {
			if strings.HasSuffix(k, "\x00"+tx) {
				if found {
					return nil, false
				}
				key = k
				found = true
			}
		}
	}
	if e, ok := s.byTx[key]; ok {
		return e, true
	}
	ref, ok := s.index[key]
	if !ok {
		return nil, false
	}
	f, err := os.Open(filepath.Join(s.dir, ref.File))
	if err != nil {
		return nil, false
	}
	defer func() { _ = f.Close() }()
	raw := make([]byte, ref.Size)
	if _, err = f.ReadAt(raw, ref.Offset); err != nil {
		return nil, false
	}
	var e Event
	if json.Unmarshal(raw, &e) != nil {
		return nil, false
	}
	return &e, true
}

// Stats summarizes retained files and the bounded memory cache.
type Stats struct {
	Count     int
	Stored    int
	DiskBytes int64
	Oldest    time.Time
	Newest    time.Time
}

// Stats returns the size and time span held in memory.
func (s *Store) Stats() Stats {
	s.mu.RLock()
	defer s.mu.RUnlock()
	st := Stats{Count: len(s.events), Stored: len(s.index), DiskBytes: s.diskBytes}
	if len(s.events) > 0 {
		st.Oldest, st.Newest = s.events[0].TS, s.events[len(s.events)-1].TS
	}
	for _, ref := range s.index {
		if st.Oldest.IsZero() || ref.TS.Before(st.Oldest) {
			st.Oldest = ref.TS
		}
		if ref.TS.After(st.Newest) {
			st.Newest = ref.TS
		}
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
	list, total, err := s.QueryDisk(q)
	if err != nil {
		slog.Error("event query incomplete", "error", err)
	}
	return list, total
}

// Window bounds analysis memory independently from the durable index. The
// window bounds are rounded to the minute and a computed window is reused
// for windowCacheTTL; callers own the returned slice but must treat the
// events as read-only (they are shared between requests).
func (s *Store) Window(q Query) []*Event {
	q.Limit = AnalysisLimit
	q.Offset = 0
	q.From = q.From.Truncate(time.Minute)
	q.To = q.To.Truncate(time.Minute)
	key := fmt.Sprintf("%+v", q)
	now := time.Now()
	s.windowMu.Lock()
	if w, ok := s.windows[key]; ok && now.Sub(w.at) < windowCacheTTL {
		s.windowMu.Unlock()
		return append([]*Event(nil), w.events...)
	}
	s.windowMu.Unlock()

	out, _, err := s.QueryDisk(q)
	if err != nil {
		slog.Error("analysis window incomplete", "error", err)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].TS.Before(out[j].TS) })
	if err == nil {
		s.windowMu.Lock()
		if s.windows == nil || len(s.windows) >= maxCachedWindows {
			s.windows = map[string]cachedWindow{}
		}
		s.windows[key] = cachedWindow{at: now, events: out}
		s.windowMu.Unlock()
	}
	return append([]*Event(nil), out...)
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
