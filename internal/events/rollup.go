package events

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/developmi/caddy-waf-ui/internal/files"
)

// Rollups are daily counters per site, rule and action, kept after the raw
// events expire (the Grafana Cloud free tier keeps 14 days). Rule 0 counts
// events; other rules count events that matched them.
type Rollups struct {
	dir    string
	mu     sync.Mutex
	months map[string]map[string]map[string]int64 // month → day → key → count
	dirty  map[string]bool
}

// RollupRow is one counter.
type RollupRow struct {
	Day    string
	Site   string
	Rule   int
	Action string
	Count  int64
}

var monthFile = regexp.MustCompile(`^rollup-(\d{4}-\d{2})\.json$`)

// OpenRollups loads the monthly counter files of dir.
func OpenRollups(dir string) (*Rollups, error) {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, err
	}
	r := &Rollups{dir: dir, months: map[string]map[string]map[string]int64{}, dirty: map[string]bool{}}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		m := monthFile.FindStringSubmatch(entry.Name())
		if m == nil {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, entry.Name())) //nolint:gosec // G304: names from os.ReadDir filtered by monthFile.
		if err != nil {
			return nil, err
		}
		var days map[string]map[string]int64
		if err := json.Unmarshal(data, &days); err != nil {
			return nil, errors.New("corrupt rollup file " + entry.Name() + ": " + err.Error())
		}
		r.months[m[1]] = days
	}
	return r, nil
}

func rollupKey(site string, rule int, action string) string {
	return site + "|" + strconv.Itoa(rule) + "|" + action
}

// Add counts one event.
func (r *Rollups) Add(e *Event) {
	day := e.TS.UTC().Format("2006-01-02")
	month := day[:7]
	r.mu.Lock()
	defer r.mu.Unlock()
	days := r.months[month]
	if days == nil {
		days = map[string]map[string]int64{}
		r.months[month] = days
	}
	counts := days[day]
	if counts == nil {
		counts = map[string]int64{}
		days[day] = counts
	}
	counts[rollupKey(e.Site, 0, e.Action)]++
	seen := map[int]bool{}
	for _, h := range e.Hits {
		if seen[h.ID] {
			continue
		}
		seen[h.ID] = true
		counts[rollupKey(e.Site, h.ID, e.Action)]++
	}
	r.dirty[month] = true
}

// Flush writes the changed months.
func (r *Rollups) Flush() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for month := range r.dirty {
		data, err := json.Marshal(r.months[month])
		if err != nil {
			return err
		}
		if err := files.AtomicWrite(filepath.Join(r.dir, "rollup-"+month+".json"), data); err != nil {
			return err
		}
		delete(r.dirty, month)
	}
	return nil
}

// Range returns the counters between from and to (inclusive days) for a
// site ("" = all sites), ordered by day, site, rule, action.
func (r *Rollups) Range(from, to time.Time, site string) []RollupRow {
	first, last := from.UTC().Format("2006-01-02"), to.UTC().Format("2006-01-02")
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []RollupRow
	for _, days := range r.months {
		for day, counts := range days {
			if day < first || day > last {
				continue
			}
			for key, count := range counts {
				parts := strings.SplitN(key, "|", 3)
				if len(parts) != 3 || (site != "" && parts[0] != site) {
					continue
				}
				rule, _ := strconv.Atoi(parts[1])
				out = append(out, RollupRow{Day: day, Site: parts[0], Rule: rule, Action: parts[2], Count: count})
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Day != b.Day {
			return a.Day < b.Day
		}
		if a.Site != b.Site {
			return a.Site < b.Site
		}
		if a.Rule != b.Rule {
			return a.Rule < b.Rule
		}
		return a.Action < b.Action
	})
	return out
}
