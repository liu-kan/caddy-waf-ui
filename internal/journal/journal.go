// Package journal records configuration changes as JSON lines. The file
// lives in the UI data volume next to the WAF events, so the same Alloy
// pipeline ships it to Loki (kind="change"), where Grafana can show changes
// as annotations. The UI reads it back for the change history page and to
// resolve which policy revision was active when an event happened.
package journal

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/developmi/caddy-waf-ui/internal/config"
)

// Entry is one configuration change attempt.
type Entry struct {
	Kind     string    `json:"kind"`
	TS       time.Time `json:"ts"`
	Node     string    `json:"node,omitempty"`
	Site     string    `json:"site"`
	Action   string    `json:"action"`
	Summary  string    `json:"summary"`
	Reason   string    `json:"reason,omitempty"`
	Actor    string    `json:"actor,omitempty"`
	RemoteIP string    `json:"remote_ip,omitempty"`
	Revision string    `json:"rev,omitempty"`
	Result   string    `json:"result"`
	Error    string    `json:"error,omitempty"`
	SHA256   string    `json:"sha256,omitempty"`
	Stages   []Stage   `json:"stages,omitempty"`
	Diff     string    `json:"diff,omitempty"`
}

// Results.
const (
	ResultSuccess = "success"
	ResultFailed  = "failed"
)

const maxDiffBytes = 16 << 10

var mu sync.Mutex

// Path returns the journal file path inside the data directory.
func Path() string {
	return filepath.Join(config.DataDir(), "changes", "changes.jsonl")
}

// Append writes an entry. Journal failures never block a configuration
// change that Caddy already accepted; callers log the returned error.
func Append(e Entry) error {
	e.Kind = "change"
	if e.TS.IsZero() {
		e.TS = time.Now().UTC()
	}
	if e.Node == "" {
		e.Node = config.NodeName()
	}
	if len(e.Diff) > maxDiffBytes {
		e.Diff = e.Diff[:maxDiffBytes] + "\n… (diff truncated)"
	}
	line, err := json.Marshal(e)
	if err != nil {
		return err
	}
	mu.Lock()
	defer mu.Unlock()
	path := Path()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	// The data directory is operator-configured (CADDY_UI_DATA_DIR).
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o640) //nolint:gosec // G304/G302: operator-configured path; shared UID/GID 65532, no world access.
	if err != nil {
		return err
	}
	if _, err := f.Write(append(line, '\n')); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// Filter narrows List.
type Filter struct {
	Site  string
	Limit int
}

// List returns entries newest first. A missing journal is empty.
func List(f Filter) ([]Entry, error) {
	mu.Lock()
	defer mu.Unlock()
	file, err := os.Open(Path())
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	entries, err := decode(file, f.Site)
	if err != nil {
		return nil, err
	}
	sort.SliceStable(entries, func(i, j int) bool { return entries[i].TS.After(entries[j].TS) })
	if f.Limit > 0 && len(entries) > f.Limit {
		entries = entries[:f.Limit]
	}
	return entries, nil
}

func decode(r io.Reader, site string) ([]Entry, error) {
	var entries []Entry
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64*1024), 1<<20)
	for scanner.Scan() {
		var e Entry
		if err := json.Unmarshal(scanner.Bytes(), &e); err != nil {
			// A torn last line after a crash must not hide the history.
			continue
		}
		if site != "" && e.Site != site {
			continue
		}
		entries = append(entries, e)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read journal: %w", err)
	}
	return entries, nil
}

// Stage describes the evidence available for a publication step.
type Stage struct {
	Name   string `json:"name"`
	Result string `json:"result"`
	Detail string `json:"detail,omitempty"`
}
