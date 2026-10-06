package events

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/developmi/caddy-waf-ui/internal/files"
	"github.com/developmi/caddy-waf-ui/internal/metrics"
)

// IngestState is the persisted read position in the Coraza audit log.
type IngestState struct {
	Path   string `json:"path"`
	Dev    uint64 `json:"dev"`
	Ino    uint64 `json:"ino"`
	Offset int64  `json:"offset"`
	// Tail holds the bytes just before Offset. If they differ on the next
	// poll the file was truncated and rewritten in place (copytruncate)
	// and is read again from the start.
	Tail    []byte    `json:"tail,omitempty"`
	Updated time.Time `json:"updated"`
}

const tailLen = 32

// IngestStatus is shown on the event pages.
type IngestStatus struct {
	Path      string
	Size      int64
	Offset    int64
	LastPoll  time.Time
	LastEvent time.Time
	LastError string
	Ingested  int64
}

// Ingester follows the Coraza audit log (JSON lines in Coraza v3; also
// newline-less concatenated objects of older writers), normalizes new
// records into the store and remembers its position across restarts.
type Ingester struct {
	Path           string
	StatePath      string
	Store          *Store
	Norm           *Normalizer
	CloudStore     *Store
	CloudRedaction Redaction
	// ChunkSize bounds the bytes read per poll.
	ChunkSize int64

	mu     sync.Mutex
	state  IngestState
	status IngestStatus
	loaded bool
}

const defaultChunk = 8 << 20

var transactionMarker = []byte(`{"transaction":`)

// Status returns a snapshot of the ingestion state.
func (in *Ingester) Status() IngestStatus {
	in.mu.Lock()
	defer in.mu.Unlock()
	st := in.status
	st.Path = in.Path
	st.Offset = in.state.Offset
	return st
}

// Run polls until ctx ends.
func (in *Ingester) Run(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		if err := in.PollArchives(); err != nil {
			slog.Warn("audit archive ingestion failed", "error", err)
		}
		if err := in.Poll(); err != nil {
			slog.Warn("audit log ingestion failed", "path", in.Path, "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (in *Ingester) loadState() {
	if in.loaded {
		return
	}
	in.loaded = true
	data, err := os.ReadFile(in.StatePath)
	if err != nil {
		return
	}
	var st IngestState
	if json.Unmarshal(data, &st) == nil && st.Path == in.Path {
		in.state = st
	}
}

func (in *Ingester) saveState() error {
	in.state.Path = in.Path
	in.state.Updated = time.Now().UTC()
	data, err := json.Marshal(in.state)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(in.StatePath), 0o750); err != nil {
		return err
	}
	return files.AtomicWrite(in.StatePath, data)
}

// Poll ingests the records appended since the last poll.
func (in *Ingester) Poll() error {
	in.mu.Lock()
	defer in.mu.Unlock()
	in.loadState()
	in.status.LastPoll = time.Now().UTC()
	err := in.poll()
	if err != nil {
		in.status.LastError = err.Error()
		metrics.IngestErrors.Inc("read")
	} else {
		in.status.LastError = ""
	}
	return err
}

func (in *Ingester) poll() error {
	fi, err := os.Stat(in.Path)
	if errors.Is(err, os.ErrNotExist) {
		in.status.Size = 0
		return nil
	}
	if err != nil {
		return err
	}
	dev, ino := fileIdentity(fi)
	f, err := os.Open(in.Path) //nolint:gosec // G304: operator-configured audit log path (CADDY_UI_AUDIT_LOG).
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	if dev != in.state.Dev || ino != in.state.Ino || fi.Size() < in.state.Offset || !in.tailMatches(f) {
		// New file (rotation) or truncated by someone else: start over.
		in.state = IngestState{Dev: dev, Ino: ino}
	}
	in.status.Size = fi.Size()
	chunk := in.ChunkSize
	if chunk <= 0 {
		chunk = defaultChunk
	}
	size := fi.Size()
	for in.state.Offset < size {
		n := size - in.state.Offset
		if n > chunk {
			n = chunk
		}
		buf := make([]byte, n)
		read, err := f.ReadAt(buf, in.state.Offset)
		if err != nil && !errors.Is(err, io.EOF) {
			return err
		}
		consumed, perr := in.process(buf[:read], n < size-in.state.Offset)
		in.state.Offset += int64(consumed)
		if perr != nil {
			in.state.Tail = readTail(f, in.state.Offset)
			_ = in.saveState()
			return perr
		}
		if consumed == 0 {
			break // a partial record: wait for the writer
		}
	}
	in.state.Tail = readTail(f, in.state.Offset)
	if err := in.saveState(); err != nil {
		return fmt.Errorf("save ingest state: %w", err)
	}
	return nil
}

// readTail returns up to tailLen bytes ending at offset.
func readTail(f *os.File, offset int64) []byte {
	start := offset - tailLen
	if start < 0 {
		start = 0
	}
	buf := make([]byte, offset-start)
	n, _ := f.ReadAt(buf, start)
	return buf[:n]
}

func (in *Ingester) tailMatches(f *os.File) bool {
	if in.state.Offset == 0 || len(in.state.Tail) == 0 {
		return true
	}
	return bytes.Equal(readTail(f, in.state.Offset), in.state.Tail)
}

// process ingests the complete records of data and returns the bytes
// consumed. more reports that data is a bounded slice of a longer file.
func (in *Ingester) process(data []byte, more bool) (int, error) {
	consumed := 0
	for consumed < len(data) {
		rest := data[consumed:]
		// Skip whitespace and NUL padding (a write racing a truncation).
		skip := 0
		for skip < len(rest) && (rest[skip] == 0 || rest[skip] == '\n' || rest[skip] == '\r' || rest[skip] == ' ' || rest[skip] == '\t') {
			skip++
		}
		if skip > 0 {
			consumed += skip
			continue
		}
		if rest[0] != '{' {
			// Garbage: resynchronize on the next record or line.
			next := nextRecord(rest)
			if next < 0 {
				if !more {
					return consumed, nil
				}
				return consumed + len(rest), nil
			}
			metrics.IngestErrors.Inc("parse")
			consumed += next
			continue
		}
		dec := json.NewDecoder(bytes.NewReader(rest))
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			var syntax *json.SyntaxError
			if errors.As(err, &syntax) {
				metrics.IngestErrors.Inc("parse")
				next := nextRecord(rest[1:])
				if next < 0 {
					if more {
						return consumed + len(rest), nil
					}
					return consumed, nil
				}
				consumed += 1 + next
				continue
			}
			if len(rest) >= defaultChunk && more {
				// A single record larger than the read window: skip it.
				metrics.IngestErrors.Inc("parse")
				return consumed + len(rest), nil
			}
			return consumed, nil // incomplete record: wait for more data
		}
		end := int(dec.InputOffset())
		if err := in.ingest(raw); err != nil {
			return consumed, err
		}
		consumed += end
	}
	return consumed, nil
}

// nextRecord finds the next plausible record start after a parse error.
func nextRecord(b []byte) int {
	marker := bytes.Index(b, transactionMarker)
	line := bytes.IndexByte(b, '\n')
	switch {
	case marker >= 0 && (line < 0 || marker < line):
		return marker
	case line >= 0:
		return line + 1
	}
	return -1
}

func (in *Ingester) ingest(raw []byte) error {
	e, err := in.Norm.Normalize(raw)
	if err != nil {
		if errors.Is(err, ErrProbeRecord) || errors.Is(err, ErrNoRuleMatch) {
			return nil
		}
		metrics.IngestErrors.Inc("parse")
		slog.Debug("skipping unparseable audit record", "error", err)
		return nil
	}
	added, err := in.Store.Append(e, SourceLocal)
	if err != nil {
		metrics.IngestErrors.Inc("store")
		return fmt.Errorf("store event: %w", err)
	}
	if added {
		in.status.Ingested++
		in.status.LastEvent = e.TS
	}
	if in.CloudStore != nil {
		// Export retries even when the local append already succeeded.
		// Never recover detail from raw input that the retained event removed.
		if !added {
			if stored, ok := in.Store.GetFor(e.TxID, e.Node); ok {
				e = stored
			}
		}
		if _, err := in.CloudStore.Append(in.CloudRedaction.Apply(e), SourceLocal); err != nil {
			metrics.IngestErrors.Inc("export")
			return fmt.Errorf("export event: %w", err)
		}
	}
	return nil
}
