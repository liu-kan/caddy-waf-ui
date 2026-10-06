package events

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// LocalMatch is match context recovered on demand from a raw audit record.
type LocalMatch struct {
	ID               int
	Var, Data, Value string
	Redacted         bool
}
type LocalRecord struct {
	File, Method, URI, Redaction string
	Headers                      map[string]string
	Matches                      []LocalMatch
}

var ErrLocalRecordNotFound = errors.New("raw audit record not available locally")
var ErrLocalScanLimit = errors.New("local audit scan budget reached; use a newer event or retained normalized context")
var txIDPattern = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,128}$`)

// maxLocalScan bounds the bytes scanned per lookup across all files when
// the event time cannot select the archive; maxCandidateScan bounds each
// time-selected file.
const (
	maxLocalScan     = 64 << 20
	maxCandidateScan = 256 << 20
)

// rotatedLayout is the UTC suffix of rotated archives (service.RotateAudit).
const rotatedLayout = "20060102T150405.000000000Z"

// rotationSlack: right after a rotation, old WAF instances keep appending
// to the renamed file until every site has reopened its log.
const rotationSlack = 5 * time.Minute

var localScanGate = make(chan struct{}, 1)

// FindLocalRecord preserves the original convenience API. The standard
// policy now also protects URL credentials and unclassified logdata.
func FindLocalRecord(path, tx string) (*LocalRecord, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return FindLocalRecordWithPolicy(ctx, path, &Event{TxID: tx}, Redaction{Level: LevelStandard})
}

// FindLocalRecordWithPolicy never bypasses the configured local policy.
// It accepts compact, formatted and concatenated JSON objects and limits
// concurrent scans, elapsed time and total bytes for small deployments.
func FindLocalRecordWithPolicy(ctx context.Context, auditPath string, event *Event, policy Redaction) (*LocalRecord, error) {
	if event == nil || !txIDPattern.MatchString(event.TxID) {
		return nil, errors.New("invalid transaction id")
	}
	select {
	case localScanGate <- struct{}{}:
		defer func() { <-localScanGate }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	// The event time selects the file directly, so a long archive retention
	// does not turn every lookup into a scan of all archives.
	tried := map[string]bool{}
	if !event.TS.IsZero() {
		candidates, err := localCandidates(auditPath, event.TS)
		if err != nil {
			return nil, err
		}
		for _, name := range candidates {
			tried[name] = true
			rec, _, err := scanLocalFile(ctx, name, event, maxCandidateScan)
			if err != nil && !errors.Is(err, os.ErrNotExist) {
				return nil, err
			}
			if rec != nil {
				return localFromRecord(rec, name, policy), nil
			}
		}
	}
	archives, err := filepath.Glob(auditPath + ".rotated-*")
	if err != nil {
		return nil, err
	}
	sort.Sort(sort.Reverse(sort.StringSlice(archives)))
	budget := int64(maxLocalScan)
	for _, name := range append([]string{auditPath}, archives...) {
		if tried[name] {
			continue
		}
		rec, n, err := scanLocalFile(ctx, name, event, budget)
		budget -= n
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		if rec != nil {
			return localFromRecord(rec, name, policy), nil
		}
		if budget <= 0 {
			return nil, ErrLocalScanLimit
		}
	}
	return nil, ErrLocalRecordNotFound
}

// localCandidates returns the raw files that may hold a record written at
// ts, most likely first: the first archive rotated after ts (or the live
// file), then the previous file when ts falls right after its rotation.
// Archives whose name carries no rotation time are left to the fallback scan.
func localCandidates(auditPath string, ts time.Time) ([]string, error) {
	paths, err := filepath.Glob(auditPath + ".rotated-*")
	if err != nil {
		return nil, err
	}
	type archive struct {
		path string
		at   time.Time
	}
	var list []archive
	for _, p := range paths {
		at, err := time.Parse(rotatedLayout, strings.TrimPrefix(p, auditPath+".rotated-"))
		if err == nil {
			list = append(list, archive{p, at})
		}
	}
	sort.Slice(list, func(i, j int) bool { return list[i].at.Before(list[j].at) })
	i := sort.Search(len(list), func(i int) bool { return list[i].at.After(ts) })
	out := []string{auditPath}
	if i < len(list) {
		out[0] = list[i].path
	}
	if i > 0 && ts.Sub(list[i-1].at) < rotationSlack {
		out = append(out, list[i-1].path)
	}
	return out, nil
}

// deadlineReader is bounded independently of record boundaries, so a
// single oversized or incomplete JSON object cannot exhaust scan memory.
type deadlineReader struct {
	ctx                              context.Context
	reader                           io.Reader
	remaining, read, recordRemaining int64
}

func (r *deadlineReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	if r.remaining <= 0 || r.recordRemaining <= 0 {
		return 0, ErrLocalScanLimit
	}
	limit := min(r.remaining, r.recordRemaining)
	if int64(len(p)) > limit {
		p = p[:limit]
	}
	n, err := r.reader.Read(p)
	r.remaining -= int64(n)
	r.recordRemaining -= int64(n)
	r.read += int64(n)
	return n, err
}
func scanLocalFile(ctx context.Context, path string, event *Event, budget int64) (*auditRecord, int64, error) {
	f, err := os.Open(path) //nolint:gosec // G304: operator-selected raw audit path and generated archives.
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = f.Close() }()
	r := &deadlineReader{ctx: ctx, reader: f, remaining: budget, recordRemaining: defaultChunk}
	dec := json.NewDecoder(r)
	for {
		var rec auditRecord
		if err := dec.Decode(&rec); err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				return nil, r.read, nil
			}
			return nil, r.read, err
		}
		r.recordRemaining = defaultChunk - (r.read - dec.InputOffset())
		if rec.Transaction.ID != event.TxID {
			continue
		}
		if !event.TS.IsZero() && (rec.Transaction.UnixTimestamp != 0 || rec.Transaction.Timestamp != "") {
			ts := recordTime(rec.Transaction.Timestamp, rec.Transaction.UnixTimestamp)
			if ts.Sub(event.TS) > time.Second || event.TS.Sub(ts) > time.Second {
				continue
			}
		}
		// A supplied Host also prevents transaction-id reuse selecting another site.
		if event.Host != "" && rec.Transaction.Request != nil {
			host := headerValue(rec.Transaction.Request.Headers, "host")
			if host != "" && !strings.EqualFold(localHost(host), localHost(event.Host)) && !strings.EqualFold(localHost(rec.Transaction.ServerID), localHost(event.Host)) {
				continue
			}
		}
		return &rec, r.read, nil
	}
}

func localFromRecord(rec *auditRecord, path string, policy Redaction) *LocalRecord {
	e := &Event{}
	if rec.Transaction.Request != nil {
		req := rec.Transaction.Request
		e.Method = req.Method
		e.Path, e.QueryKeys = splitURI(req.URI)
		if u, err := url.ParseRequestURI(req.URI); err == nil {
			e.Query = u.RawQuery
		}
		e.Headers = requestHeaders(req.Headers)
	}
	for _, m := range rec.Messages {
		if m.Data == nil || m.Data.ID == 0 || (m.Data.Msg == "" && m.Data.Data == "") {
			continue
		}
		variable, data, value := splitLogdataRaw(m.Data.Data)
		e.Hits = append(e.Hits, Hit{ID: m.Data.ID, Var: variable, Data: data, Value: value})
	}
	e = policy.Apply(e)
	out := &LocalRecord{File: filepath.Base(path), Method: e.Method, URI: e.Path, Headers: e.Headers, Redaction: e.Redaction}
	if e.Query != "" {
		out.URI += "?" + e.Query
	}
	for _, h := range e.Hits {
		out.Matches = append(out.Matches, LocalMatch{ID: h.ID, Var: h.Var, Data: h.Data, Value: h.Value, Redacted: h.Data == redacted || h.Value == redacted})
	}
	return out
}

func localHost(host string) string {
	if name, _, err := net.SplitHostPort(host); err == nil {
		return strings.Trim(name, "[]")
	}
	return strings.Trim(host, "[]")
}
