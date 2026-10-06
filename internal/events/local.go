package events

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"sort"
)

// LocalMatch is the match context of one rule recovered from the raw local
// audit record.
type LocalMatch struct {
	ID       int
	Var      string
	Data     string
	Value    string
	Redacted bool
}

// LocalRecord is the local-only request context of an event. Normalized
// events never carry matched values unless explicitly enabled; operators
// can still review them here while the raw audit file or its rotated
// archives exist. Nothing found here is stored or shipped.
type LocalRecord struct {
	File    string
	Method  string
	URI     string
	Matches []LocalMatch
}

var (
	// ErrLocalRecordNotFound means the raw record was rotated away (archives
	// are kept for 48 hours) or the event came from another node.
	ErrLocalRecordNotFound = errors.New("raw audit record not available locally")
	txIDPattern            = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,128}$`)
)

// maxLocalScan bounds the bytes scanned per lookup across all files.
const maxLocalScan = 512 << 20

// FindLocalRecord looks for transaction tx in the raw Coraza audit log and
// its rotated archives, newest first. Credential-like variables stay
// redacted; other matched fragments are returned for local review.
func FindLocalRecord(auditPath, tx string) (*LocalRecord, error) {
	if !txIDPattern.MatchString(tx) {
		return nil, errors.New("invalid transaction id")
	}
	archives, _ := filepath.Glob(auditPath + ".rotated-*")
	sort.Sort(sort.Reverse(sort.StringSlice(archives)))
	paths := append([]string{auditPath}, archives...)
	needle := []byte(`"id":"` + tx + `"`)
	budget := int64(maxLocalScan)
	for _, path := range paths {
		rec, scanned, err := scanForTransaction(path, needle, tx, budget)
		budget -= scanned
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		if rec != nil {
			return localFromRecord(rec, path), nil
		}
		if budget <= 0 {
			break
		}
	}
	return nil, ErrLocalRecordNotFound
}

func scanForTransaction(path string, needle []byte, tx string, budget int64) (*auditRecord, int64, error) {
	f, err := os.Open(path) //nolint:gosec // G304: operator-configured audit log and its rotated archives.
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = f.Close() }()
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 8<<20)
	var scanned int64
	for scanner.Scan() {
		line := scanner.Bytes()
		scanned += int64(len(line) + 1)
		if bytes.Contains(line, needle) {
			var rec auditRecord
			if json.Unmarshal(line, &rec) == nil && rec.Transaction.ID == tx {
				return &rec, scanned, nil
			}
		}
		if scanned >= budget {
			break
		}
	}
	return nil, scanned, scanner.Err()
}

func localFromRecord(rec *auditRecord, path string) *LocalRecord {
	out := &LocalRecord{File: filepath.Base(path)}
	if rec.Transaction.Request != nil {
		out.Method = rec.Transaction.Request.Method
		out.URI = truncate(rec.Transaction.Request.URI, maxPathLen)
	}
	for _, m := range rec.Messages {
		if m.Data == nil || m.Data.ID == 0 || (m.Data.Msg == "" && m.Data.Data == "") {
			continue
		}
		v, data, value := splitLogdata(m.Data.Data)
		lm := LocalMatch{ID: m.Data.ID, Var: v, Data: data, Value: value}
		if v != "" && sensitiveVar.MatchString(v) {
			lm.Data, lm.Value, lm.Redacted = redacted, redacted, true
		}
		out.Matches = append(out.Matches, lm)
	}
	return out
}
