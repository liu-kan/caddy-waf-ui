package logs

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/developmi/caddy-waf-ui/internal/config"
)

// Normalized actions consumed by the UI (D7): the logs.html template only
// knows BLOCKED/DETECTED.
const (
	actionBlocked  = "BLOCKED"
	actionDetected = "DETECTED"
)

// defaultPageSize is the default page size of the explorer (D7).
const defaultPageSize = 50

// maxTailBytes bounds the read window to the last 2 MiB of the audit log
// (D7): the whole file is never read. It is a variable so tests can shrink
// it without generating huge fixtures.
var maxTailBytes int64 = 2 << 20

// layoutApache is the timestamp format of the Coraza audit log
// ("02/Jan/2006:15:04:20 -0700", see internal/auditlog/auditlog.go).
const layoutApache = "02/Jan/2006:15:04:05 -0700"

// Options controls the filtering and pagination of Read.
type Options struct {
	Search   string // case-insensitive search over client/uri/ruleID/message
	Action   string // "BLOCKED", "DETECTED" or "" (all)
	Page     int    // 1-based; values <= 0 are treated as 1
	PageSize int    // <= 0 → defaultPageSize (50)
}

// Page is a page of entries plus the pagination context.
type Page struct {
	Entries  []AuditEntry
	Page     int
	PageSize int
	Total    int
	Pages    int
}

// AuditLogPath returns the configured path of the Coraza audit log
// (CADDY_UI_AUDIT_LOG; default /data/logs/coraza-audit.log - D7). The value
// lives centralized in config (finding J5-3); this function is kept as a
// delegate so the call sites that use it as a package API do not break.
func AuditLogPath() string {
	return config.AuditLogPath()
}

// Read reads the tail window (2 MiB) of the Coraza audit log, parses the
// records, filters by search/action and paginates the result (newest first).
// It supports two formats: JSONL with newlines (the ReadBytes loop) and
// concatenated JSON objects WITHOUT newlines (the caddy-waf plugin v3.3.1
// appends without "\n"; json.Decoder reads them one at a time). A record that
// fails to parse is logged with slog.Error (spec audit-logs: never silently
// discarded) and reading continues with the rest.
func Read(path string, opts Options) (Page, error) {
	f, err := os.Open(path)
	if err != nil {
		return Page{}, err
	}
	defer func() { _ = f.Close() }()

	data, err := tailWindow(f)
	if err != nil {
		return Page{}, err
	}

	entries := make([]AuditEntry, 0, 64)
	if bytes.IndexByte(data, '\n') < 0 && len(bytes.TrimSpace(data)) > 0 {
		// Stream without newlines (caddy-waf plugin v3.3.1): concatenated
		// JSON objects, one object per detected transaction.
		dec := json.NewDecoder(bytes.NewReader(data))
		for {
			var l auditLine
			err := dec.Decode(&l)
			if err == io.EOF {
				break
			}
			if err != nil {
				// Fail-loud: after a decode error the boundary between
				// objects cannot be re-synced; it is logged and cut short.
				slog.Error("unparseable newline-less audit log", "path", path, "error", err)
				break
			}
			entry, perr := entryFromLine(l)
			if perr != nil {
				// Fail-loud: unknown formats are never ignored.
				slog.Error("unparseable audit log entry", "path", path, "error", perr)
				continue
			}
			if matches(entry, opts.Search, opts.Action) {
				entries = append(entries, entry)
			}
		}
	} else {
		// Plain JSONL: one entry per line.
		reader := bufio.NewReader(bytes.NewReader(data))
		lineNum := 0
		for {
			line, err := reader.ReadBytes('\n')
			lineNum++
			if len(bytes.TrimSpace(line)) > 0 {
				entry, perr := parseLine(line)
				if perr != nil {
					// Fail-loud: unknown formats are never ignored.
					slog.Error("unparseable audit log line", "path", path, "line", lineNum, "error", perr)
				} else if matches(entry, opts.Search, opts.Action) {
					entries = append(entries, entry)
				}
			}
			if err != nil {
				if err != io.EOF {
					return Page{}, err
				}
				break
			}
		}
	}

	// The log grows towards the end: newest first.
	for i, j := 0, len(entries)-1; i < j; i, j = i+1, j-1 {
		entries[i], entries[j] = entries[j], entries[i]
	}
	return paginate(entries, opts.Page, opts.PageSize), nil
}

// tailWindow returns the last maxTailBytes of the file. If the file is
// smaller it is read in full; if the window cuts a line in half, the first
// line of the window is discarded (it may be incomplete; the recent data,
// which lives at the end, stays intact).
func tailWindow(f *os.File) ([]byte, error) {
	stat, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if stat.Size() <= maxTailBytes {
		return io.ReadAll(f)
	}
	offset := stat.Size() - maxTailBytes
	buf := make([]byte, maxTailBytes)
	if _, err := f.ReadAt(buf, offset); err != nil && err != io.EOF {
		return nil, err
	}
	// Coraza's serial writer can concatenate JSON without newlines. Seek
	// the next complete transaction rather than decoding a truncated object.
	// Quotes inside JSON strings are escaped, so this cannot match rule data.
	if i := bytes.Index(buf, []byte(`{"transaction":`)); i >= 0 {
		return buf[i:], nil
	}
	if i := bytes.IndexByte(buf, '\n'); i >= 0 {
		buf = buf[i+1:]
	} else {
		return nil, nil
	}
	return buf, nil
}

// auditLine is the JSON shape of a Coraza audit log entry (formats_json.go
// of coraza v3). coraza v3 does not emit the transaction.action field (the
// action lives in the actionsets and in is_interrupted), but it is accepted
// for compatibility with legacy formats or third-party writers.
type auditLine struct {
	Transaction auditTransaction `json:"transaction"`
	Messages    []auditMessage   `json:"messages"`
}

type auditTransaction struct {
	Timestamp     string `json:"timestamp"`
	UnixTimestamp int64  `json:"unix_timestamp"`
	ID            string `json:"id"`
	ClientIP      string `json:"client_ip"`
	IsInterrupted *bool  `json:"is_interrupted"`
	Action        string `json:"action"`
	Request       *struct {
		URI string `json:"uri"`
	} `json:"request"`
}

type auditMessage struct {
	Message   string        `json:"message"`
	Actionset string        `json:"actionset"`
	Data      *auditMsgData `json:"data"`
}

type auditMsgData struct {
	ID  int    `json:"id"`
	Msg string `json:"msg"`
}

// entryFromLine maps an already deserialized auditLine to AuditEntry.
// Without a transaction.id it returns an error: the reader logs it
// (fail-loud). It is the mapping shared by parseLine (JSONL) and the Decoder
// branch of the newline-less stream of the caddy-waf plugin v3.3.1.
func entryFromLine(l auditLine) (AuditEntry, error) {
	if l.Transaction.ID == "" {
		return AuditEntry{}, fmt.Errorf("line without transaction.id (unknown format)")
	}

	entry := AuditEntry{
		Timestamp: normalizeTimestamp(l.Transaction.Timestamp, l.Transaction.UnixTimestamp),
		Client:    l.Transaction.ClientIP,
		Action:    classifyTransaction(l.Transaction.Action, l.Transaction.IsInterrupted, actionsetsOf(l.Messages)),
	}
	if l.Transaction.Request != nil {
		entry.URI = l.Transaction.Request.URI
	}
	for _, m := range l.Messages {
		if entry.Message == "" {
			entry.Message = m.Message
		}
		if entry.RuleID == "" && m.Data != nil && m.Data.ID > 0 {
			entry.RuleID = strconv.Itoa(m.Data.ID)
		}
	}
	return entry, nil
}

// parseLine converts a JSONL line to an AuditEntry. Any shape that is not a
// Coraza entry (invalid JSON or without transaction.id) returns an error: the
// reader logs it with the line number (fail-loud).
func parseLine(raw []byte) (AuditEntry, error) {
	var l auditLine
	if err := json.Unmarshal(raw, &l); err != nil {
		return AuditEntry{}, err
	}
	return entryFromLine(l)
}

// actionsetsOf extracts the actionsets from the messages for the disruptive
// action classification (D7: deny/drop/redirect → BLOCKED; pass/allow →
// DETECTED).
func actionsetsOf(messages []auditMessage) []string {
	sets := make([]string, 0, len(messages))
	for _, m := range messages {
		sets = append(sets, m.Actionset)
	}
	return sets
}

// The actual interruption flag takes priority: deny also appears on matched
// rules in DetectionOnly. An allow action can end WAF processing without denial.
func classifyTransaction(txAction string, interrupted *bool, actionsets []string) string {
	if interrupted != nil {
		if !*interrupted {
			return actionDetected
		}
		hasAllow := false
		for _, set := range actionsets {
			for _, token := range strings.Split(set, ",") {
				token = strings.Trim(strings.TrimSpace(token), "'\"")
				if token == "deny" || token == "drop" || token == "redirect" || strings.HasPrefix(token, "redirect:") {
					return actionBlocked
				}
				if token == "allow" {
					hasAllow = true
				}
			}
		}
		if hasAllow || strings.EqualFold(txAction, "allow") {
			return actionDetected
		}
		return actionBlocked
	}
	switch strings.ToLower(strings.TrimSpace(txAction)) {
	case "deny", "drop", "redirect":
		return actionBlocked
	case "pass", "allow":
		return actionDetected
	}
	for _, set := range actionsets {
		switch disruptiveVerb(set) {
		case "deny", "drop", "redirect":
			return actionBlocked
		case "pass", "allow":
			continue
		}
	}
	return actionDetected
}

// disruptiveVerb returns the first disruptive action verb of a Coraza
// actionset (comma-separated action list), or "". redirect accepts a value
// ("redirect:https://..."), the rest are bare verbs.
func disruptiveVerb(actionset string) string {
	for _, token := range strings.Split(actionset, ",") {
		token = strings.Trim(strings.TrimSpace(token), "'\"")
		switch {
		case token == "deny" || token == "drop" || token == "redirect" || strings.HasPrefix(token, "redirect:"):
			return "deny"
		case token == "pass" || token == "allow":
			return "pass"
		}
	}
	return ""
}

// matches decides whether an entry passes the filters: exact action
// (case-insensitive) and search as a case-insensitive substring over
// client/uri/ruleID/message.
func matches(e AuditEntry, search, action string) bool {
	if action != "" && !strings.EqualFold(e.Action, action) {
		return false
	}
	search = strings.TrimSpace(search)
	if search == "" {
		return true
	}
	needle := strings.ToLower(search)
	for _, hay := range []string{e.Client, e.URI, e.RuleID, e.Message} {
		if strings.Contains(strings.ToLower(hay), needle) {
			return true
		}
	}
	return false
}

// paginate slices the filtered list by page/pageSize (1-based) and returns
// the pagination context. Out-of-range pages are clamped to the last one;
// Entries is never nil (the template uses {{ if .Logs }}).
func paginate(entries []AuditEntry, page, pageSize int) Page {
	if entries == nil {
		entries = []AuditEntry{}
	}
	if page < 1 {
		page = 1
	}
	if pageSize < 1 {
		pageSize = defaultPageSize
	}
	total := len(entries)
	pages := 0
	if total > 0 {
		pages = (total + pageSize - 1) / pageSize
	}
	if page > pages {
		page = pages
	}
	if page < 1 {
		page = 1
	}
	start := (page - 1) * pageSize
	end := start + pageSize
	if start > total {
		start = total
	}
	if end > total {
		end = total
	}
	return Page{Entries: entries[start:end], Page: page, PageSize: pageSize, Total: total, Pages: pages}
}

// normalizeTimestamp converts the Coraza timestamp (Apache format) to
// RFC3339 so the date helper of the templates can format it; if it is not
// recognized, it keeps the raw value. Without a timestamp it uses
// unix_timestamp.
func normalizeTimestamp(ts string, unix int64) string {
	if ts != "" {
		if parsed, err := time.Parse(layoutApache, ts); err == nil {
			return parsed.Format(time.RFC3339)
		}
		return ts
	}
	if unix > 0 {
		return time.Unix(unix, 0).UTC().Format(time.RFC3339)
	}
	return ts
}
