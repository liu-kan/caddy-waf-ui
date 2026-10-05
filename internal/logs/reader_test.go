package logs

import (
	"bytes"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// Fixtures of the Coraza v3 JSON format (SecAuditLogFormat JSON, coraza
// internal/auditlog: transaction.{timestamp,id,client_ip,is_interrupted,
// request.uri} + messages[].{message,actionset,data.id}).
var (
	fixtureValid     = filepath.Join("testdata", "audit-valid.jsonl")
	fixtureMalformed = filepath.Join("testdata", "audit-malformed.jsonl")
)

// captureLogs redirects slog to a buffer and restores it when the test ends.
func captureLogs(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return &buf
}

func TestReadParsesCorazaJSONLNewestFirst(t *testing.T) {
	got, err := Read(fixtureValid, Options{})
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}
	if len(got.Entries) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(got.Entries))
	}
	// The log grows towards the end: reading returns the newest first.
	if got.Entries[0].RuleID != "910000" || got.Entries[2].RuleID != "942100" {
		t.Errorf("the order must be newest-first (910000, 920420, 942100), got %+v", got.Entries)
	}

	blocked := got.Entries[2] // tx-0001: deny
	if blocked.Timestamp != "2026-08-06T14:23:11Z" {
		t.Errorf("timestamp must be normalized to RFC3339, got %q", blocked.Timestamp)
	}
	if blocked.Client != "1.2.3.4" {
		t.Errorf("client must be 1.2.3.4, got %q", blocked.Client)
	}
	if blocked.URI != "/wp-admin/login.php" {
		t.Errorf("uri must be /wp-admin/login.php, got %q", blocked.URI)
	}
	if blocked.Action != "BLOCKED" {
		t.Errorf("deny must map to BLOCKED, got %q", blocked.Action)
	}
	if blocked.Message != "Inbound XSS Attack Detected" {
		t.Errorf("message must be the message of the first rule, got %q", blocked.Message)
	}

	detected := got.Entries[1] // tx-0002: pass
	if detected.Action != "DETECTED" {
		t.Errorf("pass must map to DETECTED, got %q", detected.Action)
	}
	allowed := got.Entries[0] // tx-0003: allow
	if allowed.Action != "DETECTED" {
		t.Errorf("allow must map to DETECTED, got %q", allowed.Action)
	}
	if allowed.Timestamp != "2026-08-06T14:26:07Z" {
		t.Errorf("tx-0003 timestamp must be RFC3339, got %q", allowed.Timestamp)
	}
}

func TestReadFiltersByAction(t *testing.T) {
	got, err := Read(fixtureValid, Options{Action: "BLOCKED"})
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}
	if len(got.Entries) != 1 || got.Entries[0].RuleID != "942100" {
		t.Fatalf("actionFilter=BLOCKED must leave only the deny entry, got %+v", got.Entries)
	}
	if got.Total != 1 {
		t.Errorf("Total must reflect the filtered list, got %d", got.Total)
	}
}

func TestReadFiltersBySearchCaseInsensitive(t *testing.T) {
	cases := []struct {
		search string
		wantID string
	}{
		{"1.2.3.4", "942100"},  // client_ip
		{"WP-ADMIN", "942100"}, // uri, case-insensitive
		{"942100", "942100"},   // rule id
		{"xss attack", "942100"},
		{"203.0.113.9", "920420"},
		{"no-such-term", ""},
	}
	for _, tc := range cases {
		got, err := Read(fixtureValid, Options{Search: tc.search})
		if err != nil {
			t.Fatalf("Read(search=%q) failed: %v", tc.search, err)
		}
		if tc.wantID == "" {
			if len(got.Entries) != 0 {
				t.Errorf("search=%q must not match anything, got %d", tc.search, len(got.Entries))
			}
			continue
		}
		if len(got.Entries) != 1 || got.Entries[0].RuleID != tc.wantID {
			t.Errorf("search=%q must return %s, got %+v", tc.search, tc.wantID, got.Entries)
		}
	}
}

func TestReadPaginates(t *testing.T) {
	page1, err := Read(fixtureValid, Options{Page: 1, PageSize: 2})
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}
	if len(page1.Entries) != 2 || page1.Entries[0].RuleID != "910000" || page1.Entries[1].RuleID != "920420" {
		t.Fatalf("page 1 must bring 910000 and 920420, got %+v", page1.Entries)
	}
	if page1.Total != 3 || page1.Pages != 2 {
		t.Errorf("expected Total=3, Pages=2, got Total=%d Pages=%d", page1.Total, page1.Pages)
	}

	page2, err := Read(fixtureValid, Options{Page: 2, PageSize: 2})
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}
	if len(page2.Entries) != 1 || page2.Entries[0].RuleID != "942100" {
		t.Fatalf("page 2 must bring 942100, got %+v", page2.Entries)
	}

	// Out-of-range page: clamped to the last one.
	out, err := Read(fixtureValid, Options{Page: 9, PageSize: 2})
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}
	if out.Page != 2 || len(out.Entries) != 1 {
		t.Errorf("page=9 must be clamped to the last page (2), got page=%d len=%d", out.Page, len(out.Entries))
	}

	// Default values: pageSize 50, page 1.
	def, err := Read(fixtureValid, Options{})
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}
	if def.Page != 1 || def.PageSize != 50 || def.Pages != 1 {
		t.Errorf("expected defaults page=1 pageSize=50 pages=1, got page=%d pageSize=%d pages=%d", def.Page, def.PageSize, def.Pages)
	}
}

func TestReadMalformedLinesLoggedWithLineNumber(t *testing.T) {
	logs := captureLogs(t)

	got, err := Read(fixtureMalformed, Options{})
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}
	// The valid lines (1 and 4) survive; the invalid ones (2, 3 and 5) are logged.
	if len(got.Entries) != 2 {
		t.Fatalf("expected 2 valid entries, got %d: %+v", len(got.Entries), got.Entries)
	}
	if got.Entries[0].RuleID != "920420" || got.Entries[1].RuleID != "932100" {
		t.Errorf("expected newest-first order (920420, 932100), got %+v", got.Entries)
	}
	// Spec audit-logs: an unparseable line is never silently discarded.
	out := logs.String()
	if !strings.Contains(out, "unparseable") {
		t.Errorf("the error must be logged with slog.Error, output: %s", out)
	}
	for _, line := range []string{"line=2", "line=3", "line=5"} {
		if !strings.Contains(out, line) {
			t.Errorf("the error must include the line number %s, output: %s", line, out)
		}
	}
}

func TestReadTailWindowBounded(t *testing.T) {
	// Bounded window (D7): with a file larger than the window only the tail is
	// read; the first line of the window (possibly cut off) is discarded.
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	compact := func(id, ip, uri string) string {
		return `{"transaction":{"timestamp":"06/Aug/2026:15:00:00 +0000","unix_timestamp":1786028400,"id":"` + id +
			`","client_ip":"` + ip + `","client_port":1,"host_ip":"10.0.0.5","host_port":443,"server_id":"",` +
			`"request":{"method":"GET","protocol":"HTTP/1.1","uri":"` + uri + `","http_version":"1.1","headers":{},"body":"","files":[],"args":"","length":0},` +
			`"response":null,"producer":null,"highest_severity":"2","is_interrupted":true},"messages":[]}`
	}
	// Line 1 is long garbage (outside the window), line 2 is cut by the window
	// limit, lines 3 and 4 are complete inside the window.
	lineOld := strings.Repeat("x", 300) + "\n"
	lineCut := compact("tx-corte", "9.9.9.9", "/cortada") + "\n"
	lineA := compact("tx-9991", "9.9.9.1", "/ok1") + "\n"
	lineB := compact("tx-9992", "9.9.9.2", "/ok2") + "\n"
	content := lineOld + lineCut + lineA + lineB
	if err := os.WriteFile(path, []byte(content), 0640); err != nil {
		t.Fatalf("failed writing fixture: %v", err)
	}

	// The window starts 40 bytes into lineCut: it stays cut off, but lineA
	// and lineB enter complete.
	prev := maxTailBytes
	maxTailBytes = int64(len(content) - len(lineOld) - 40)
	t.Cleanup(func() { maxTailBytes = prev })

	logs := captureLogs(t)
	got, err := Read(path, Options{})
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}
	// Only the complete lines of the window (tx-9991 and tx-9992).
	if len(got.Entries) != 2 {
		t.Fatalf("the window must return only the complete lines at the end, got %d: %+v", len(got.Entries), got.Entries)
	}
	if got.Entries[0].Client != "9.9.9.2" || got.Entries[1].Client != "9.9.9.1" {
		t.Errorf("expected newest-first order 9.9.9.2, 9.9.9.1, got %+v", got.Entries)
	}
	// Line 1 (garbage) stayed outside the window: no parse error must be
	// logged, nor must the cut line be reported as an error.
	out := logs.String()
	if strings.Contains(out, "unparseable") {
		t.Errorf("the garbage outside the window must not be read (bounded read), logs: %s", out)
	}
	if strings.Contains(out, "tx-corte") {
		t.Errorf("the cut line must be discarded without error, logs: %s", out)
	}
}

// pluginAuditJSON builds an object in the format written by the caddy-waf
// plugin v3.3.1 (image ghcr.io/developmi/caddy-waf): actionset without a list
// of disruptive actions ("OWASP_CRS/4.28.0"), timestamp "YYYY/MM/DD HH:MM:SS"
// (not Apache) and unix_timestamp in nanoseconds.
func pluginAuditJSON(id, ip, uri string) string {
	return `{"transaction":{"timestamp":"2026/08/15 04:06:23","unix_timestamp":1786766783310338248,"id":"` + id +
		`","client_ip":"` + ip + `","client_port":1,"host_ip":"10.0.0.5","host_port":443,"server_id":"",` +
		`"request":{"method":"GET","protocol":"HTTP/1.1","uri":"` + uri + `","http_version":"1.1","headers":{},"body":"","files":[],"args":"","length":0},` +
		`"response":null,"producer":null,"highest_severity":"2","is_interrupted":false},` +
		`"messages":[{"actionset":"OWASP_CRS/4.28.0","message":"Path Traversal Attack (/../) or (/.../)",` +
		`"data":{"id":930100,"msg":"Path Traversal Attack (/../) or (/.../)"}}]}`
}

func TestReadParsesPluginJSONWithoutNewlines(t *testing.T) {
	// The caddy-waf plugin v3.3.1 writes the audit log as concatenated JSON
	// objects WITHOUT \n (the whole stream falls into one "line" and the
	// JSONL loop cannot split it): the Decoder branch must read the complete
	// object.
	dir := t.TempDir()
	path := filepath.Join(dir, "coraza-audit.log")
	content := pluginAuditJSON("sbFfTCoDDhkAiWoq", "172.80.3.1", "/?q=../../etc/passwd")
	if err := os.WriteFile(path, []byte(content), 0640); err != nil {
		t.Fatalf("failed writing fixture: %v", err)
	}

	got, err := Read(path, Options{})
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}
	if len(got.Entries) != 1 {
		t.Fatalf("expected 1 entry, got %d: %+v", len(got.Entries), got.Entries)
	}
	e := got.Entries[0]
	if e.Client != "172.80.3.1" {
		t.Errorf("client must be 172.80.3.1, got %q", e.Client)
	}
	if e.URI != "/?q=../../etc/passwd" {
		t.Errorf("uri must be /?q=../../etc/passwd, got %q", e.URI)
	}
	if e.RuleID != "930100" {
		t.Errorf("ruleID must be 930100, got %q", e.RuleID)
	}
	if e.Action != "DETECTED" {
		t.Errorf("without action or is_interrupted the default must be DETECTED, got %q", e.Action)
	}
	if !strings.Contains(e.Message, "Path Traversal") {
		t.Errorf("message must contain 'Path Traversal', got %q", e.Message)
	}
}

func TestReadParsesConcatenatedJSONWithoutNewlines(t *testing.T) {
	// Two concatenated objects without \n (the plugin append adds no
	// separators): they must be read as two entries, newest-first.
	dir := t.TempDir()
	path := filepath.Join(dir, "coraza-audit.log")
	content := pluginAuditJSON("tx-9991", "10.0.0.1", "/a") +
		pluginAuditJSON("tx-9992", "10.0.0.2", "/b")
	if err := os.WriteFile(path, []byte(content), 0640); err != nil {
		t.Fatalf("failed writing fixture: %v", err)
	}

	got, err := Read(path, Options{})
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}
	if len(got.Entries) != 2 {
		t.Fatalf("expected 2 entries, got %d: %+v", len(got.Entries), got.Entries)
	}
	if got.Entries[0].Client != "10.0.0.2" || got.Entries[1].Client != "10.0.0.1" {
		t.Errorf("expected newest-first order 10.0.0.2, 10.0.0.1, got %+v", got.Entries)
	}
	if got.Total != 2 {
		t.Errorf("Total must be 2, got %d", got.Total)
	}
}

func TestReadMissingFileReturnsError(t *testing.T) {
	if _, err := Read(filepath.Join(t.TempDir(), "no-such-file.log"), Options{}); err == nil {
		t.Fatal("expected an error with a nonexistent file")
	}
}

func TestAuditLogPathFromEnvWithDefault(t *testing.T) {
	t.Setenv("CADDY_UI_AUDIT_LOG", "/tmp/audit.log")
	if got := AuditLogPath(); got != "/tmp/audit.log" {
		t.Errorf("AuditLogPath must read CADDY_UI_AUDIT_LOG, got %q", got)
	}
	t.Setenv("CADDY_UI_AUDIT_LOG", "")
	if got := AuditLogPath(); got != "/data/logs/coraza-audit.log" {
		t.Errorf("without env the default must be /data/logs/coraza-audit.log, got %q", got)
	}
}

func TestClassifyActionMapping(t *testing.T) {
	cases := []struct {
		name        string
		txAction    string
		interrupted bool
		actionsets  []string
		want        string
	}{
		{"explicit deny", "deny", false, nil, "DETECTED"},
		{"explicit drop", "drop", false, nil, "DETECTED"},
		{"explicit redirect", "redirect", false, nil, "DETECTED"},
		{"explicit pass", "pass", false, nil, "DETECTED"},
		{"explicit allow", "allow", false, nil, "DETECTED"},
		{"deny in actionset", "", false, []string{"id:942100,phase:2,deny,log"}, "DETECTED"},
		{"redirect with value in actionset", "", false, []string{"id:12345,phase:2,redirect:https://x/blocked,log"}, "DETECTED"},
		{"pass in actionset", "", false, []string{"id:920420,phase:2,pass,log"}, "DETECTED"},
		{"allow in actionset beats is_interrupted", "", true, []string{"id:910000,phase:1,allow,log"}, "DETECTED"},
		{"no verbs but interrupted", "", true, []string{"id:920000,phase:2,log"}, "BLOCKED"},
		{"no signals", "", false, nil, "DETECTED"},
		{"explicit action beats actionset", "deny", false, []string{"id:910000,phase:1,allow,log"}, "DETECTED"},
	}
	for _, tc := range cases {
		if got := classifyTransaction(tc.txAction, &tc.interrupted, tc.actionsets); got != tc.want {
			t.Errorf("%s: expected %s, got %s", tc.name, tc.want, got)
		}
	}
}

func TestPaginatePure(t *testing.T) {
	entries := make([]AuditEntry, 55)
	for i := range entries {
		entries[i] = AuditEntry{RuleID: strconv.Itoa(i)}
	}

	p1 := paginate(entries, 1, 50)
	if len(p1.Entries) != 50 || p1.Total != 55 || p1.Pages != 2 {
		t.Fatalf("page 1: expected 50 entries, Total 55, Pages 2; got len=%d Total=%d Pages=%d", len(p1.Entries), p1.Total, p1.Pages)
	}
	p2 := paginate(entries, 2, 50)
	if len(p2.Entries) != 5 {
		t.Fatalf("page 2: expected 5 entries, got %d", len(p2.Entries))
	}
	if p2.Entries[0].RuleID != "50" {
		t.Errorf("entry 51 must be the index 50 one, got %q", p2.Entries[0].RuleID)
	}

	empty := paginate(nil, 1, 50)
	if empty.Entries == nil || len(empty.Entries) != 0 || empty.Page != 1 || empty.Pages != 0 {
		t.Fatalf("empty list: non-nil empty Entries, Page 1, Pages 0; got %+v", empty)
	}

	def := paginate(entries, 0, 0)
	if def.Page != 1 || def.PageSize != 50 {
		t.Errorf("page=0/pageSize=0 must fall back to 1/50, got page=%d pageSize=%d", def.Page, def.PageSize)
	}
}

func TestParseLineRejectsUnknownFormat(t *testing.T) {
	if _, err := parseLine([]byte("this is not json")); err == nil {
		t.Error("a non-JSON line must return an error")
	}
	if _, err := parseLine([]byte(`{"foo":"bar"}`)); err == nil {
		t.Error("JSON without transaction.id must return an error (unknown format)")
	}
}

func TestNormalizeTimestamp(t *testing.T) {
	cases := []struct {
		ts   string
		unix int64
		want string
	}{
		{"06/Aug/2026:14:23:11 +0000", 0, "2026-08-06T14:23:11Z"}, // Apache layout of Coraza
		{"", 1786026367, "2026-08-06T14:26:07Z"},                  // unix_timestamp fallback
		{"unknown-format", 0, "unknown-format"},                   // the raw value is preserved
		{"", 0, ""},                                               // no data
	}
	for _, tc := range cases {
		if got := normalizeTimestamp(tc.ts, tc.unix); got != tc.want {
			t.Errorf("normalizeTimestamp(%q, %d): expected %q, got %q", tc.ts, tc.unix, tc.want, got)
		}
	}
}
