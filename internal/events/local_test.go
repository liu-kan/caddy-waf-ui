package events

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFindLocalRecordInLogAndArchives(t *testing.T) {
	data, err := os.ReadFile("testdata/coraza-3.8.0-audit.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	dir := t.TempDir()
	audit := filepath.Join(dir, "coraza-audit.log")
	// The first records were rotated away; the rest are in the live file.
	if err := os.WriteFile(audit+".rotated-20261005T000000.000000000Z", []byte(strings.Join(lines[:4], "\n")+"\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(audit, []byte(strings.Join(lines[4:], "\n")+"\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	git, err := FindLocalRecord(audit, "YqBrJkwPrpHwOYMd")
	if err != nil {
		// The fixture's first record id is fixed by the recording.
		t.Fatalf("archived record: %v", err)
	}
	if git.URI != "/.git/config" || git.Matches[0].ID != 930130 || git.Matches[0].Data != ".git/" || git.Matches[0].Var != "REQUEST_FILENAME" {
		t.Fatalf("archived record context: %+v", git)
	}
	var cookieTx string
	norm := &Normalizer{}
	for _, l := range lines {
		if strings.Contains(l, "REQUEST_COOKIES:session") {
			e, err := norm.Normalize([]byte(l))
			if err == nil {
				cookieTx = e.TxID
			}
		}
	}
	cookie, err := FindLocalRecord(audit, cookieTx)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range cookie.Matches {
		if strings.HasPrefix(m.Var, "REQUEST_COOKIES") && (!m.Redacted || m.Data != redacted) {
			t.Fatalf("cookie values must stay hidden locally too: %+v", m)
		}
	}
	if _, err := FindLocalRecord(audit, "missing-tx"); !errors.Is(err, ErrLocalRecordNotFound) {
		t.Fatalf("missing: %v", err)
	}
	if _, err := FindLocalRecord(audit, `x" or "1`); err == nil {
		t.Fatal("transaction ids are validated")
	}
}
