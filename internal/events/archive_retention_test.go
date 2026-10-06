package events

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestArchiveRetentionIsConfigurable(t *testing.T) {
	store, _ := newStore(t)
	logPath := filepath.Join(t.TempDir(), "audit.log")
	archive := logPath + ".rotated-20261001T000000.000000000Z"
	appendFile(t, archive, fixtureLines(t)[0]+"\n")
	old := time.Now().Add(-60 * time.Hour)
	if err := os.Chtimes(archive, old, old); err != nil {
		t.Fatal(err)
	}
	in := newIngester(t, logPath, store)
	in.ArchiveRetention = 72 * time.Hour
	if err := in.PollArchives(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(archive); err != nil {
		t.Fatal("an archive younger than the configured retention must be kept")
	}
	in.ArchiveRetention = 0 // default 48 hours
	if err := in.PollArchives(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(archive); !os.IsNotExist(err) {
		t.Fatal("an ingested archive older than the default retention must be removed")
	}
}

func TestLocalCandidatesFollowRotationTimes(t *testing.T) {
	dir := t.TempDir()
	audit := filepath.Join(dir, "coraza-audit.log")
	names := []string{"20261001T000000.000000000Z", "20261002T000000.000000000Z", "20261003T000000.000000000Z"}
	for _, n := range names {
		if err := os.WriteFile(audit+".rotated-"+n, nil, 0o640); err != nil {
			t.Fatal(err)
		}
	}
	at := func(s string) time.Time {
		ts, err := time.Parse(time.RFC3339, s)
		if err != nil {
			t.Fatal(err)
		}
		return ts
	}
	arch := func(i int) string { return audit + ".rotated-" + names[i] }
	cases := []struct {
		ts   time.Time
		want []string
	}{
		// Written before the first rotation: only the first archive.
		{at("2026-09-30T12:00:00Z"), []string{arch(0)}},
		// Just after a rotation, old writers may still append to the
		// previous archive until every site reopened its log.
		{at("2026-10-02T00:01:00Z"), []string{arch(2), arch(1)}},
		{at("2026-10-01T12:00:00Z"), []string{arch(1)}},
		// After the last rotation: the live file (and the last archive
		// right after rotating).
		{at("2026-10-03T00:00:30Z"), []string{audit, arch(2)}},
		{at("2026-10-04T00:00:00Z"), []string{audit}},
	}
	for _, c := range cases {
		got, err := localCandidates(audit, c.ts)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: got %v, want %v", c.ts, got, c.want)
		}
	}
}
