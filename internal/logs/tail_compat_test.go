package logs

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestBoundedTailResynchronizesConcatenatedCorazaJSON(t *testing.T) {
	var stream string
	var last string
	for i := 10; i < 20; i++ {
		last = fmt.Sprintf(`{"transaction":{"id":"tx-%d","client_ip":"visitor-%d","is_interrupted":false},"messages":[]}`, i, i)
		stream += last
	}
	previous := maxTailBytes
	maxTailBytes = int64(len(last)*2 + len(last)/2)
	defer func() { maxTailBytes = previous }()
	path := filepath.Join(t.TempDir(), "audit.json")
	if err := os.WriteFile(path, []byte(stream), 0600); err != nil {
		t.Fatal(err)
	}
	page, err := Read(path, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Entries) != 2 || page.Entries[0].Client != "visitor-19" {
		t.Fatalf("bounded newline-less logs must retain complete recent entries, got %+v", page)
	}
}
