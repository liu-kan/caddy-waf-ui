package textdiff

import (
	"strings"
	"testing"
)

func TestUnifiedShowsChangesWithContext(t *testing.T) {
	a := "header 1\na\nb\nc\nd\ne\nf\n"
	b := "header 2\na\nb\nC\nd\ne\nf\ng\n"
	ignore := func(line string) bool { return strings.HasPrefix(line, "header") }
	got := Unified(a, b, 1, ignore)
	want := "@@\n  b\n- c\n+ C\n  d\n@@\n  f\n+ g\n"
	if got != want {
		t.Fatalf("got:\n%s\nwant:\n%s", got, want)
	}
	if Unified(a, a, 2, nil) != "" {
		t.Fatal("identical input must produce no diff")
	}
	if Unified("x\n", "x\n", 0, nil) != "" || Unified("", "y", 0, nil) != "+ y\n" {
		t.Fatal("edge cases")
	}
	big := strings.Repeat("x\n", maxLines+1)
	if !strings.Contains(Unified(big, "y", 0, nil), "diff skipped") {
		t.Fatal("oversized inputs are summarized")
	}
}
