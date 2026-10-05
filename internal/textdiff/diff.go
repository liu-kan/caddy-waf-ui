// Package textdiff renders a compact line diff of two small text files
// (managed overlays) for change previews and the change journal.
package textdiff

import (
	"fmt"
	"strings"
)

const maxLines = 4000

// Line is one diff line: Op is ' ' (context), '-' (removed) or '+' (added).
type Line struct {
	Op   byte
	Text string
}

// Lines computes the line-level edit script between a and b using the
// longest common subsequence. Lines for which ignore returns true are
// compared as equal (e.g. timestamps and revisions that change every time).
func Lines(a, b string, ignore func(string) bool) []Line {
	x, y := split(a), split(b)
	if len(x) > maxLines || len(y) > maxLines {
		return []Line{{Op: '+', Text: fmt.Sprintf("(diff skipped: %d → %d lines)", len(x), len(y))}}
	}
	eq := func(i, j int) bool {
		if x[i] == y[j] {
			return true
		}
		return ignore != nil && ignore(x[i]) && ignore(y[j])
	}
	// lcs[i][j] = LCS length of x[i:], y[j:].
	lcs := make([][]int, len(x)+1)
	for i := range lcs {
		lcs[i] = make([]int, len(y)+1)
	}
	for i := len(x) - 1; i >= 0; i-- {
		for j := len(y) - 1; j >= 0; j-- {
			if eq(i, j) {
				lcs[i][j] = lcs[i+1][j+1] + 1
			} else if lcs[i+1][j] >= lcs[i][j+1] {
				lcs[i][j] = lcs[i+1][j]
			} else {
				lcs[i][j] = lcs[i][j+1]
			}
		}
	}
	var out []Line
	i, j := 0, 0
	for i < len(x) && j < len(y) {
		switch {
		case eq(i, j):
			out = append(out, Line{Op: ' ', Text: y[j]})
			i++
			j++
		case lcs[i+1][j] >= lcs[i][j+1]:
			out = append(out, Line{Op: '-', Text: x[i]})
			i++
		default:
			out = append(out, Line{Op: '+', Text: y[j]})
			j++
		}
	}
	for ; i < len(x); i++ {
		out = append(out, Line{Op: '-', Text: x[i]})
	}
	for ; j < len(y); j++ {
		out = append(out, Line{Op: '+', Text: y[j]})
	}
	return out
}

// Unified renders the changed lines with context lines around them, or ""
// when nothing changed.
func Unified(a, b string, context int, ignore func(string) bool) string {
	lines := Lines(a, b, ignore)
	keep := make([]bool, len(lines))
	changed := false
	for i, l := range lines {
		if l.Op == ' ' {
			continue
		}
		changed = true
		for k := i - context; k <= i+context; k++ {
			if k >= 0 && k < len(lines) {
				keep[k] = true
			}
		}
	}
	if !changed {
		return ""
	}
	var out strings.Builder
	skipped := false
	for i, l := range lines {
		if !keep[i] {
			skipped = true
			continue
		}
		if skipped {
			out.WriteString("@@\n")
			skipped = false
		}
		out.WriteByte(l.Op)
		out.WriteByte(' ')
		out.WriteString(l.Text)
		out.WriteByte('\n')
	}
	return out.String()
}

func split(s string) []string {
	s = strings.TrimRight(s, "\n")
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}
