package ui

import (
	"net/http/httptest"
	"strings"
	"testing"
	"unicode/utf8"
)

// TestActorTruncatesOnRuneBoundaries: long reasons and proxy identities are
// truncated to their byte limits without splitting a multi-byte character
// (the journal would otherwise store U+FFFD).
func TestActorTruncatesOnRuneBoundaries(t *testing.T) {
	t.Setenv("CADDY_UI_ACTOR_HEADER", "X-User")
	req := httptest.NewRequest("POST", "/", nil)
	req.Header.Set("X-User", strings.Repeat("管", 50))
	a := actor(req, strings.Repeat("误报", 200))
	if !utf8.ValidString(a.Reason) || len(a.Reason) > 500 || len(a.Reason) < 497 {
		t.Fatalf("reason: valid=%v len=%d", utf8.ValidString(a.Reason), len(a.Reason))
	}
	if !utf8.ValidString(a.User) || len(a.User) > 128 || len(a.User) < 126 {
		t.Fatalf("user: valid=%v len=%d", utf8.ValidString(a.User), len(a.User))
	}
}
