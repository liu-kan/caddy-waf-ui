package feedback

import (
	"testing"

	"github.com/developmi/caddy-waf-ui/internal/config"
)

func TestFeedbackIsDurableAndScopedByNode(t *testing.T) {
	t.Setenv("CADDY_UI_DATA_DIR", t.TempDir())
	_ = config.DataDir()
	r := Record{Tx: "same", Node: "a", Site: "example.com", Decision: "false_positive", Reason: "Known application input"}
	if err := Save(r); err != nil {
		t.Fatal(err)
	}
	got, err := Get("a", "same")
	if err != nil || got == nil || got.Reason != r.Reason || got.Updated.IsZero() {
		t.Fatal(got, err)
	}
	if other, err := Get("b", "same"); err != nil || other != nil {
		t.Fatal("feedback crossed node boundary")
	}
	r.Decision = "automatically_allow"
	if err := Save(r); err == nil {
		t.Fatal("invalid decision accepted")
	}
}
