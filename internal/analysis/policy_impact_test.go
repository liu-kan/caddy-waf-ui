package analysis

import (
	"testing"

	"github.com/developmi/caddy-waf-ui/internal/crs"
	"github.com/developmi/caddy-waf-ui/internal/events"
	"github.com/developmi/caddy-waf-ui/internal/waf"
)

func TestPolicyDisabledGroupImpact(t *testing.T) {
	e := &events.Event{TxID: "test", Mode: "On", BlockingPL: 1, DetectionPL: 1, Tuning: true, Action: events.ActionBlocked, Hits: []events.Hit{{ID: 930130, Kind: crs.KindDetection, Dir: crs.DirInbound, PL: 1, Score: 5}}}
	p := waf.DefaultPolicy()
	p.DisabledGroups = []string{"930"}
	im := Estimate([]*events.Event{e}, nil, crs.Default(), Change{Policy: &p})
	t.Logf("disable group 930 containing sole score contributor: unblocked=%d caveats=%v", im.Unblocked, im.Caveats)
	if im.Unblocked != 1 {
		t.Error("policy disabled group ignored by estimate")
	}
}
