package analysis

import (
	"net/netip"
	"strings"
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

func TestEstimateAppliesIPGroupRules(t *testing.T) {
	cn := netip.MustParsePrefix("203.0.113.0/24")
	member := func(group string, ip netip.Addr) bool { return group == "cn" && cn.Contains(ip) }
	sqli := events.Hit{ID: 942100, Kind: crs.KindDetection, Dir: crs.DirInbound, PL: 1, Score: 5}
	notice := events.Hit{ID: 920350, Kind: crs.KindDetection, Dir: crs.DirInbound, PL: 1, Score: 3}
	inside := &events.Event{TxID: "in", ClientIP: "203.0.113.9", Mode: "DetectionOnly", Engine: "DetectionOnly", Tuning: true, Action: events.ActionWouldBlock, Hits: []events.Hit{sqli}}
	outside := &events.Event{TxID: "out", ClientIP: "198.51.100.1", Mode: "DetectionOnly", Engine: "DetectionOnly", Tuning: true, Action: events.ActionDetected, Hits: []events.Hit{notice}}
	// Blocked by an old group rule only: the hit is policy, not evidence.
	grouped := &events.Event{TxID: "old", ClientIP: "192.0.2.1", Mode: "On", Engine: "On", Action: events.ActionBlocked, Interrupted: true,
		Hits: []events.Hit{{ID: crs.UIGroupBlockMin, Kind: crs.KindBlocking, Category: "ui-ipgroup"}}}
	history := []*events.Event{inside, outside, grouped}

	relax := waf.DefaultPolicy()
	relax.IPGroups = []waf.IPGroupRule{{Group: "cn", Action: waf.GroupTune, InboundThreshold: 10}}
	im := Estimate(history, nil, crs.Default(), Change{Policy: &relax, Member: member})
	if im.Unblocked != 2 || im.NewlyBlocked != 0 {
		t.Fatalf("relaxing members unblocks their event and dropping the old group rule unblocks its event: %+v", im)
	}
	for _, c := range im.Caveats {
		if strings.Contains(c, "different baseline") {
			t.Fatalf("recorded group blocks must be part of the baseline model: %v", im.Caveats)
		}
	}

	block := waf.DefaultPolicy()
	block.IPGroups = []waf.IPGroupRule{{Group: "cn", Negate: true, Action: waf.GroupBlock}}
	im = Estimate(history, nil, crs.Default(), Change{Policy: &block, Member: member})
	if im.NewlyBlocked != 1 || im.Unblocked != 0 {
		t.Fatalf("blocking non-members blocks the passed outside event and keeps the old block: %+v", im)
	}
	if !hasCaveat(im, "trial") {
		t.Fatalf("block rules must point to trial mode: %v", im.Caveats)
	}

	trusted := waf.DefaultPolicy()
	trusted.IPGroups = []waf.IPGroupRule{{Group: "cn", Action: waf.GroupEngine, Engine: "Off"}}
	if im = Estimate([]*events.Event{inside}, nil, crs.Default(), Change{Policy: &trusted, Member: member}); im.Unblocked != 1 {
		t.Fatalf("an Off engine rule passes its members: %+v", im)
	}
	if im = Estimate([]*events.Event{inside}, nil, crs.Default(), Change{Policy: &trusted}); !hasCaveat(im, "IP group") {
		t.Fatalf("without group lists the estimate must say so: %v", im.Caveats)
	}
}

func hasCaveat(im Impact, text string) bool {
	for _, c := range im.Caveats {
		if strings.Contains(c, text) {
			return true
		}
	}
	return false
}
