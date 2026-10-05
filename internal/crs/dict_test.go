package crs

import (
	"bytes"
	"strconv"
	"strings"
	"testing"
	"testing/fstest"
)

func TestEmbeddedDictionaryMatchesBackendRuleset(t *testing.T) {
	d := Default()
	if d.CRSVersion != "4.25.0" || d.Len() < 600 {
		t.Fatalf("unexpected embedded dictionary: CRS %s with %d rules", d.CRSVersion, d.Len())
	}
	cases := map[int]string{
		930130: KindDetection, 942100: KindDetection, 941100: KindDetection, 913100: KindDetection,
		949110: KindDecision, 949111: KindDecision, 959100: KindDecision,
		200002: KindBlocking, 200003: KindBlocking, 980170: KindCorrelation,
	}
	for id, kind := range cases {
		r, ok := d.Lookup(id)
		if !ok || r.Kind != kind {
			t.Errorf("%d: got %+v, want kind %s", id, r, kind)
		}
	}
	r, _ := d.Lookup(930130)
	if r.PL != 1 || r.Score != 5 || r.Dir != DirInbound || r.Comment == "" ||
		!strings.HasPrefix(r.Link, "https://github.com/coreruleset/coreruleset/blob/v4.25.0/rules/REQUEST-930") {
		t.Fatalf("930130 metadata incomplete: %+v", r)
	}
	if r, _ := d.Lookup(942430); r.Score != 3 || r.PL != 2 {
		t.Fatalf("942430 must be a PL2 warning-score rule: %+v", r)
	}
	if r, _ := d.Lookup(951110); r.Dir != DirOutbound {
		t.Fatalf("response rules must score outbound: %+v", r)
	}
}

func TestUIRulesAreDescribed(t *testing.T) {
	d := Default()
	for _, id := range []int{UIExclusionMin, UIExclusionMax, UIPolicyMin, UITuningRuleID, 9005000} {
		r, ok := d.Lookup(id)
		if !ok || r.Kind != KindUI || r.Msg == "" {
			t.Errorf("%d: %+v", id, r)
		}
	}
	if _, ok := d.Lookup(123); ok {
		t.Fatal("unknown ids must not resolve")
	}
	if r, _ := d.Lookup(949110); r.IsExcludable() {
		t.Fatal("decision rules must not be offered as exclusions")
	}
	if r, _ := d.Lookup(942100); !r.IsExcludable() {
		t.Fatal("detection rules are excludable")
	}
}

func TestNotesReferenceExistingRulesAndCategories(t *testing.T) {
	d := Default()
	n := loadNotes()
	if len(n.Rules) < 100 {
		t.Fatalf("expected curated notes for frequent rules, got %d", len(n.Rules))
	}
	for key := range n.Rules {
		id, err := strconv.Atoi(key)
		if err != nil {
			t.Fatalf("note key %q is not an id", key)
		}
		if _, ok := d.Lookup(id); !ok {
			t.Errorf("note for unknown rule %d", id)
		}
	}
	categories := map[string]bool{}
	for _, r := range d.Rules {
		categories[r.Category] = true
	}
	for _, r := range d.Rules {
		if r.Kind != KindDetection {
			continue
		}
		if _, ok := n.Categories[r.Category]; !ok {
			t.Errorf("detection category %q (rule %d) has no Chinese fallback", r.Category, r.ID)
		}
	}
	rule, category := Note(Rule{ID: 930130, Category: "lfi"})
	if rule == "" || category == "" {
		t.Fatal("note lookup failed")
	}
}

func TestBuildAndRoundTrip(t *testing.T) {
	fsys := fstest.MapFS{
		"@owasp_crs/REQUEST-930-APPLICATION-ATTACK-LFI.conf": {Data: []byte(fixture)},
		"README.md": {Data: []byte("SecRule ignored")},
	}
	d, err := Build(fsys, "test", "https://example.test/")
	if err != nil {
		t.Fatal(err)
	}
	if d.CRSVersion != "4.25.0" || d.Len() != 6 {
		t.Fatalf("got CRS %s with %d rules", d.CRSVersion, d.Len())
	}
	r, _ := d.Lookup(930130)
	if r.Link != "https://example.test/@owasp_crs/REQUEST-930-APPLICATION-ATTACK-LFI.conf#L10" {
		t.Fatalf("link: %s", r.Link)
	}
	var buf bytes.Buffer
	if err := d.Encode(&buf); err != nil {
		t.Fatal(err)
	}
	back, err := Decode(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if back.Len() != 6 || back.CRSVersion != "4.25.0" {
		t.Fatalf("round trip lost data: %+v", back)
	}
	docs := &Dictionary{Rules: []Rule{{ID: 930130, Comment: "upstream comment", Link: "https://upstream/#L1"}}}
	docs.index()
	back.ApplyDocs(docs, "upstream")
	if r, _ := back.Lookup(930130); r.Comment != "upstream comment" || r.Link != "https://upstream/#L1" {
		t.Fatalf("docs not applied: %+v", r)
	}
	if hits := back.Search("restricted file"); len(hits) != 1 || hits[0].ID != 930130 {
		t.Fatalf("search: %+v", hits)
	}
	if hits := back.Search("", KindDecision); len(hits) != 1 {
		t.Fatalf("kind filter: %+v", hits)
	}
}

func TestBuildRejectsDuplicateIDs(t *testing.T) {
	fsys := fstest.MapFS{
		"a.conf": {Data: []byte(`SecAction "id:1,phase:1,pass"`)},
		"b.conf": {Data: []byte(`SecAction "id:1,phase:1,pass"`)},
	}
	if _, err := Build(fsys, "dup", ""); err == nil {
		t.Fatal("duplicate ids must fail the build")
	}
}

func TestMergePrefersOperatorRules(t *testing.T) {
	base := Default()
	other := &Dictionary{Source: "file:///rules", CRSVersion: "4.26.0", Rules: []Rule{{ID: 930130, Kind: KindDetection, Msg: "changed"}}}
	merged := base.Merge(other)
	r, _ := merged.Lookup(930130)
	if r.Msg != "changed" || r.Comment == "" || merged.CRSVersion != "4.26.0" {
		t.Fatalf("merge: %+v %s", r, merged.CRSVersion)
	}
	if _, ok := merged.Lookup(942100); !ok {
		t.Fatal("merge dropped base rules")
	}
}
