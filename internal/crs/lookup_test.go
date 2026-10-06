package crs

import "testing"

func TestCopiedRuleIDsResolveDetectionAndDecision(t *testing.T) {
	for _, q := range []string{"930130,949110", `,930130,949110,`, `"rule_ids_csv":"930130,949110"`} {
		list := Default().Search(q)
		if len(list) != 2 || list[0].ID != 930130 || list[0].Kind != KindDetection || list[1].ID != 949110 || list[1].Kind != KindDecision {
			t.Fatalf("%s: %+v", q, list)
		}
		for _, r := range list {
			note, _ := Note(r)
			if note == "" {
				t.Fatalf("missing explanation for %d", r.ID)
			}
		}
	}
}

func TestPartialIDSearchesSubstrings(t *testing.T) {
	list := Default().Search("93013")
	if len(list) == 0 || list[0].ID != 930130 {
		t.Fatalf("partial id: %+v", list)
	}
	if got := Default().Search("123456789"); len(got) != 0 {
		t.Fatalf("an unknown typed number is searched, not invented: %+v", got)
	}
	if got := Default().Search("123456789,930130"); len(got) != 2 || got[0].Kind != "unknown" {
		t.Fatalf("pasted lists report unknown ids explicitly: %+v", got)
	}
}
