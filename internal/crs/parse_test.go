package crs

import (
	"strings"
	"testing"
)

const fixture = `# ------------------------------------------------------------------------
# OWASP CRS ver.4.25.0
# ------------------------------------------------------------------------

#
# -=[ Restricted File Access ]=-
#
# Detects attempts to retrieve application source code.
#
SecRule REQUEST_FILENAME "@pmFromFile restricted-files.data" \
    "id:930130,\
    phase:1,\
    block,\
    capture,\
    msg:'Restricted File Access Attempt',\
    logdata:'Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}',\
    tag:'attack-lfi',\
    tag:'paranoia-level/1',\
    ver:'OWASP_CRS/4.25.0',\
    severity:'CRITICAL',\
    setvar:'tx.lfi_score=+%{tx.critical_anomaly_score}',\
    setvar:'tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}'"

SecRule REQUEST_HEADERS:Content-Type "!@rx ^[\w/.+*-]+(?:\s?;\s?(?:action|boundary|charset|component|start(?:-info)?|type|version)\s?=\s?['\"\w.()+,/:=?<>@#*-]+)*$" \
    "id:920470,\
    phase:1,\
    block,\
    t:none,t:lowercase,\
    msg:'Illegal Content-Type header',\
    tag:'paranoia-level/2',\
    ver:'OWASP_CRS/4.25.0',\
    severity:'WARNING',\
    chain"
    SecRule REQUEST_METHOD "!@within GET HEAD" \
        "setvar:'tx.inbound_anomaly_score_pl2=+%{tx.warning_anomaly_score}'"

SecRule TX:BLOCKING_INBOUND_ANOMALY_SCORE "@ge %{tx.inbound_anomaly_score_threshold}" \
    "id:949110,\
    phase:2,\
    deny,\
    t:none,\
    msg:'Inbound Anomaly Score Exceeded (Total Score: %{TX.BLOCKING_INBOUND_ANOMALY_SCORE})',\
    ver:'OWASP_CRS/4.25.0',\
    chain"
    SecRule TX:EARLY_BLOCKING "@eq 1"

SecRule REQBODY_ERROR "!@eq 0" \
    "id:'200002', phase:2,t:none,log,deny,status:400,msg:'Failed to parse request body.',logdata:'%{reqbody_error_msg}',severity:2"

SecRule TX:DETECTION_PARANOIA_LEVEL "@lt 1" "id:930011,phase:1,pass,nolog,ver:'OWASP_CRS/4.25.0',skipAfter:END-REQUEST-930"
SecMarker "END-REQUEST-930"
SecAction "id:959100,phase:4,deny,msg:'x, y',setvar:'tx.a=1'"
`

func parseFixture(t *testing.T) map[int]Rule {
	t.Helper()
	rules, err := Parse(strings.NewReader(fixture), "REQUEST-930-APPLICATION-ATTACK-LFI.conf")
	if err != nil {
		t.Fatal(err)
	}
	byID := map[int]Rule{}
	for _, r := range rules {
		byID[r.ID] = r
	}
	return byID
}

func TestParseDetectionRule(t *testing.T) {
	r := parseFixture(t)[930130]
	if r.Kind != KindDetection || r.Dir != DirInbound || r.Score != 5 || r.PL != 1 {
		t.Fatalf("unexpected classification: %+v", r)
	}
	if r.Phase != 1 || r.Severity != "CRITICAL" || r.Category != "lfi" || r.Action != "block" {
		t.Fatalf("unexpected metadata: %+v", r)
	}
	if r.Msg != "Restricted File Access Attempt" || r.Operator != "@pmFromFile restricted-files.data" {
		t.Fatalf("unexpected msg/operator: %q %q", r.Msg, r.Operator)
	}
	if r.Comment != "Restricted File Access\nDetects attempts to retrieve application source code." {
		t.Fatalf("comment not attached or not cleaned: %q", r.Comment)
	}
	if r.Line != 10 || r.Ver != "OWASP_CRS/4.25.0" {
		t.Fatalf("line/ver: %d %q", r.Line, r.Ver)
	}
}

func TestParseChainContributesScore(t *testing.T) {
	r := parseFixture(t)[920470]
	if r.Kind != KindDetection || r.Score != 3 || r.PL != 2 || len(r.Chain) != 1 {
		t.Fatalf("chained setvar must classify the parent: %+v", r)
	}
	if r.Chain[0].Operator != "!@within GET HEAD" {
		t.Fatalf("chain condition: %+v", r.Chain)
	}
	if !strings.Contains(r.Operator, `['\"\w`) && !strings.Contains(r.Operator, `['"\w`) {
		t.Fatalf("escaped quote inside operator lost: %q", r.Operator)
	}
	if r.Comment != "" {
		t.Fatalf("a rule after a blank line without its own block must not inherit a comment: %q", r.Comment)
	}
}

func TestParseDecisionBlockingAndControl(t *testing.T) {
	rules := parseFixture(t)
	if r := rules[949110]; r.Kind != KindDecision || r.Dir != DirInbound {
		t.Fatalf("949110: %+v", r)
	}
	if r := rules[200002]; r.Kind != KindBlocking || r.Status != 400 || r.Severity != "CRITICAL" || r.Phase != 2 {
		t.Fatalf("200002: %+v", r)
	}
	if r := rules[930011]; r.Kind != KindControl {
		t.Fatalf("930011: %+v", r)
	}
	if r := rules[959100]; r.Msg != "x, y" || r.Kind != KindBlocking {
		t.Fatalf("comma inside a quoted action value: %+v", r)
	}
	if len(rules) != 6 {
		t.Fatalf("expected 6 rules with ids, got %d", len(rules))
	}
}

func TestSeverityHelpers(t *testing.T) {
	cases := map[string]int{"CRITICAL": 5, "'ERROR'": 4, "4": 3, "notice": 2, "INFO": 0, "2": 5}
	for in, want := range cases {
		if got := SeverityScore(in); got != want {
			t.Errorf("SeverityScore(%q) = %d, want %d", in, got, want)
		}
	}
	if SeverityName("3") != "ERROR" {
		t.Fatal("numeric severity not normalized")
	}
}

func TestCategoryFallsBackToFileGroup(t *testing.T) {
	if got := categoryOf(nil, "@owasp_crs/REQUEST-949-BLOCKING-EVALUATION.conf"); got != "blocking-evaluation" {
		t.Fatalf("got %q", got)
	}
	if got := categoryOf([]string{"OWASP_CRS", "attack-sqli"}, "x.conf"); got != "sqli" {
		t.Fatalf("got %q", got)
	}
}
