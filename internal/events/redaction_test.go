package events

import (
	"reflect"
	"testing"
)

func TestParseLevel(t *testing.T) {
	for in, want := range map[string]Level{"strict": LevelStrict, " Standard ": LevelStandard, "FULL": LevelFull} {
		got, err := ParseLevel(in)
		if err != nil || got != want {
			t.Fatalf("ParseLevel(%q) = %v, %v", in, got, err)
		}
	}
	for _, bad := range []string{"", "ful", "none"} {
		if got, err := ParseLevel(bad); err == nil || got != LevelStrict {
			t.Fatalf("ParseLevel(%q) must fail closed to strict, got %v, %v", bad, got, err)
		}
	}
	if Stricter(LevelFull, LevelStandard) != LevelStandard || Stricter(LevelStrict, LevelFull) != LevelStrict {
		t.Fatal("Stricter must return the level that keeps less")
	}
}

func TestCredentialNamesUseWholeWords(t *testing.T) {
	for _, name := range []string{"password", "new_password", "user_pass", "passwd", "client_secret", "access_token",
		"authToken", "X-Auth-Token", "Authorization", "Proxy-Authorization", "Cookie", "set-cookie", "x-api-key",
		"apiKey", "session_id", "connect.sid", "csrf_token", "otp", "private_key", "X-Amz-Signature", "jwt"} {
		if !isCredential(name) {
			t.Errorf("%q must be treated as a credential", name)
		}
	}
	// Substring matching used to hide these ordinary fields, which made
	// false positives on them impossible to investigate.
	for _, name := range []string{"max_tokens", "maxTokens", "author", "oauth_provider", "passage", "message",
		"json.messages.0.content", "q", "assessment", "keyword"} {
		if isCredential(name) {
			t.Errorf("%q must not be treated as a credential", name)
		}
	}
}

func redactionFixture() *Event {
	return &Event{
		TxID: "tx-1", Path: "/api/posts", QueryKeys: []string{"q", "access_token", "page"},
		Query: "q=union+select&access_token=abc123&page=2",
		Headers: map[string]string{"user-agent": "curl/8.7", "cookie": "sid=s3cr3t", "authorization": "Bearer t0k3n",
			"x-custom": "custom-value", "referer": "https://app.example.com/reset?token=r3s3t&step=2"},
		Hits: []Hit{
			{ID: 942100, Var: "ARGS:json.messages.0.content", Data: "select * from", Value: "please select * from users"},
			{ID: 942100, Var: "ARGS:json.password", Data: "or 1=1", Value: "hunter2 or 1=1"},
			{ID: 942100, Var: "ARGS:json.max_tokens", Data: "1 union", Value: "1 union select"},
			{ID: 941100, Var: "REQUEST_COOKIES:theme", Data: "<script>", Value: "<script>dark"},
			{ID: 913100, Var: "REQUEST_HEADERS:User-Agent", Data: "sqlmap", Value: "sqlmap/1.7"},
			{ID: 920100, Var: "REQUEST_URI", Data: "union", Value: "/search?token=abc&q=union"},
			{ID: 942100, Var: "REQUEST_BODY", Data: "or 1=1", Value: `{"password":"hunter2","q":"or 1=1"}`},
			{ID: 1000001, Var: "", Data: "custom logdata with secret"},
			{ID: 949110, Kind: "decision"},
		},
	}
}

func hitByVar(e *Event, v string) Hit {
	for _, h := range e.Hits {
		if h.Var == v {
			return h
		}
	}
	return Hit{}
}

func TestStrictKeepsOnlyNames(t *testing.T) {
	e := Redaction{Level: LevelStrict}.Apply(redactionFixture())
	for _, h := range e.Hits {
		if h.Data != "" && h.Data != redacted || h.Value != "" && h.Value != redacted {
			t.Fatalf("strict must hide every matched value: %+v", h)
		}
	}
	if hitByVar(e, "").Data != redacted || e.Hits[len(e.Hits)-1].Data != "" {
		t.Fatal("strict hides logdata but must not invent values for hits without data")
	}
	if e.Query != "" || e.Headers != nil || len(e.QueryKeys) != 3 || e.Redaction != "strict" {
		t.Fatalf("strict keeps query names only: %+v", e)
	}
}

func TestStandardHidesCredentialsOnly(t *testing.T) {
	src := redactionFixture()
	e := Redaction{Level: LevelStandard}.Apply(src)
	if h := hitByVar(e, "ARGS:json.messages.0.content"); h.Data != "select * from" || h.Value != "please select * from users" {
		t.Fatalf("ordinary content must stay visible: %+v", h)
	}
	if h := hitByVar(e, "ARGS:json.max_tokens"); h.Value != "1 union select" {
		t.Fatalf("max_tokens is not a credential: %+v", h)
	}
	for _, v := range []string{"ARGS:json.password", "REQUEST_COOKIES:theme", ""} {
		if h := hitByVar(e, v); h.Data != redacted {
			t.Fatalf("%q must stay hidden in standard: %+v", v, h)
		}
	}
	if h := hitByVar(e, "REQUEST_HEADERS:User-Agent"); h.Value != "sqlmap/1.7" {
		t.Fatalf("user agent matches stay visible: %+v", h)
	}
	if h := hitByVar(e, "REQUEST_URI"); h.Value != "/search?token=[redacted]&q=union" {
		t.Fatalf("credential query values inside composite variables are hidden: %+v", h)
	}
	if h := hitByVar(e, "REQUEST_BODY"); h.Value != `{"password":"[redacted]","q":"or 1=1"}` {
		t.Fatalf("credential JSON values inside the body are hidden: %+v", h)
	}
	if e.Query != "q=union+select&access_token=[redacted]&page=2" {
		t.Fatalf("query values are kept except credentials: %q", e.Query)
	}
	want := map[string]string{"user-agent": "curl/8.7", "cookie": redacted, "authorization": redacted,
		"referer": "https://app.example.com/reset?token=[redacted]&step=2"}
	if !reflect.DeepEqual(e.Headers, want) {
		t.Fatalf("standard keeps diagnostic headers and marks credentials: %v", e.Headers)
	}
	if e.Redaction != "standard" {
		t.Fatalf("level label: %q", e.Redaction)
	}
	if src.Hits[1].Data != "or 1=1" || src.Headers["cookie"] != "sid=s3cr3t" || src.Redaction != "" {
		t.Fatal("Apply must not modify its input")
	}
}

func TestFullKeepsEverythingButTheHideList(t *testing.T) {
	e := Redaction{Level: LevelFull}.Apply(redactionFixture())
	if h := hitByVar(e, "ARGS:json.password"); h.Value != "hunter2 or 1=1" {
		t.Fatalf("full keeps credentials: %+v", h)
	}
	if h := hitByVar(e, ""); h.Data != "custom logdata with secret" {
		t.Fatalf("full keeps unparsed logdata: %+v", h)
	}
	if e.Query != "q=union+select&access_token=abc123&page=2" || e.Headers["cookie"] != "sid=s3cr3t" || e.Headers["x-custom"] != "custom-value" {
		t.Fatalf("full keeps the query and every header: %+v", e)
	}

	hide := Redaction{Level: LevelFull, Hide: []string{"password", "Authorization", "access_token"}}.Apply(redactionFixture())
	if h := hitByVar(hide, "ARGS:json.password"); h.Value != redacted {
		t.Fatalf("hide list applies at every level: %+v", h)
	}
	if h := hitByVar(hide, "REQUEST_BODY"); h.Value != `{"password":"[redacted]","q":"or 1=1"}` {
		t.Fatalf("hide list applies inside composite values: %+v", h)
	}
	if hide.Headers["authorization"] != redacted || hide.Headers["cookie"] != "sid=s3cr3t" {
		t.Fatalf("hidden header: %v", hide.Headers)
	}
	if hide.Query != "q=union+select&access_token=[redacted]&page=2" {
		t.Fatalf("hidden query value: %q", hide.Query)
	}
}

func TestKeepListOverridesBuiltInNames(t *testing.T) {
	e := Redaction{Level: LevelStandard, Keep: []string{"password", "theme", "x-custom"}}.Apply(redactionFixture())
	if h := hitByVar(e, "ARGS:json.password"); h.Value != "hunter2 or 1=1" {
		t.Fatalf("keep exempts a parameter by its last segment: %+v", h)
	}
	if h := hitByVar(e, "REQUEST_COOKIES:theme"); h.Value != "<script>dark" {
		t.Fatalf("keep exempts a named cookie: %+v", h)
	}
	if e.Headers["x-custom"] != "custom-value" {
		t.Fatalf("keep adds a header to the standard allowlist: %v", e.Headers)
	}
	both := Redaction{Level: LevelStandard, Keep: []string{"password"}, Hide: []string{"password"}}.Apply(redactionFixture())
	if h := hitByVar(both, "ARGS:json.password"); h.Value != redacted {
		t.Fatalf("hide wins over keep: %+v", h)
	}
}

func TestStricterRedactionIsMonotonic(t *testing.T) {
	policies := []Redaction{{Level: LevelStrict}, {Level: LevelStandard, Keep: []string{"theme"}}, {Level: LevelFull, Hide: []string{"page"}}}
	for i, local := range policies {
		for _, cloud := range policies[:i+1] {
			cloud.Hide, cloud.Keep = local.Hide, local.Keep
			direct := cloud.Apply(redactionFixture())
			derived := cloud.Apply(local.Apply(redactionFixture()))
			if !reflect.DeepEqual(direct, derived) {
				t.Fatalf("%s from %s differs:\n%+v\n%+v", cloud.Level, local.Level, direct, derived)
			}
		}
	}
	if got := (Redaction{Level: LevelFull}).Apply(Redaction{Level: LevelStrict}.Apply(redactionFixture())); got.Redaction != "strict" {
		t.Fatalf("a less strict policy cannot relabel already redacted data: %q", got.Redaction)
	}
}
